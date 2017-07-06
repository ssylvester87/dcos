"""
TLS-related tests.
"""
import logging
import socket
import ssl
import traceback
from collections import namedtuple

import pytest
from cryptography import x509

from ee_helpers import bootstrap_config, CRYPTOGRAPHY_BACKEND, DCOS_NODES


log = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.security,
    pytest.mark.skipif(
        bootstrap_config['security'] != 'strict',
        reason='Tests must run against a cluster in strict mode'
    )]

SanEntry = namedtuple("SanEntry", ['type', 'val'])
Netloc = namedtuple("Netloc", ["host", "port", "description", "expected_sans"])

COMMON_SAN_ENTRIES = [
    SanEntry("ip", "127.0.0.1"),
    SanEntry("dns", "127.0.0.1"),
    SanEntry("dns", "localhost"),
    ]

MASTERS_SAN_ENTRIES = [
    SanEntry("dns", "master.mesos"),
    SanEntry("dns", "leader.mesos"),
    ]

MARATHON_SAN_ENTRIES = [SanEntry("dns", "marathon.mesos")]


def _tls_netlocs():
    """Generate `Netloc` objects for every node in the cluster."""

    netlocs = []

    for host in DCOS_NODES.masters:

        ar_san_entries = [
            SanEntry("dns", host),
            SanEntry("ip", host)
            ]

        netlocs.extend([
            Netloc(
                host,
                5050,
                "Mesos (master) on %s:%s" % (host, 5050),
                COMMON_SAN_ENTRIES + MASTERS_SAN_ENTRIES),
            Netloc(
                host,
                8443,
                "Root Marathon (master) on %s:%s" % (host, 8443),
                COMMON_SAN_ENTRIES + MASTERS_SAN_ENTRIES + MARATHON_SAN_ENTRIES),
            Netloc(
                host,
                9443,
                "Metronome (master) on %s:%s" % (host, 9443),
                COMMON_SAN_ENTRIES + MASTERS_SAN_ENTRIES),
            Netloc(
                host,
                443,
                "Admin Router (master) on %s:%s" % (host, 443),
                COMMON_SAN_ENTRIES + MASTERS_SAN_ENTRIES + ar_san_entries)
            ])

    for host in DCOS_NODES.all_agents:
        netlocs.extend([
            Netloc(
                host,
                5051,
                "Mesos (agent) on %s:%s" % (host, 5051),
                COMMON_SAN_ENTRIES),
            Netloc(
                host,
                61002,
                "Admin Router (agent) on %s:%s" % (host, 61002),
                COMMON_SAN_ENTRIES)
            ])

    log.info('Generated netlocs: %r', netlocs)
    return netlocs


# Generate list of `Netloc` objects and corresponding descriptions/ids for
# pytest test parametrization.
tls_netlocs = _tls_netlocs()
tls_netlocs_ids = [n.description for n in tls_netlocs]


@pytest.fixture
def signing_ca_cert(superuser_api_session):
    r = superuser_api_session.ca.post('/info', json={'profile': ''})
    assert r.status_code == 200

    signing_ca_cert = x509.load_pem_x509_certificate(
        r.json()['result']['certificate'].encode('ascii'), CRYPTOGRAPHY_BACKEND)

    return signing_ca_cert


@pytest.mark.parametrize('netloc', tls_netlocs, ids=tls_netlocs_ids)
def test_retrieve_server_cert(netloc):
    """
    Verify that the remote end expects an SSL/TLS connection at all, and
    that it presents a certificate.

    Note that `ssl.PROTOCOL_SSLv23` does not mean that the cipher suite
    negotiation must yield SSLv2 or SSLv3, but the highest protocol version
    supported by both peers in the TLS handshake. From CPython 3.5.3 on
    we should use `ssl.PROTOCOL_TLS` instead.
    """
    cert_pem = ssl.get_server_certificate(
        (netloc.host, netloc.port),
        ssl_version=ssl.PROTOCOL_SSLv23)
    assert cert_pem, 'Failed to retrieve cert from: {}'.format(str(netloc))


@pytest.mark.parametrize('netloc', tls_netlocs, ids=tls_netlocs_ids)
def test_retrieve_server_cert_via_tls_1_2(netloc):
    """
    Verify that the remote end supports a TLS 1.2 connection.
    """
    cert_pem = ssl.get_server_certificate(
        addr=(netloc.host, netloc.port),
        ssl_version=ssl.PROTOCOL_TLSv1_2)
    assert cert_pem, 'Failed TLSv1_2 cert check for: {}'.format(str(netloc))


@pytest.mark.parametrize('netloc', tls_netlocs, ids=tls_netlocs_ids)
def test_verify_server_cert_against_root_cert(netloc, superuser_api_session):
    cert_pem = ssl.get_server_certificate(
        addr=(netloc.host, netloc.port),
        ca_certs=superuser_api_session.session.verify,
        ssl_version=ssl.PROTOCOL_SSLv23)
    assert cert_pem, 'Failed to verify cert against root for : {}'.format(str(netloc))


@pytest.mark.parametrize('netloc', tls_netlocs, ids=tls_netlocs_ids)
def test_component_cert_issuer(netloc, signing_ca_cert):
    """
    Retrieve the "signing CA certificate", i.e. the CA certificate that the
    DC/OS CA uses to sign end-entity certificates (that may be an intermediate
    CA certificate or a root CA certificate -- this is not always equivalent
    with the DC/OS root CA certificate).

    Then confirm that the end-entity certificates presented by the individual
    network locations are certificates signed directly by the signing CA
    certificate.
    """
    cert_pem = ssl.get_server_certificate(
        (netloc.host, netloc.port),
        ssl_version=ssl.PROTOCOL_SSLv23)
    component_cert = x509.load_pem_x509_certificate(
        cert_pem.encode('ascii'), CRYPTOGRAPHY_BACKEND)
    assert component_cert.issuer == signing_ca_cert.subject


@pytest.mark.parametrize('netloc', tls_netlocs, ids=tls_netlocs_ids)
def test_cert_san_entries(netloc):
    """
    For every network location in `tls_netlocs`, fetch the end entity ("server")
    certificate that the remote end presents during the TLS handshake and
    inspect its Subject Alternative Name entries (SANs).

    Each `netloc` object encodes a list of expected SANs. Compare the SAN
    entries found in the server certificate to those that are expected. Each
    expected SAN must be found in the server certificate, otherwise the test
    fails. If the server certificate encodes more SANs than those that are
    expected then this does not make the test fail (the set of expected SANs is
    expected to be just a subset of the SANs encoded in the server certificate).
    """

    # Todo(JP): Use `ssl.PROTOCOL_TLS` instead of `ssl.PROTOCOL_SSLv23` from
    # CPython 3.5.3 on.
    cert_pem = ssl.get_server_certificate(
        (netloc.host, netloc.port),
        ssl_version=ssl.PROTOCOL_SSLv23)
    cert = x509.load_pem_x509_certificate(
        cert_pem.encode('ascii'),
        CRYPTOGRAPHY_BACKEND)

    ext = cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

    # Get list of SAN entries of type `dNSName` (list of strings) as well as the
    # list of SAN entries of type `iPAddress` (list of strings).
    # Reference: https://tools.ietf.org/html/rfc5280#section-4.2.1.6
    dns_names = ext.value.get_values_for_type(x509.DNSName)
    ip_names = [str(x) for x in ext.value.get_values_for_type(x509.IPAddress)]

    assert len(dns_names) > 1
    assert len(ip_names) > 1
    log.info("dns names: %s", dns_names)
    log.info("ip addresses: %s", ip_names)

    for expected_dns in (x.val for x in netloc.expected_sans if x.type == 'dns'):
        assert expected_dns in dns_names

    for expected_ip in (x.val for x in netloc.expected_sans if x.type == 'ip'):
        assert expected_ip in ip_names


@pytest.mark.parametrize('netloc', tls_netlocs, ids=tls_netlocs_ids)
def test_cert_hostname_verification(netloc, superuser_api_session):
    """
    Note: the cryptography package does not expose OpenSSL's
    API for cert/hostname verification yet:
    https://github.com/pyca/cryptography/pull/1888
    (but the stdlib tools are just fine since 3.4.3)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)

    ss = ssl.wrap_socket(
        s,
        cert_reqs=ssl.CERT_REQUIRED,
        ca_certs=superuser_api_session.session.verify,
        do_handshake_on_connect=True)
    with s:
        ss.connect((netloc.host, netloc.port))
        certdict = ss.getpeercert()

    # https://docs.python.org/3/library/ssl.html#ssl.match_hostname
    ssl.match_hostname(certdict, netloc.host)


# Note(JP): SSLv2 and SSLv3 cannot be tested using this test runner (a CPython
# process), because both are disabled here by default (because our OpenSSL build
# that backs our CPython build has been compiled w/o SSLv2/v3 support). This
# test assumes that we never enable SSLv2/v3 in our OpenSSL build. Of course
# this assumption should be verified by some entirely different level of
# (penetration) testing.
@pytest.mark.parametrize('netloc', tls_netlocs, ids=tls_netlocs_ids)
@pytest.mark.parametrize('unsupported_tls_version', [
    ssl.PROTOCOL_TLSv1,
    ssl.PROTOCOL_TLSv1_1]
    )
def test_internal_components_only_support_tls12(netloc, unsupported_tls_version):
    """
    Verify that 'internal components' do not support protocol versions besides
    TLSv1.2.

    The outside-facing Master Admin Router is the only exception.
    """

    if 'Admin Router (master)' in netloc.description:
        log.info('Skip test for the master Admin Router %r', netloc)
        return

    log.info('Verify that %r does not support %s', netloc, unsupported_tls_version)

    try:
        ssl.get_server_certificate(
            addr=(netloc.host, netloc.port),
            ssl_version=unsupported_tls_version)

        raise Exception(
            'TLS handshake between the test runner and `{netloc}` '
            'with `{tls_version!s}` succeeded, but was not expected to '
            'succeed'.format_map({
                'tls_version': unsupported_tls_version,
                'netloc': netloc.description}))

    except ssl.SSLError as exc:

        expected_error_codes = ('TLSV1_ALERT_PROTOCOL_VERSION', )
        for ecode in expected_error_codes:
            if ecode in str(exc):
                log.info('Exception is presumed to be expected: %s', exc)
                break
        else:
            # 'nobreak' case: unexpected `SSLError`, re-raise.
            raise

    except ConnectionResetError as exc:
        # Make sure that the ConnectionResetError was raised within the
        # `do_handshake` method:
        # >    self._sslobj.do_handshake()
        # E    ConnectionResetError: [Errno 104] Connection reset by peer
        #
        # Background: https://hg.python.org/cpython/rev/69f737f410f0 "What
        #    probably happens is that OpenSSL versions, instead of answering
        #    'sorry, I can't talk to you', brutally reset the connections."
        #
        # Extract only the last stack trace entry / line
        tb = traceback.format_exc(limit=-1)
        if '_sslobj.do_handshake()' in tb:
            log.info('Expected exception during `do_handshake()`: %s', exc)
            return

        # Re-raise what's unexpected.
        raise
