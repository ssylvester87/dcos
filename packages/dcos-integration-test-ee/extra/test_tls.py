"""
SSL/TLS-related tests.
"""
import logging
import socket
import ssl
from collections import namedtuple

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend as crypto_backend

log = logging.getLogger(__name__)

pytestmark = [pytest.mark.security]

SanEntry = namedtuple("SanEntry", ['type', 'val'])
Netloc = namedtuple("Netloc", ["host", "port", "description", "expected_sans"])

common_san_entries = [SanEntry("ip", "127.0.0.1"),
                      SanEntry("dns", "127.0.0.1"),
                      SanEntry("dns", "localhost"),
                      ]
masters_san_entries = [SanEntry("dns", "master.mesos"),
                       SanEntry("dns", "leader.mesos"),
                       ]
marathon_san_entries = [SanEntry("dns", "marathon.mesos")]


@pytest.fixture
def ssl_cluster(cluster, cluster_config):
    if cluster_config['security'] != 'strict':
        pytest.skip("SSL/TLS tests skipped: strict security mode not expected")
    return cluster


@pytest.fixture
def tls_netlocs(ssl_cluster):
    """Generate Netlocs for every node in the cluster
    """
    netlocs = []
    for host in ssl_cluster.masters:
        ar_san_entries = [
            SanEntry("dns", host),
            SanEntry("ip", host)]
        netlocs.extend([
            Netloc(
                host,
                5050,
                "Mesos (master)",
                common_san_entries + masters_san_entries),
            Netloc(
                host,
                8443,
                "Root Marathon (master)",
                common_san_entries + masters_san_entries + marathon_san_entries),
            Netloc(
                host,
                9443,
                "Metronome (master)",
                common_san_entries + masters_san_entries),
            Netloc(
                host,
                7443,
                "Cosmos (master)",
                common_san_entries + masters_san_entries),
            Netloc(
                host,
                443,
                "Admin Router (master)",
                common_san_entries + masters_san_entries + ar_san_entries)])

    for host in ssl_cluster.all_slaves:
        netlocs.extend([
            Netloc(
                host,
                5051,
                "Mesos (agent)",
                common_san_entries),
            Netloc(
                host,
                61002,
                "Admin Router (agent)",
                common_san_entries)])
    return netlocs


def test_retrieve_server_cert(tls_netlocs):
    """
    Verify that the remote end expects an SSL/TLS connection at all, and
    that it presents a certificate.
    """
    for netloc in tls_netlocs:
        cert_pem = ssl.get_server_certificate(
            (netloc.host, netloc.port),
            ssl_version=ssl.PROTOCOL_SSLv23)
        assert cert_pem, 'Failed to retrieve cert from: {}'.format(str(netloc))


def test_retrieve_server_cert_enforce_tls_1_2(tls_netlocs):
    for netloc in tls_netlocs:
        cert_pem = ssl.get_server_certificate(
            addr=(netloc.host, netloc.port),
            ssl_version=ssl.PROTOCOL_TLSv1_2)
        assert cert_pem, 'Failed TLSv1_2 cert check for: {}'.format(str(netloc))


def test_verify_server_cert_against_root_cert(tls_netlocs, use_custom_ca):
    for netloc in tls_netlocs:
        cert_pem = ssl.get_server_certificate(
            addr=(netloc.host, netloc.port),
            ca_certs=use_custom_ca,
            ssl_version=ssl.PROTOCOL_SSLv23)
        assert cert_pem, 'Failed to verify cert against root for : {}'.format(str(netloc))


def test_cert_issuer_and_subject(tls_netlocs):
    for netloc in tls_netlocs:
        cert_pem = ssl.get_server_certificate(
            (netloc.host, netloc.port),
            ssl_version=ssl.PROTOCOL_SSLv23)
        cert = x509.load_pem_x509_certificate(
            cert_pem.encode('ascii'), crypto_backend())

        issuer_cns = cert.issuer.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME)
        assert len(issuer_cns) == 1
        assert issuer_cns[0].value == 'DC/OS Root CA'

        subject_ons = cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.ORGANIZATION_NAME)
        assert len(subject_ons) == 1
        assert subject_ons[0].value == 'Mesosphere, Inc.'


def test_cert_dns_names(tls_netlocs):
    for netloc in tls_netlocs:
        cert_pem = ssl.get_server_certificate(
            (netloc.host, netloc.port),
            ssl_version=ssl.PROTOCOL_SSLv23)
        cert = x509.load_pem_x509_certificate(
            cert_pem.encode('ascii'),
            crypto_backend())

        ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_names = ext.value.get_values_for_type(x509.DNSName)
        ip_names = [str(x) for x in ext.value.get_values_for_type(x509.IPAddress)]
        assert len(dns_names) > 1
        assert len(ip_names) > 1
        log.info("dns names: %s", dns_names)
        log.info("ip names: %s", ip_names)
        # TODO(prozlach): not sure how we can test DNSNames that contain i.e. lb
        # addr
        for expected_dns in (x.val for x in netloc.expected_sans if x.type == 'dns'):
            assert expected_dns in dns_names
        for expected_ip in (x.val for x in netloc.expected_sans if x.type == 'ip'):
            assert expected_ip in ip_names


def test_cert_hostname_verification(tls_netlocs, use_custom_ca):
    """
    Note: the cryptography package does not expose OpenSSL's
    API for cert/hostname verification yet:
    https://github.com/pyca/cryptography/pull/1888
    (but the stdlib tools are just fine since 3.4.3)
    """
    for netloc in tls_netlocs:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)

        ss = ssl.wrap_socket(
            s,
            cert_reqs=ssl.CERT_REQUIRED,
            ca_certs=use_custom_ca,
            do_handshake_on_connect=True)
        with s:
            ss.connect((netloc.host, netloc.port))
            certdict = ss.getpeercert()

        # https://docs.python.org/3/library/ssl.html#ssl.match_hostname
        ssl.match_hostname(certdict, netloc.host)

# TODO(JP): add cipher verification
# TODO(JP) cert signature algorithm verification
