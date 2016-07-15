# -*- coding: utf-8 -*-
# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


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

from dcostests import dcos


log = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.security,
    pytest.mark.skipif(
        not pytest.config.getoption('expect_strict_security'),
        reason="SSL/TLS tests skipped: strict security mode not expected")
    ]


Netloc = namedtuple("Netloc", ["host", "port", "description"])

tls_netlocs = []

for host in dcos.masters:
    tls_netlocs.extend([
        Netloc(host, 5050, "Mesos (master)"),
        Netloc(host, 8443, "Root Marathon (master)"),
        Netloc(host, 9443, "Metronome (master)"),
        Netloc(host, 7443, "Cosmos (master)"),
        Netloc(host, 443, "Admin Router (master)"),
        ])

for host in dcos.agents:
    tls_netlocs.extend([
        Netloc(host, 5051, "Mesos (agent)"),
        Netloc(host, 61002, "Admin Router (agent)")
        ])

# Prepare string representation for network locations,
# to be consumed by pytest's parametrize().
tls_netloc_labels = [str(n) for n in tls_netlocs]


@pytest.mark.parametrize("netloc", tls_netlocs, ids=tls_netloc_labels)
def test_retrieve_server_cert(netloc):
    # Verify that the remote end expects an SSL/TLS connection at all, and
    # that it presents a certificate.
    cert_pem = ssl.get_server_certificate((netloc.host, netloc.port))


@pytest.mark.parametrize("netloc", tls_netlocs, ids=tls_netloc_labels)
def test_retrieve_server_cert_enforce_tls_1_2(netloc):
    cert_pem = ssl.get_server_certificate(
        addr=(netloc.host, netloc.port),
        ssl_version=ssl.PROTOCOL_TLSv1_2
        )


@pytest.mark.parametrize("netloc", tls_netlocs, ids=tls_netloc_labels)
def test_verify_server_cert_against_root_cert(netloc):
    cert_pem = ssl.get_server_certificate(
        addr=(netloc.host, netloc.port),
        ca_certs=dcos.ca_crt_file_path
        )


@pytest.mark.parametrize("netloc", tls_netlocs, ids=tls_netloc_labels)
def test_cert_issuer_and_subject(netloc):
    cert_pem = ssl.get_server_certificate((netloc.host, netloc.port))
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


@pytest.mark.parametrize("netloc", tls_netlocs, ids=tls_netloc_labels)
def test_cert_dns_names(netloc):
    cert_pem = ssl.get_server_certificate((netloc.host, netloc.port))
    cert = x509.load_pem_x509_certificate(
        cert_pem.encode('ascii'), crypto_backend())

    ext = cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    dns_names = ext.value.get_values_for_type(x509.DNSName)
    assert len(dns_names) > 1
    assert 'localhost' in dns_names
    log.info("dns names: %s", dns_names)
    # TODO(JP): how do we want to systematically test DNSName entries?
    # TODO(JP): check IPAddress OID


@pytest.mark.parametrize("netloc", tls_netlocs, ids=tls_netloc_labels)
def test_cert_hostname_verification(netloc):
    # Note: the cryptography package does not expose OpenSSL's
    # API for cert/hostname verification yet:
    # https://github.com/pyca/cryptography/pull/1888
    # (but the stdlib tools are just fine since 3.4.3)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)

    ss = ssl.wrap_socket(
        s,
        cert_reqs=ssl.CERT_REQUIRED,
        ca_certs=dcos.ca_crt_file_path,
        do_handshake_on_connect=True
        )
    with s:
        ss.connect((netloc.host, netloc.port))
        certdict = ss.getpeercert()

    # https://docs.python.org/3/library/ssl.html#ssl.match_hostname
    ssl.match_hostname(certdict, netloc.host)

# TODO(JP): add cipher verification
# TODO(JP) cert signature algorithm verification