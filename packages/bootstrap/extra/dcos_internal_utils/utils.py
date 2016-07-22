import datetime
import fcntl
import ipaddress
import logging
import os
import random
import string
import subprocess
import uuid


import cryptography.hazmat.backends
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from jwt.utils import base64url_decode, bytes_to_number
from socket import gethostbyaddr, herror

log = logging.getLogger(__name__)


crypto_backend = cryptography.hazmat.backends.default_backend()


def read_file_line(filename):
    with open(filename, 'r') as f:
        return f.read().strip()


def random_string(length):
    choices = string.ascii_letters + string.digits
    return ''.join(random.choice(choices) for i in range(length))


def generate_RSA_keypair(key_size=2048):
    """
    Generate an RSA keypair with an exponent of 65537. Serialize the public
    key in the the X.509 SubjectPublicKeyInfo/OpenSSL PEM public key format
    (RFC 5280). Serialize the private key in the PKCS#8 (RFC 3447) format.

    Args:
        bits (int): the key length in bits.
    Returns:
        (private key, public key) 2-tuple, both unicode
        objects holding the serialized keys.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=crypto_backend)

    privkey_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    public_key = private_key.public_key()
    pubkey_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return privkey_pem.decode('ascii'), pubkey_pem.decode('ascii')


def load_pem_private_key(pem_data):
    pem_data = bytes(pem_data, 'ascii')
    return serialization.load_pem_private_key(
        pem_data,
        password=None,
        backend=crypto_backend)


def public_key_pem(private_key):
    public_key = private_key.public_key()
    pubkey_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return pubkey_pem.decode('ascii')


def dict_merge(dct, merge_dct):
    for k, v in merge_dct.items():
        if (k in dct and isinstance(dct[k], dict) and isinstance(merge_dct[k], dict)):
            dict_merge(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]


class Directory:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        log.info('Opening {}'.format(self.path))
        self.fd = os.open(self.path, os.O_RDONLY)
        log.info('Opened {} with fd {}'.format(self.path, self.fd))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        log.info('Closing {} with fd {}'.format(self.path, self.fd))
        os.close(self.fd)

    def lock(self):
        return Flock(self.fd, fcntl.LOCK_EX)


class Flock:
    def __init__(self, fd, op):
        (self.fd, self.op) = (fd, op)

    def __enter__(self):
        log.info('Locking fd {}'.format(self.fd))
        # If the fcntl() fails, an IOError is raised.
        fcntl.flock(self.fd, self.op)
        log.info('Locked fd {}'.format(self.fd))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        log.info('Unlocked fd {}'.format(self.fd))


def generate_CA_key_certificate(valid_days=3650):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=crypto_backend)

    privkey_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Mesosphere, Inc."),
        x509.NameAttribute(NameOID.COMMON_NAME, u"DC/OS Root CA"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=valid_days)
    ).serial_number(
        int(uuid.uuid4())
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).sign(key, hashes.SHA256(), crypto_backend)

    crt_pem = cert.public_bytes(serialization.Encoding.PEM)

    return privkey_pem.decode('ascii'), crt_pem.decode('ascii')


def generate_key_CSR(base_cn, master=False, marathon=False, extra_san=[]):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=crypto_backend)

    machine_ip = subprocess.check_output(
            ['/opt/mesosphere/bin/detect_ip'],
            stderr=subprocess.DEVNULL).decode('ascii').strip()

    san = [
        x509.DNSName(machine_ip),
        x509.DNSName('127.0.0.1'),
        x509.DNSName('localhost'),
        x509.IPAddress(ipaddress.IPv4Address(machine_ip)),
        x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
        ]

    if master:
        san += [
            x509.DNSName('master.mesos'),
            x509.DNSName('leader.mesos'),
        ]

    if marathon:
        san += [
            x509.DNSName('marathon.mesos'),
        ]

    try:
        host = gethostbyaddr(machine_ip)
        san += [x509.DNSName(host[0])]
    except herror:
        pass

    for s in extra_san:
        san.append(x509.DNSName(s))

    log.info('Subject Alternative Names: %s', san)

    # common name has a maximum length of 64 characters
    common_name = base_cn + ' on ' + machine_ip

    # cfssl ignores KeyUsage and ExtendedKeyUsage
    # so we currently take care of these in the
    # default signing profile
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'CA'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, 'San Francisco'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Mesosphere, Inc.'),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).add_extension(
        x509.SubjectAlternativeName(san),
        critical=False,
    ).add_extension(
        # digital signing
        x509.KeyUsage(True, False, True, False, False, False, False, False, False),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH,
            ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        critical=False,
    ).sign(key, hashes.SHA256(), crypto_backend)

    privkey_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    return privkey_pem.decode('ascii'), csr_pem.decode('ascii')


def jwks_to_public_keys(jwks):
    output = ''
    for key in jwks['keys']:
        # Extract the public modulus and exponent from the data.
        exponent_bytes = base64url_decode(key['e'].encode('ascii'))
        exponent_int = bytes_to_number(exponent_bytes)

        modulus_bytes = base64url_decode(key['n'].encode('ascii'))
        modulus_int = bytes_to_number(modulus_bytes)

        # Generate a public key instance from these numbers.
        public_numbers = rsa.RSAPublicNumbers(n=modulus_int, e=exponent_int)
        public_key = public_numbers.public_key(backend=crypto_backend)

        pubkey_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        output += pubkey_pem.decode('ascii')

    return output
