import base64
import datetime
import fcntl
import ipaddress
import logging
import os
import random
import string
import subprocess
import uuid
from collections import namedtuple
from socket import gethostbyaddr, herror


import cryptography.hazmat.backends
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from jwt.utils import base64url_decode, bytes_to_number

import gen

log = logging.getLogger(__name__)


crypto_backend = cryptography.hazmat.backends.default_backend()

SanEntry = namedtuple("SanEntry", ['type', 'val'])

# Certificate Common Name length is restricted to 64 characters per RFC 5280
COMMON_NAME_MAX_LENGTH = 64


def read_file_line(filename):
    with open(filename, 'r') as f:
        return f.read().strip()


def random_string(length):
    choices = string.ascii_letters + string.digits
    return ''.join(random.choice(choices) for i in range(length))


def generate_executor_secret_key():
    # Generate 256 random bytes and transform to an ascii-safe representation
    # 5/4 the size (generate 320 random ascii characters).
    return base64.b85encode(os.urandom(256)).decode('ascii')


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


def get_private_key_type_from_name(name):
    """
    Returns private key class from provided name

    Return:
        Either ec.EllipticCurvePrivateKey or rsa.RSAPrivateKey
    """
    supported_modules = [ec, rsa]
    for module in supported_modules:
        if hasattr(module, name):
            return getattr(module, name)

    raise ValueError('`{}` is unsupported private key type'.format(name))


def get_private_key_type_name_from_object(private_key):
    """
    Returns a string representing private key type
    """
    supported_types = [ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]
    for key_type in supported_types:
        if isinstance(private_key, key_type):
            return key_type.__name__

    raise ValueError('`{}` is unsupported private key'.format(private_key))


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


def generate_CA_key_certificate(valid_days=3650, cn_suffix=None):
    # The default certificate Common Name that can be optionally extended with
    # the `cn_suffix` parameter.
    common_name = "DC/OS Root CA"
    if cn_suffix:
        common_name = "{} {}".format(common_name, cn_suffix)

    # Certificate common name length is restricted to 64 characters per RFC 5280
    # By default we're adding "DC/OS Root CA" prefix so we need to make sure that
    # provided common name and prefix are shorter than 64 characters constraint.
    if len(common_name) > COMMON_NAME_MAX_LENGTH:
        raise ValueError(
            "Comman Name longer than {} characters: {}".format(
                COMMON_NAME_MAX_LENGTH, common_name)
            )

    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=crypto_backend)

    privkey_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mesosphere, Inc."),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
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


def detect_ip():
    cmd = ['/opt/mesosphere/bin/detect_ip']
    machine_ip = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode('ascii').strip()
    gen.calc.validate_ipv4_addresses([machine_ip])
    return machine_ip


def generate_key_CSR(
        base_cn,
        master=False,
        marathon=False,
        extra_san=None,
        private_key_type=rsa.RSAPrivateKey,
        use_exact_cn=False
        ):
    """Creates a private key and certificate.

    Args:
        base_cn (str):
            Defines the value of the "common name" attribute of the subject of
            the X.509 certificate: the certificate subject field contains an
            X.500 distinguished name (DN). The subject DN itself is comprised
            of multiple attributes. This parameter defines the value of the
            attribute with OID 2.5.4.3 (usually abbreviated "CN"). By default,
            the current machine's internal IP address as returned by
            `detect_ip()` is appended to the name. Set the `use_exact_cn`
            parameter to True to prevent that modification from happening.
        master (bool):
            If True the master DNS entries will be added to the
            list of SANs. Defaults to False.
        marathon (bool):
            If True the Marathon DNS entries will be added to
            the list of SANs. Defaults to False.
        extra_san ([cryptography.GeneralName], optional):
            A list of additional SANs to be added to the certificate.
        private_key_type (rsa.RSAPrivateKey or ec.EllipticCurvePrivateKey):
            The type of private key to generate.
            Defaults to rsa.RSAPrivateKey
        use_exact_cn (bool):
            If `use_exact_cn` is False the value of `base_cn` is modified
            for use as the CommonName in the certificate. If True,
            the value of `base_cn` is used exactly as the CommonName in the
            certificate.

    Returns:
        A tuple containing two PEM-encoded strings. The first is a 2048-bit
        RSA private key and the second is a Certificate Signing Request.
    """
    if private_key_type is rsa.RSAPrivateKey:
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=crypto_backend)
    elif private_key_type is ec.EllipticCurvePrivateKey:
        # TODO(mh): Add support for ec.SECP384R1?
        key = ec.generate_private_key(ec.SECP256R1(), crypto_backend)
    else:
        raise ValueError('Unsupported private_key_type')

    machine_ip = detect_ip()

    san = [
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

    # Add IP addresses as DNSName records for legacy reasons, i.e. some clients
    # don't support IPAddress SAN record types. It's important to add these as
    # last entries so Firefox can validate certificates. See DCOS_OSS-646
    ip_addresses_as_dns_names = [
        x509.DNSName(machine_ip),
        x509.DNSName('127.0.0.1'),
    ]

    if extra_san is not None:
        for s in extra_san:
            if s.type == 'dns':
                # If DNSName looks like an IP address add it to the last position
                try:
                    ipaddress.ip_address(s.val)
                    ip_addresses_as_dns_names.append(x509.DNSName(s.val))
                except ValueError:
                    san.append(x509.DNSName(s.val))
            elif s.type == 'ip':
                san.append(x509.IPAddress(ipaddress.IPv4Address(s.val)))
            else:
                msg_fmt = "Unrecognized extra_san entry type: %s for %s"
                raise AssertionError(msg_fmt.format(s.type, s.val))

    san.extend(ip_addresses_as_dns_names)

    log.info('Subject Alternative Names: %s', san)

    # common name has a maximum length of 64 characters
    if use_exact_cn:
        common_name = base_cn
    else:
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
