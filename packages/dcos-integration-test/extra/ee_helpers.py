import cryptography.hazmat.backends
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pkgpanda.util import load_json

CRYPTOGRAPHY_BACKEND = cryptography.hazmat.backends.default_backend()

bootstrap_config = load_json('/opt/mesosphere/etc/bootstrap-config.json')
dcos_config = load_json('/opt/mesosphere/etc/expanded.config.json')

OPS_ENDPOINTS = [
    '/acs/api/v1/users/',
    '/dcos-history-service/',
    '/exhibitor',
    '/mesos',
    '/mesos_dns/v1/config',
    '/metadata',
    '/networking/api/v1/vips',
    '/pkgpanda/active.buildinfo.full.json',
    '/secrets/v1/store',
    '/system/health/v1',
    'pkgpanda/active/']


def sleep_app_definition(uid):
    return {
        'id': "/integration-test-sleep-app-%s" % uid,
        'cpus': 0.1,
        'mem': 32,
        'cmd': 'sleep 3600',
        'instances': 1,
        }


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
        backend=CRYPTOGRAPHY_BACKEND)

    privkey_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    public_key = private_key.public_key()
    pubkey_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return privkey_pem.decode('ascii'), pubkey_pem.decode('ascii')


def parse_dotenv(path):
    """Parse environment file as used by systemd.

    Args:
        path: dot env file path

    Returns:
        Generator(key, value)

    Remarks:
        Mostly copied from https://github.com/theskumar/python-dotenv/blob/master/dotenv/main.py#L94
    """

    with open(path) as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith('#') or '=' not in line:
                continue

            key, value = line.split('=', 1)

            # Remove any leading and trailing spaces in key, value
            key, value = key.strip(), value.strip()

            if len(value) > 0:
                quoted = value[0] == value[-1] == '"'
                if quoted:
                    value = value[1:-1]

            yield key, value
