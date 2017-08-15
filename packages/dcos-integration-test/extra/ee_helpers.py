"""
A set of utilities that is used in the dcos-intergration-test test modules in
the dcos-enterprise repository.
"""


import cryptography.hazmat.backends
# Note(JP): isort is not well-configured. Import of custom code should be below
# import of third party modules.
import dcos_test_utils
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
    '/networking/api/v1/vips',
    '/pkgpanda/active.buildinfo.full.json',
    '/secrets/v1/store',
    '/system/health/v1',
    'pkgpanda/active/']


class _DCOSNodes:
    """
    Meant to be instantiated as a singleton during module import. That singleton
    then represents the nodes in the test cluster and can be used in other
    modules at import time. This assumes that the DC/OS cluster has

    - at least one master node
    - at least one (private) agent node
    - at least one public agent node

    This code also assumes that the corresponding data is available at import
    time without performing networked I/O. That is, the node information must be
    readily available to the test runner process through e.g. the process
    environment, file input, or command line arguments.

    The public (and intended to be stable) interface of this class is comprised
    of the following attributes:

        - `masters`: a list of strings, the master node hostnames/IP addresses
        - `agents`: a list of strings, the (private) agent node hostnames/IP
          addresses
        - `public_agents`: a list of strings, the public agent node hostnames/IP
          addresses
        - `all_agents`: a list of strings, the node hostnames/IP addresses for
          all agent nodes

    As of now this uses the same environment-based interface as the dcos_api_session:
    https://github.com/mesosphere/dcos-test-utils/blob/c4b660991995f20a8e6d3ed08bdb1e691374530f/dcos_test_utils/dcos_api_session.py#L123
    """
    def __init__(self):

        cluster_args = dcos_test_utils.enterprise.EnterpriseApiSession.get_args_from_env()

        self.masters = sorted(cluster_args['masters'])
        self.agents = sorted(cluster_args['slaves'])
        self.public_agents = sorted(cluster_args['public_slaves'])

        self.all_agents = self.agents + self.public_agents


# This singleton creation during module import is required for tests that need
# to be (pytest-)parametrized with / based on the set of nodes. In pytest,
# parametrization is performed during the collection phase which is about the
# same as during module import. That is, this data must be available through
# Python's import system and not be provided through a pytest fixture.
DCOS_NODES = _DCOSNodes()


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
