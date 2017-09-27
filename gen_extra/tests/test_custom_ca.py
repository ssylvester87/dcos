"""
Tests generating configuration with custom CA certificate
"""

import json
import logging
import os
import tempfile
from collections import namedtuple, OrderedDict

import pytest

import gen
from gen.tests.utils import make_arguments

log = logging.getLogger(__name__)


class CertificateFile:
    """
    CertificateFile is a file that represents part of a certificate, i.e.
    cert, key or CA
    """

    __slots__ = ('content', 'path', 'file')

    def __init__(self, content, path, file=None):
        self.content = content
        self.path = path
        self.file = file


class Certificate(namedtuple('Certificate', 'cert key chain')):
    """
    Represents certificate stored on a filesystem.

    Args:
        cert, key, chain (CertificateFile): Files containing content for given
            file available on disk.
    """

    def to_genconf_arguments(self):
        """
        Returns a dict that can be used as a `gen.generate` or `gen.validate`
        arguments dict
        """
        return {
            'ca_certificate_path': self.cert.path,
            'ca_certificate_key_path': self.key.path,
            'ca_certificate_chain_path': self.chain.path,
            }


def temp_file(value=''):
    """
    Creates a temporary file with provided value.

    value (str, bytes): Value that file should be crated with. If `str` type is
        provided it's automatically encoded to `bytes` with `utf-8` encoding.
    """
    if isinstance(value, str):
        value = value.encode('utf-8')

    temp_file = tempfile.NamedTemporaryFile()
    temp_file.write(value)
    temp_file.flush()
    return temp_file


def certificate_file(content=''):
    """
    Creates a CertificateFile with underlying temporary file and provided
    content.
    """
    cert_file = temp_file(content)
    return CertificateFile(content=content, path=cert_file.name, file=cert_file)


@pytest.fixture(scope='session')
def invalid_certificate():
    """
    Generates certificate files with invalid stub content that isn't a valid
    certificate
    """
    cert = certificate_file(content='cert')
    key = certificate_file(content='key')
    chain = certificate_file(content='chain')

    yield Certificate(cert, key, chain)

    # Clean up underlying temporary files
    map(lambda cert_file: cert_file.file.close(), [cert, key, chain])


def certificate_file_from_file(path):
    """
    Load CertificateFile from file on disk.
    """
    with open(path, 'rb') as f:
        content = f.read().decode('utf-8')
    return CertificateFile(content=content, path=path)


def certificate_from_fixture_directory(name):
    """
    Load certificate files from fixtures directory.
    """
    base = os.path.join(os.path.dirname(__file__), 'fixtures', name)

    cert = certificate_file_from_file(
        os.path.join(base, 'dcos-ca-certificate.crt'))
    key = certificate_file_from_file(
        os.path.join(base, 'dcos-ca-certificate-key.key'))

    chain = None
    chain_path = os.path.join(base, 'dcos-ca-certificate-chain.crt')
    if os.path.isfile(chain_path):
        chain = certificate_file_from_file(chain_path)

    return Certificate(cert, key, chain)


@pytest.fixture(scope='session')
def rsa_root_only_certificate():
    """
    Loads RSA root only certificate from fixtures directory
    """
    return certificate_from_fixture_directory('rsa_root')


@pytest.fixture(scope='session')
def rsa_intermediate_certificate():
    """
    Loads RSA root only certificate from fixtures directory
    """
    return certificate_from_fixture_directory('rsa_intermediate')


class TestCustomCACertificate:

    # Path in `dcos-config.yaml` file where will be Custom CA certificate stored.
    CA_CONFIG_PATH = '/etc_master/ca.json'

    def _assert_result_errors(self, result, keys=[], messages={}):
        """
        Asserts that result from `gen.validate` function is a error.

        Args:
            result (dict): Result dict from `gen.validate` call.
            keys (list): Optionally list of config values that failed
            messages (dict): Optionally dict of config values that failed with
                matching error message. Error messages will be asserted to match
                for each field.

                {
                    "custom_key": "Failed to validate provided custom key"
                }
        """
        assert result['status'] == 'errors'
        assert 'errors' in result

        for key in keys:
            assert key in result['errors']

        for key, message in messages.items():
            assert result['errors'][key]['message'] == message

    def _find_ca_cert_config(self, generated_config):
        """
        Finds config item for custom CA cert in `dcos-config.yaml` file

        Returns:
            `None` if generated configuration doesn't contain entry for
            custom CA certificate.

            `Dict` containing rendered custom CA certificate.
        """
        package = generated_config.templates['dcos-config.yaml']['package']
        result = [
            item for item in package if item['path'] == self.CA_CONFIG_PATH]
        return result[0] if len(result) > 0 else None

    def test_not_providing_any_ca_cert_arguments_validates(self):
        """
        Not providing any ca_certificate related paths should validate the
        configuration.
        """
        result = gen.validate(make_arguments(new_arguments={}))
        assert result['status'] == 'ok'

    def test_not_providing_any_ca_cert_arguments_doesnt_output_ca_in_yaml(self):
        """
        Generated `docs-config.yaml` template doesn't contain
        `/etc_master/ca.cert` file when no cert related arguments are provided
        """
        generated = gen.generate(make_arguments(new_arguments={}))
        config = self._find_ca_cert_config(generated)
        assert config is None

    def test_configuring_only_cert_path_fails_validation(self):
        """
        Providing path to certificate without key fails.
        """
        arguments = make_arguments({
            'ca_certificate_path': '/',
            })
        result = gen.validate(arguments)
        self._assert_result_errors(result, messages={
            'ca_certificate_key_path':
                'Definition of `ca_certificate_key_path` is required '
                'when setting up a custom CA certificate'
            })

    def test_configuring_only_cert_key_path_fails_validation(self):
        """
        Providing path to certificate key without certificate fails.
        """
        arguments = make_arguments({
            'ca_certificate_key_path': '/',
            })
        result = gen.validate(arguments)
        self._assert_result_errors(result, messages={
            'ca_certificate_key_path':
                'Definition of `ca_certificate_path` is required '
                'when setting up a custom CA certificate'
            })

    def test_configuring_only_chain_path_fails_validation(self):
        """
        Providing path to certificate chain without certificate and key fails.
        """
        arguments = make_arguments({
            'ca_certificate_chain_path': '/',
            })
        result = gen.validate(arguments)
        self._assert_result_errors(result, messages={
            'ca_certificate_key_path':
                'Definition of `ca_certificate_path` is required '
                'when setting up a custom CA certificate'
            })

    def test_invalid_configuration_does_not_produces_user_warning(self, capfd):
        """
        When a validation runs with invalid configuration end user doesn't see
        the private key placement warning.
        """
        arguments = make_arguments({
            'ca_certificate_chain_path': '/',
            })
        gen.validate(arguments)

        (stdout, _stderr) = capfd.readouterr()
        assert "Note: You are using a custom CA certificate" not in stdout

    def test_adding_non_existing_paths_fails_validation(self):
        """
        Non-existing certificate paths should result in validation error
        """
        ca_arguments = {
            'ca_certificate_path': '/non/existing',
            'ca_certificate_key_path': '/non/existing-2',
            'ca_certificate_chain_path': '/non/existing-3',
            }
        arguments = make_arguments(ca_arguments)
        result = gen.validate(arguments)
        self._assert_result_errors(result, ca_arguments.keys())

    def test_configuring_valid_rsa_root_ca(
            self, rsa_root_only_certificate, caplog):
        """
        Valid file paths for certificate, key and chain validates config
        and generates `dcos-config.yaml` file with Custom CA certificate.
        """
        arguments = make_arguments({
            'ca_certificate_path': rsa_root_only_certificate.cert.path,
            'ca_certificate_key_path': rsa_root_only_certificate.key.path,
            'ca_certificate_chain_path': '',
        })

        generated = gen.generate(arguments)
        config = self._find_ca_cert_config(generated)
        assert config['content'].strip() == json.dumps(OrderedDict((
            ('ca_certificate', rsa_root_only_certificate.cert.content),
            ('ca_certificate_chain', ''),
            )))

        expected_message = 'Note: You are using a custom CA certificate.'
        ca_notes = [rec for rec in caplog.records if expected_message in rec.message]
        assert len(ca_notes) == 1

    def test_configuring_valid_rsa_intermediate_ca(
            self, rsa_intermediate_certificate, caplog):
        """
        Valid file paths for certificate, key and chain validates config
        and generates `dcos-config.yaml` file with Custom CA certificate.
        """
        arguments = make_arguments({
            'ca_certificate_path': rsa_intermediate_certificate.cert.path,
            'ca_certificate_key_path': rsa_intermediate_certificate.key.path,
            'ca_certificate_chain_path': rsa_intermediate_certificate.chain.path,
        })

        generated = gen.generate(arguments)
        config = self._find_ca_cert_config(generated)
        assert config['content'].strip() == json.dumps(OrderedDict((
            ('ca_certificate', rsa_intermediate_certificate.cert.content),
            ('ca_certificate_chain', rsa_intermediate_certificate.chain.content),
            )))

        expected_message = 'Note: You are using a custom CA certificate.'
        ca_notes = [rec for rec in caplog.records if expected_message in rec.message]
        assert len(ca_notes) == 1
