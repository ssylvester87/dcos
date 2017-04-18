# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


import datetime
import uuid

import pytest

import cryptography.hazmat.backends
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, NameOID
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, dsa, rsa

from ca_validate import (
    CustomCACertConfiguration,
    ValidationError,
    load_pem_private_key,
    load_pem_x509_cert,
    )


cryptography_default_backend = cryptography.hazmat.backends.default_backend()


def generate_rsa_private_key(key_size=2048, public_exponent=65537):
    """
    Generate RSA private key.

    Args:
        key_size (int): RSA key size
        public_exponent (int): Key public exponent

    Return:
        rsa.RSAPrivateKey
    """
    return rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=cryptography_default_backend
        )


def generate_ec_private_key(curve=None):
    """
    Generate EC private key.

    Args:
        curve (ec.EllipticCurve): EC if not provided SECP384R1 used.

    Return:
        ec.EllipticCurvePrivateKey
    """
    curve = ec.SECP384R1() if curve is None else curve
    return ec.generate_private_key(
        curve=curve,
        backend=cryptography_default_backend
        )


def generate_dsa_private_key(key_size=1024):
    """
    Generate DSA private key.

    Args:
        key_size (int): Key size of DSA key.

    Return:
        ec.DSAPrivateKey
    """
    return dsa.generate_private_key(
        key_size=key_size,
        backend=cryptography_default_backend
        )


def cert_key_usage(**kwargs):
    """
    Helper to create x509.KeyUsage object. Function provide defaults (False)
    for unspecified KeyUsage arguments.

    Args:
        x509.KeyUsage keys. If not provided False is used for each arg.

    Return:
        x509.KeyUsage
    """
    required = [
        'digital_signature',
        'content_commitment',
        'key_encipherment',
        'data_encipherment',
        'key_agreement',
        'key_cert_sign',
        'crl_sign',
        'encipher_only',
        'decipher_only',
    ]
    for name in required:
        if name not in kwargs:
            kwargs[name] = False

    return x509.KeyUsage(**kwargs)


def generate_root_ca_cert_builder(
        public_key,
        common_name="Test",
        valid_days=3650,
        basic_constraints=x509.BasicConstraints(ca=True, path_length=None),
        key_usage=cert_key_usage(key_cert_sign=True),
        not_valid_before=None,
        not_valid_after=None,
        ):
    """
    Generate root CA cert builder with some sensitive defaults. If no values are
    overriden then the certificate created by builder is a valid custom CA cert.

    Args:
        common_name (str): Certificate issuer common name
        valid_days (int): Number of days that cert is valid
        basic_constraints (x509.BasicConstraints): Custom basic constraints
            extension value
        key_usage (x509.KeyUsage): Custom key constraints extension value
        not_valid_before (datetime): From which time is a certificate valid
        not_valid_after (datetime): After which time is certificate invalid

    Return:
        x509.CertitificateBuilder
    """
    if not_valid_before is None:
        not_valid_before = datetime.datetime.utcnow()

    if not_valid_after is None:
        not_valid_after = not_valid_before + datetime.timedelta(days=valid_days)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mesosphere, Inc."),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).not_valid_before(
        not_valid_before
    ).not_valid_after(
        not_valid_after
    ).serial_number(
        int(uuid.uuid4())
    )

    if basic_constraints:
        builder = builder.add_extension(basic_constraints, critical=True)

    if key_usage:
        builder = builder.add_extension(key_usage, critical=True)

    return builder


def sign_cert_builder(cert_builder, private_key, alg=None):
    """
    Create certificate from CertificateBuilder and sign with provided key and
    algorithm.

    Args:
        cert_builder (x509.CertificateBuilder): Certificate configuration that
            should be signed.

    Return:
        x509.Certificate
    """
    alg = alg if alg else hashes.SHA256()
    return cert_builder.sign(
        private_key=private_key,
        algorithm=alg,
        backend=cryptography_default_backend
        )


def serialize_key_to_pem(key):
    """
    Serialize private key to OpenSSL format with PEM encoding.

    Args:
        key (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey): Key to serialize

    Return:
        bytes array representing serialized key.
    """
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
        )


def serialize_cert_to_pem(cert):
    """
    Serialize certificate to PEM format.

    Args:
        cert (x509.Certificate): Certificate to be serialized.

    Return:
        bytes array representing serialized certificate.
    """
    return cert.public_bytes(encoding=serialization.Encoding.PEM)


def generate_valid_root_ca_cert_pem(private_key):
    """
    Helper to create and serialize root CA cert.

    Args:
        private_key (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey): Key that
            should be used for signing the certificate.

    Return:
        bytes array representing certificate.
    """
    return serialize_cert_to_pem(
        sign_cert_builder(
            generate_root_ca_cert_builder(
                private_key.public_key()),
            private_key
            )
        )


"""List of supported private key types"""
SUPPORTED_PRIVATE_KEY_GENERATORS = [
    generate_rsa_private_key, generate_ec_private_key]

"""Private key generators names"""
SUPPORTED_PRIVATE_KEY_GENERATORS_IDS = list(map(
    lambda f: f.__name__, SUPPORTED_PRIVATE_KEY_GENERATORS))


class TestPrivateKeyLoading:

    @pytest.mark.parametrize(
        "generator",
        SUPPORTED_PRIVATE_KEY_GENERATORS,
        ids=SUPPORTED_PRIVATE_KEY_GENERATORS_IDS)
    def test_supported_private_key(self, generator):
        """
        Load supported type of private key from bytes
        """
        pem = serialize_key_to_pem(generator())
        assert load_pem_private_key(pem)

    def test_dsa_private_key(self):
        """
        Loading unsupported private key (DSA) fails.
        """
        with pytest.raises(ValidationError) as e_info:
            pem = serialize_key_to_pem(generate_dsa_private_key())
            load_pem_private_key(pem)
        assert str(e_info.value) == 'Unexpected private key type (not RSA or EC)'

    def test_invalid_data(self):
        """
        Loading from invalid byte array fails.
        """
        with pytest.raises(ValidationError) as e_info:
            load_pem_private_key(b'INVALID')
        assert 'Invalid private key: ' in str(e_info.value)


class TestCertLoading:

    @pytest.mark.parametrize(
        "generator",
        SUPPORTED_PRIVATE_KEY_GENERATORS,
        ids=SUPPORTED_PRIVATE_KEY_GENERATORS_IDS)
    def test_supported_cert_key_loading(self, generator):
        """
        Load X509 certficate signed with supported key.
        """
        key = generator()
        cert_bytes = serialize_cert_to_pem(
            sign_cert_builder(
                generate_root_ca_cert_builder(
                    key.public_key()),
                key
                )
            )
        load_pem_x509_cert(cert_bytes)

    def test_dsa_private_key(self):
        """
        Load valid X.509 certificate signed with unsupported (DSA) key.
        """
        with pytest.raises(ValidationError) as e_info:
            key = generate_dsa_private_key()
            cert_bytes = serialize_cert_to_pem(
                sign_cert_builder(
                    generate_root_ca_cert_builder(
                        key.public_key()),
                    key
                    )
                )
            load_pem_x509_cert(cert_bytes)
        assert str(e_info.value) == 'Unexpected public key type (not RSA or EC)'

    def test_invalid_data(self):
        """
        Load certificate from invalid byte array fails.
        """
        with pytest.raises(ValidationError) as e_info:
            load_pem_x509_cert(b'INVALID')
        assert 'Invalid certificate: ' in str(e_info.value)


class TestRSAKeyValidation:

    def test_invalid_key_size(self):
        """
        Certificate signed with weak RSA private key fails validation.
        """
        key = generate_rsa_private_key(key_size=1024)
        key_pem = serialize_key_to_pem(key)
        cert_pem = generate_valid_root_ca_cert_pem(key)
        ca_cert_config = CustomCACertConfiguration(cert_pem, key_pem)
        with pytest.raises(ValidationError) as e_info:
            ca_cert_config.validate()
        assert str(e_info.value) == 'Private key size smaller than 2048 bits'

    def test_pub_private_key_mismatch(self):
        """
        Certificate signed with different private key fails validation.
        """
        key = serialize_key_to_pem(generate_rsa_private_key())
        cert = generate_valid_root_ca_cert_pem(generate_rsa_private_key())
        ca_cert_config = CustomCACertConfiguration(cert, key)
        with pytest.raises(ValidationError) as e_info:
            ca_cert_config.validate()
        assert str(e_info.value) == 'private key does not match public key'

    # TODO(mh) Is there a way to test that public key is smaller than private?


class TestECKeyValidation:

    @pytest.mark.skip(reason="How to ensure that openssl backend has weak EC?")
    def test_invalid_key_size(self):
        """
        Certificate signed with weak EC private key fails validation.
        """
        key = generate_ec_private_key(curve=ec.SECT163K1())
        key_pem = serialize_key_to_pem(key)
        cert_pem = generate_valid_root_ca_cert_pem(key)
        ca_cert_config = CustomCACertConfiguration(cert_pem, key_pem)
        with pytest.raises(ValidationError) as e_info:
            ca_cert_config.validate()
        assert str(e_info.value) == 'Private key size smaller than 256 bits'

    def test_pub_private_key_mismatch(self):
        """
        Certificate signed with different private key fails validation.
        """
        key = serialize_key_to_pem(generate_ec_private_key())
        cert = generate_valid_root_ca_cert_pem(generate_ec_private_key())
        ca_cert_config = CustomCACertConfiguration(cert, key)
        with pytest.raises(ValidationError) as e_info:
            ca_cert_config.validate()
        assert str(e_info.value) == 'private key does not match public key'

    # TODO(mh) Is there a way to test that public key is smaller than private?


class TestCertValidation:

    def test_weak_sign_hash_algorithm(self):
        """
        Certificate signed with a valid RSA key and weak hash is not valid.
        """
        private_key = generate_rsa_private_key()
        key_pem = serialize_key_to_pem(private_key)
        cert_pem = serialize_cert_to_pem(
            sign_cert_builder(
                generate_root_ca_cert_builder(
                    private_key.public_key()),
                private_key,
                hashes.SHA1()
                )
            )
        ca_cert_config = CustomCACertConfiguration(cert_pem, key_pem)
        with pytest.raises(ValidationError) as e_info:
            ca_cert_config.validate()
        assert str(e_info.value) == \
            'Certificate is signed with weak hash algorithm'

    def test_basic_constraints_extension_missing(self):
        """
        Certificate without BasicConstraints extension is not valid.
        """
        private_key = generate_rsa_private_key()
        key_pem = serialize_key_to_pem(private_key)
        cert_pem = serialize_cert_to_pem(
            sign_cert_builder(
                generate_root_ca_cert_builder(
                    private_key.public_key(),
                    basic_constraints=None),
                private_key,
                )
            )
        ca_cert_config = CustomCACertConfiguration(cert_pem, key_pem)
        with pytest.raises(ValidationError) as e_info:
            ca_cert_config.validate()
        assert str(e_info.value) == \
            'Certificate misses basic constraints extension'

    def test_basic_constraints_ca_false(self):
        """
        Certificate with basic constraints CA flag set to false is not valid.
        """
        private_key = generate_rsa_private_key()
        key_pem = serialize_key_to_pem(private_key)
        cert_pem = serialize_cert_to_pem(
            sign_cert_builder(
                generate_root_ca_cert_builder(
                    private_key.public_key(),
                    basic_constraints=x509.BasicConstraints(
                        ca=False, path_length=None)),
                private_key,
                )
            )
        ca_cert_config = CustomCACertConfiguration(cert_pem, key_pem)
        with pytest.raises(ValidationError) as e_info:
            ca_cert_config.validate()
        assert str(e_info.value) == \
            'Certificate basic constraints CA is false'

    def test_basic_constraint_pathlen(self):
        """
        Certificate with basic constraints path length > 0 is not valid.
        """
        private_key = generate_rsa_private_key()
        key_pem = serialize_key_to_pem(private_key)
        cert_pem = serialize_cert_to_pem(
            sign_cert_builder(
                generate_root_ca_cert_builder(
                    private_key.public_key(),
                    basic_constraints=x509.BasicConstraints(
                        ca=True, path_length=10)),
                private_key,
                )
            )
        ca_cert_config = CustomCACertConfiguration(cert_pem, key_pem)
        with pytest.raises(ValidationError) as e_info:
            ca_cert_config.validate()
        assert str(e_info.value) == \
            'Certificate basic constraints path_length is > 0'

    def test_key_usage_extension_missing(self):
        """
        Certificate without KeyUsage extension is not valid.
        """
        private_key = generate_rsa_private_key()
        key_pem = serialize_key_to_pem(private_key)
        cert_pem = serialize_cert_to_pem(
            sign_cert_builder(
                generate_root_ca_cert_builder(
                    private_key.public_key(),
                    key_usage=None),
                private_key,
                )
            )
        ca_cert_config = CustomCACertConfiguration(cert_pem, key_pem)
        with pytest.raises(ValidationError) as e_info:
            ca_cert_config.validate()
        assert str(e_info.value) == \
            'Certificate misses key usage extension'

    def test_key_usage_key_cert_sign_flag_false(self):
        """
        Certificate with KeyUsage.keyCertSign set to False is not valid.
        """
        private_key = generate_rsa_private_key()
        key_pem = serialize_key_to_pem(private_key)
        cert_pem = serialize_cert_to_pem(
            sign_cert_builder(
                generate_root_ca_cert_builder(
                    private_key.public_key(),
                    key_usage=cert_key_usage(key_cert_sign=False)),
                private_key,
                )
            )
        ca_cert_config = CustomCACertConfiguration(cert_pem, key_pem)
        with pytest.raises(ValidationError) as e_info:
            ca_cert_config.validate()
        assert str(e_info.value) == \
            'Certificate key usage keyCertSign is false'

    def test_not_before_date_in_future(self):
        """
        Certificate notBefore date is in future.
        """
        not_valid_before = (
            datetime.datetime.utcnow() + datetime.timedelta(days=1))
        private_key = generate_rsa_private_key()

        key_pem = serialize_key_to_pem(private_key)
        cert_pem = serialize_cert_to_pem(
            sign_cert_builder(
                generate_root_ca_cert_builder(
                    private_key.public_key(),
                    not_valid_before=not_valid_before),
                private_key,
                )
            )
        ca_cert_config = CustomCACertConfiguration(cert_pem, key_pem)
        with pytest.raises(ValidationError) as e_info:
            ca_cert_config.validate()
        assert str(e_info.value) == \
            'Certificate notBefore date is in future'

    def test_not_after_date_in_past(self):
        """
        Certificate notAfter date is in past.
        """
        not_valid_before = (
            datetime.datetime.utcnow() - datetime.timedelta(days=10))
        not_valid_after = not_valid_before + datetime.timedelta(days=5)

        private_key = generate_rsa_private_key()
        key_pem = serialize_key_to_pem(private_key)
        cert_pem = serialize_cert_to_pem(
            sign_cert_builder(
                generate_root_ca_cert_builder(
                    private_key.public_key(),
                    not_valid_before=not_valid_before,
                    not_valid_after=not_valid_after),
                private_key,
                )
            )
        ca_cert_config = CustomCACertConfiguration(cert_pem, key_pem)
        with pytest.raises(ValidationError) as e_info:
            ca_cert_config.validate()
        assert str(e_info.value) == \
            'Certificate notAfter date is in past'

    def test_not_after_date_ending_soon(self):
        """
        Certificate notAfter date is in past.
        """
        not_valid_after = datetime.datetime.utcnow() + datetime.timedelta(days=5)

        private_key = generate_rsa_private_key()
        key_pem = serialize_key_to_pem(private_key)
        cert_pem = serialize_cert_to_pem(
            sign_cert_builder(
                generate_root_ca_cert_builder(
                    private_key.public_key(),
                    not_valid_after=not_valid_after),
                private_key,
                )
            )
        ca_cert_config = CustomCACertConfiguration(cert_pem, key_pem)
        with pytest.raises(ValidationError) as e_info:
            ca_cert_config.validate()
        assert str(e_info.value) == \
            'Certificate must be valid at least 365 days'
