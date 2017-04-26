# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


import datetime
import os
import uuid

import cryptography.hazmat.backends
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import NameOID

from ca_validate import (  # noqa=I100
    CustomCACertValidationError,
    CustomCACertValidator,
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


def cert_name(common_name):
    """
    Create x509.Name
    """
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mesosphere, Inc."),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])


def cert_builder(
        public_key,
        common_name="Root CA",
        issuer=None,
        basic_constraints=x509.BasicConstraints(ca=True, path_length=None),
        key_usage=cert_key_usage(key_cert_sign=True),
        not_valid_before=None,
        not_valid_after=None,
        valid_days=3650,
        ):
    """
    Create cert builder with some sensitive defaults CA cert. If no values are
    overriden then the certificate created by builder is a valid self signed
    root CA cert that can be used as a custom CA cert.

    Args:
        common_name (str): Certificate subject common name
        issuer (x509.Name): Issuer name, if not provided subject is used
        basic_constraints (x509.BasicConstraints): Custom basic constraints
            extension value
        key_usage (x509.KeyUsage): Custom key constraints extension value
        not_valid_before (datetime): From which time is a certificate valid
        not_valid_after (datetime): After which time is certificate invalid
        valid_days (int): Number of days that cert is valid

    Returns:
        x509.CertitificateBuilder
    """
    if not_valid_before is None:
        not_valid_before = datetime.datetime.utcnow()

    if not_valid_after is None:
        not_valid_after = not_valid_before + datetime.timedelta(days=valid_days)

    subject = cert_name(common_name)
    if issuer is None:
        issuer = subject

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

    Returns:
        PEM text representing serialized key.
    """
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')


def serialize_cert_to_pem(cert):
    """
    Serialize certificate to PEM format.

    Args:
        cert (x509.Certificate): Certificate to be serialized.

    Return:
        PEM text representing serialized certificate.
    """
    return cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')


def generate_valid_root_ca_cert_pem(private_key):
    """
    Helper to create and serialize root CA cert.

    Args:
        private_key (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey): Key that
            should be used for signing the certificate.

    Return:
        PEM text representing serialized certificate.
    """
    return serialize_cert_to_pem(
        sign_cert_builder(
            cert_builder(
                private_key.public_key()),
            private_key
            )
        )


def generate_root_ca_and_intermediate_ca(
        number=1,
        ):
    """
    Helper to create root CA cert and intermediate certs.

    Args:
        number (int): Number of intermediate certs. Not used if `common_names`
            arg is provided.

    Returns:
        Certificate chain up to the root self signed certificate.

        List[(x509.Certificate, rsa.RSAPrivateKey)]
    """
    chain = []

    root_ca_private_key = generate_rsa_private_key()
    root_ca = sign_cert_builder(
        cert_builder(root_ca_private_key.public_key()),
        root_ca_private_key
        )
    chain.append((root_ca, root_ca_private_key))

    parent, parent_private_key = root_ca, root_ca_private_key
    for i in range(0, number):
        intermediate_ca_private_key = generate_rsa_private_key()
        intermediate_ca = sign_cert_builder(
            cert_builder(
                intermediate_ca_private_key.public_key(),
                common_name="Intermediate CA {}".format(i),
                issuer=parent.subject,
                ),
            parent_private_key
        )
        chain.append((intermediate_ca, intermediate_ca_private_key))
        parent, parent_private_key = intermediate_ca, intermediate_ca_private_key

    return list(reversed(chain))


def serialize_cert_chain_to_pem(chain):
    """
    Serialize chain of certificates to PEM format string.

    Args:
        chain (List[x509.Certificate]): Chain of certificates to be serialized.

    Return:
        PEM text representing serialized certificate.
    """
    return ''.join([serialize_cert_to_pem(cert) for cert in chain])


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
        with pytest.raises(CustomCACertValidationError) as exc:
            pem = serialize_key_to_pem(generate_dsa_private_key())
            load_pem_private_key(pem)
        assert str(exc.value) == 'Unexpected private key type (not RSA or EC)'

    def test_invalid_data(self):
        """
        Loading from invalid data fails.
        """
        with pytest.raises(CustomCACertValidationError) as exc:
            load_pem_private_key('INVALID')
        assert 'Invalid private key: ' in str(exc.value)


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
                cert_builder(
                    key.public_key()),
                key
                )
            )
        load_pem_x509_cert(cert_bytes)

    def test_dsa_private_key(self):
        """
        Load valid X.509 certificate signed with unsupported (DSA) key.
        """
        with pytest.raises(CustomCACertValidationError) as exc:
            key = generate_dsa_private_key()
            cert_bytes = serialize_cert_to_pem(
                sign_cert_builder(
                    cert_builder(
                        key.public_key()),
                    key
                    )
                )
            load_pem_x509_cert(cert_bytes)
        assert str(exc.value) == 'Unexpected public key type (not RSA or EC)'

    def test_invalid_data(self):
        """
        Load certificate from invalid data fails.
        """
        with pytest.raises(CustomCACertValidationError) as exc:
            load_pem_x509_cert('INVALID')
        assert 'Invalid certificate: ' in str(exc.value)


class TestRSAKeyValidation:

    def test_invalid_key_size(self):
        """
        Certificate signed with weak RSA private key fails validation.
        """
        key = generate_rsa_private_key(key_size=1024)
        key_pem = serialize_key_to_pem(key)
        cert_pem = generate_valid_root_ca_cert_pem(key)
        ca_cert_validator = CustomCACertValidator(cert_pem, key_pem)
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        assert str(exc.value) == 'Private key size smaller than 2048 bits'

    def test_pub_private_key_mismatch(self):
        """
        Certificate signed with different private key fails validation.
        """
        key = serialize_key_to_pem(generate_rsa_private_key())
        cert = generate_valid_root_ca_cert_pem(generate_rsa_private_key())
        ca_cert_validator = CustomCACertValidator(cert, key)
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        assert str(exc.value) == 'private key does not match public key'

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
        ca_cert_validator = CustomCACertValidator(cert_pem, key_pem)
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        assert str(exc.value) == 'Private key size smaller than 256 bits'

    def test_pub_private_key_mismatch(self):
        """
        Certificate signed with different private key fails validation.
        """
        key = serialize_key_to_pem(generate_ec_private_key())
        cert = generate_valid_root_ca_cert_pem(generate_ec_private_key())
        ca_cert_validator = CustomCACertValidator(cert, key)
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        assert str(exc.value) == 'private key does not match public key'

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
                cert_builder(
                    private_key.public_key()),
                private_key,
                hashes.SHA1()
                )
            )
        ca_cert_validator = CustomCACertValidator(cert_pem, key_pem)
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        assert 'unsupported hash algorithm' in str(exc.value)

    def test_basic_constraints_extension_missing(self):
        """
        Certificate without BasicConstraints extension is not valid.
        """
        private_key = generate_rsa_private_key()
        key_pem = serialize_key_to_pem(private_key)
        cert_pem = serialize_cert_to_pem(
            sign_cert_builder(
                cert_builder(
                    private_key.public_key(),
                    basic_constraints=None),
                private_key,
                )
            )
        ca_cert_validator = CustomCACertValidator(cert_pem, key_pem)
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        assert 'required to have a basic constraints extension' \
            in str(exc.value)

    def test_basic_constraints_ca_false(self):
        """
        Certificate with basic constraints CA flag set to false is not valid.
        """
        private_key = generate_rsa_private_key()
        key_pem = serialize_key_to_pem(private_key)
        cert_pem = serialize_cert_to_pem(
            sign_cert_builder(
                cert_builder(
                    private_key.public_key(),
                    basic_constraints=x509.BasicConstraints(
                        ca=False, path_length=None)),
                private_key,
                )
            )
        ca_cert_validator = CustomCACertValidator(cert_pem, key_pem)
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        assert str(exc.value) == (
            'The custom CA certificate must have the basic constraint '
            '`CA` set to `true`'
            )

    # TODO(jp): this should just be a warning.
    # def test_basic_constraint_pathlen(self):
    #     """
    #     Certificate with basic constraints path length > 0 is not valid.
    #     """
    #     private_key = generate_rsa_private_key()
    #     key_pem = serialize_key_to_pem(private_key)
    #     cert_pem = serialize_cert_to_pem(
    #         sign_cert_builder(
    #             cert_builder(
    #                 private_key.public_key(),
    #                 basic_constraints=x509.BasicConstraints(
    #                     ca=True, path_length=10)),
    #             private_key,
    #             )
    #         )
    #     ca_cert_validator = CustomCACertValidator(cert_pem, key_pem)
    #     with pytest.raises(CustomCACertValidationError) as exc:
    #         ca_cert_validator.validate()
    #     assert str(exc.value) == \
    #         'Certificate basic constraints path_length is > 0'

    def test_key_usage_extension_missing(self):
        """
        Certificate without KeyUsage extension is not valid.
        """
        private_key = generate_rsa_private_key()
        key_pem = serialize_key_to_pem(private_key)
        cert_pem = serialize_cert_to_pem(
            sign_cert_builder(
                cert_builder(
                    private_key.public_key(),
                    key_usage=None),
                private_key,
                )
            )
        ca_cert_validator = CustomCACertValidator(cert_pem, key_pem)
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        assert str(exc.value) == (
            'The custom CA certificate is required to have a key '
            'usage extension'
            )

    def test_key_usage_key_cert_sign_flag_false(self):
        """
        Certificate with KeyUsage.keyCertSign set to False is not valid.
        """
        private_key = generate_rsa_private_key()
        key_pem = serialize_key_to_pem(private_key)
        cert_pem = serialize_cert_to_pem(
            sign_cert_builder(
                cert_builder(
                    private_key.public_key(),
                    key_usage=cert_key_usage(key_cert_sign=False)),
                private_key,
                )
            )
        ca_cert_validator = CustomCACertValidator(cert_pem, key_pem)
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        assert str(exc.value) == (
            'The custom CA certificate must have a key usage extension '
            'defining `keyCertSign` as `true`'
            )

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
                cert_builder(
                    private_key.public_key(),
                    not_valid_before=not_valid_before),
                private_key,
                )
            )
        ca_cert_validator = CustomCACertValidator(cert_pem, key_pem)
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        assert str(exc.value) == \
            'The custom CA certificate `notBefore` date is in the future'

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
                cert_builder(
                    private_key.public_key(),
                    not_valid_before=not_valid_before,
                    not_valid_after=not_valid_after),
                private_key,
                )
            )
        ca_cert_validator = CustomCACertValidator(cert_pem, key_pem)
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        assert str(exc.value) == \
            'The custom CA certificate `notAfter` date is in the past'

    def test_not_after_date_ending_soon(self):
        """
        Certificate notAfter date is in past.
        """
        not_valid_after = (
            datetime.datetime.utcnow() + datetime.timedelta(days=5))

        private_key = generate_rsa_private_key()
        key_pem = serialize_key_to_pem(private_key)
        cert_pem = serialize_cert_to_pem(
            sign_cert_builder(
                cert_builder(
                    private_key.public_key(),
                    not_valid_after=not_valid_after),
                private_key,
                )
            )
        ca_cert_validator = CustomCACertValidator(cert_pem, key_pem)
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        assert str(exc.value) == \
            'The custom CA certificate must be valid for at least 365 days'

    def test_intermediate_without_ca_chain(self):
        """
        Intermediate CA certificate was provided without a CA chain
        """
        chain = generate_root_ca_and_intermediate_ca(number=3)
        intermediate_ca, private_key = chain[0][0], chain[0][1]
        ca_cert_validator = CustomCACertValidator(
            serialize_cert_to_pem(intermediate_ca),
            serialize_key_to_pem(private_key)
            )
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        assert str(exc.value) == \
            'Certificate chain must be provided'

    def test_chain_cert_with_basic_constraints_ca_false(self):
        """
        Intermediate CA certificate was provided with CA chain where one
        of the certificates is with basic constraints CA:FALSE flag
        """
        chain = generate_root_ca_and_intermediate_ca()

        parent, parent_private_key = chain[0][0], chain[0][1]

        # Add new "intermediate" CA certificate with basic constrainst CA:FALSE
        intermediate_ca_private_key = generate_rsa_private_key()
        intermediate_ca = sign_cert_builder(
            cert_builder(
                intermediate_ca_private_key.public_key(),
                common_name="Intermediate CA with CA:FALSE",
                issuer=parent.subject,
                basic_constraints=x509.BasicConstraints(ca=False, path_length=None),
                ),
            parent_private_key
        )
        chain.append((intermediate_ca, intermediate_ca_private_key))
        parent, parent_private_key = intermediate_ca, intermediate_ca_private_key

        # Add valid intermediate CA certificate
        intermediate_ca_private_key = generate_rsa_private_key()
        intermediate_ca = sign_cert_builder(
            cert_builder(
                intermediate_ca_private_key.public_key(),
                common_name="Intermediate CA Final",
                issuer=parent.subject,
                ),
            parent_private_key
        )

        chaincerts = [item[0] for item in chain]
        chain_pem = serialize_cert_chain_to_pem(chaincerts)
        ca_cert_validator = CustomCACertValidator(
            serialize_cert_to_pem(intermediate_ca),
            serialize_key_to_pem(intermediate_ca_private_key),
            chain_pem,
            )
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        assert exc.match(
            'The chain certificate with subject .* does not have '
            'the basic constraint `CA` set to `true`'
            )

    def test_chain_cert_without_basic_constraints_extension(self):
        """
        Intermediate CA certificate was provided with CA chain where one
        of the certificates is without basic constraints extension.
        """
        chain = generate_root_ca_and_intermediate_ca()

        parent, parent_private_key = chain[0][0], chain[0][1]

        # Add new "intermediate" CA certificate with basic constrainst CA:FALSE
        intermediate_ca_private_key = generate_rsa_private_key()
        intermediate_ca = sign_cert_builder(
            cert_builder(
                intermediate_ca_private_key.public_key(),
                common_name="Intermediate CA with CA:FALSE",
                issuer=parent.subject,
                basic_constraints=None,
                ),
            parent_private_key
        )
        chain.append((intermediate_ca, intermediate_ca_private_key))
        parent, parent_private_key = intermediate_ca, intermediate_ca_private_key

        # Add valid intermediate CA certificate
        intermediate_ca_private_key = generate_rsa_private_key()
        intermediate_ca = sign_cert_builder(
            cert_builder(
                intermediate_ca_private_key.public_key(),
                common_name="Intermediate CA Final",
                issuer=parent.subject,
                ),
            parent_private_key
        )

        chaincerts = [item[0] for item in chain]
        chain_pem = serialize_cert_chain_to_pem(chaincerts)
        ca_cert_validator = CustomCACertValidator(
            serialize_cert_to_pem(intermediate_ca),
            serialize_key_to_pem(intermediate_ca_private_key),
            chain_pem,
            )
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        assert exc.match(
            'The chain certificate with subject .* does not have '
            'the basic constraint `CA` set to `true`'
            )

    def test_intermediate_cert_chain_missing_first_cert(self):
        """
        Intermediate CA certificate was provided with CA chain where the
        certificate issuer is missing.

        [Intermediate CA] -> [missing] -> [Parent CA] -> [Root CA]
        """
        chain = generate_root_ca_and_intermediate_ca(number=3)
        intermediate_ca, private_key = chain[0][0], chain[0][1]

        # Provide chain of certificates with missing certificate to test
        # that parent subject matches cert issuer
        chaincerts = [item[0] for item in chain[1:]]
        chain_pem = serialize_cert_chain_to_pem(chaincerts[1:])

        ca_cert_validator = CustomCACertValidator(
            serialize_cert_to_pem(intermediate_ca),
            serialize_key_to_pem(private_key),
            chain_pem,
            )
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        exc.match(
            'The first chain certificate \(subject .*\) must be the issuer of '
            'the custom CA certificate'
            )

    def test_intermediate_cert_chain_without_root_cert(self):
        """
        Intermediate CA certificate was provided with CA chain which is missing
        Root CA cert.

        [Intermediate CA] -> [Parent] -> [MISSING]
        """
        chain = generate_root_ca_and_intermediate_ca(number=3)
        intermediate_ca, private_key = chain[0][0], chain[0][1]

        chaincerts = [item[0] for item in chain[1:]]
        chain_pem = serialize_cert_chain_to_pem(chaincerts[:-1])

        ca_cert_validator = CustomCACertValidator(
            serialize_cert_to_pem(intermediate_ca),
            serialize_key_to_pem(private_key),
            chain_pem,
            )
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        exc.match(
            'The last chain certificate .* \(must be a root CA certificate\)')

    def test_intermediate_cert_chain_is_not_coherent(self):
        """
        Intermediate CA certificate was provided with CA chain where the chain
        has a "hole" and is not coherent.

        [Intermediate CA] -> [Parent] -> [MISSING] -> [Root CA]
        """
        chain = generate_root_ca_and_intermediate_ca(number=3)
        intermediate_ca, private_key = chain[0][0], chain[0][1]

        chaincerts = [item[0] for item in chain[1:]]
        chain_pem = (
            serialize_cert_chain_to_pem(chaincerts[:1]) +
            serialize_cert_chain_to_pem(chaincerts[2:])
            )

        ca_cert_validator = CustomCACertValidator(
            serialize_cert_to_pem(intermediate_ca),
            serialize_key_to_pem(private_key),
            chain_pem,
            )
        with pytest.raises(CustomCACertValidationError) as exc:
            ca_cert_validator.validate()
        exc.match(
            'The certificate chain is not coherent: the issuer of the child '
            'certificate with the subject `.*` is not equivalent to the '
            'subject `.*` of the parent certificate'
            )

    def test_valid_intermediate_cert_with_complete_chain(self):
        """
        Intermediate CA with complete cert chain
        """
        chain = generate_root_ca_and_intermediate_ca(number=3)
        intermediate_ca, private_key = chain[0][0], chain[0][1]

        chaincerts = [item[0] for item in chain[1:]]
        chain_pem = serialize_cert_chain_to_pem(chaincerts)

        CustomCACertValidator(
            serialize_cert_to_pem(intermediate_ca),
            serialize_key_to_pem(private_key),
            chain_pem,
        ).validate()

    def test_valid_intermediate_cert_with_complete_chain_by_openssl(self):
        """
        Intermediate CA with complete cert chain generated with openssl utility
        See: https://github.com/mesosphere/dcos-custom-ca-cert-configs
        """

        fixtures_dir = os.path.join(
            os.path.dirname(__file__), 'fixtures', 'test_03')

        with open(os.path.join(fixtures_dir, 'dcos-ca-certificate.crt'), 'rb') as f:
            intermediate_ca = f.read().decode('utf-8')

        with open(os.path.join(fixtures_dir, 'dcos-ca-certificate-key.key'), 'rb') as f:
            private_key = f.read().decode('utf-8')

        with open(os.path.join(fixtures_dir, 'dcos-ca-certificate-chain.crt'), 'rb') as f:
            chain_pem = f.read().decode('utf-8')

        CustomCACertValidator(
            intermediate_ca,
            private_key,
            chain_pem,
        ).validate()
