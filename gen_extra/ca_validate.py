# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
Verify user-given certificate and key data:

- Require a single X.509 root CA certificate and the corresponding private
  key.
- Require the certificate to be encoded in the "OpenSSL PEM format".
- Require an RSA private key of at least 2048 bit strength key encoded in
  the PKCS#8 PEM format.
"""

import datetime

import cryptography.hazmat.backends
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import  hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa


cryptography_default_backend = cryptography.hazmat.backends.default_backend()


class CustomCACertConfiguration:
    """
    Custom CA certificate configuration is helper that allows to validate all
    properties of provided CA certificate and encryption key.
    """

    """Min bits size for RSA encryption key"""
    RSA_KEY_MIN_SIZE = 2048

    """Min bits size for EC encryption key"""
    EC_KEY_MIN_SIZE = 256

    """Supported certificate signature hash algorithms"""
    SIGN_HASH_ALGORITHMS = (
        hashes.SHA256,
        hashes.SHA384,
        hashes.SHA512,
        hashes.RIPEMD160,
        hashes.Whirlpool,
        hashes.BLAKE2b,
        hashes.BLAKE2s,
    )

    """Min days that certificate needs to be valid in future"""
    MIN_VALID_DAYS = 365

    def __init__(self, cert_bytes, key_bytes, chain_bytes=None):
        """
        Args:
            cert_bytes (bytes): PEM encoded X509 certificate
            key_bytes (bytes): PEM encoded private key used for signing the
                certificate
            chain_bytes (bytes): PEM encoded CA chain if the provided
                certificate is intermediate CA certificate
        """
        self.private_key = load_pem_private_key(key_bytes)
        self.cert = load_pem_x509_cert(cert_bytes)
        self.chain = chain_bytes

    def validate(self):
        """
        Execute all validation rules and raises an exception if some
        certificate or private key requirements aren't met.

        Raises:
            ValidationError

        - RSA key size is at least 2048 bits.
        - EC key size is at least 256 bits.

        - Private and public key are matching.

        - Signed with a strong hash algorithm.

        - BasicConstraints extension is present and `CA` is enabled.
        - BasicConstraints `path_length` is 0.

        - KeyUsage extension is present and `keyCertSign` is enabled.

        - `notBefore` date is not in future.
        - `notAfter` date is not in past.
        - `notAfter` date makes certificate valid at least 1 year.

        - Root CA is not configured with any certificate chain.
        """

        if isinstance(self.private_key, rsa.RSAPrivateKey):
            self._validate_rsa_keys()

        if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            self._validate_ec_keys()

        self._validate_signature_hash_algorithm()

        try:
            if not self.basic_constraints.ca:
                raise ValidationError(
                    'Certificate basic constraints CA is false')

            path_length = self.basic_constraints.path_length
            if path_length and path_length > 0:
                raise ValidationError(
                    'Certificate basic constraints path_length is > 0')
        except x509.ExtensionNotFound:
            raise ValidationError(
                'Certificate misses basic constraints extension')

        try:
            if not self.key_usage.key_cert_sign:
                raise ValidationError(
                    'Certificate key usage keyCertSign is false')
        except x509.ExtensionNotFound:
            raise ValidationError(
                'Certificate misses key usage extension')

        if self.cert.not_valid_before > datetime.datetime.utcnow():
            raise ValidationError(
                'Certificate notBefore date is in future')

        if self.cert.not_valid_after < datetime.datetime.utcnow():
            raise ValidationError(
                'Certificate notAfter date is in past')

        valid_period = self.cert.not_valid_after - datetime.datetime.utcnow()
        if valid_period < datetime.timedelta(days=self.MIN_VALID_DAYS):
            raise ValidationError(
                'Certificate must be valid at least {} days'.format(
                    self.MIN_VALID_DAYS))

        if self.is_root and len(self.chain) > 0:
            raise ValidationError(
                'Certificate is root CA and does not require CA chain')

        # chain must lead to cert

    def _validate_signature_hash_algorithm(self):
        """
        Validates certificate signature algorithm

        Raises:
            ValidationError
        """
        cert_algo = self.cert.signature_hash_algorithm

        for supported_algo in self.SIGN_HASH_ALGORITHMS:
            if isinstance(cert_algo, supported_algo):
                return

        raise ValidationError(
            'Certificate is signed with weak hash algorithm')

    def _validate_rsa_keys(self):
        """
        Validates that RSA key used for signing has min required size and
        that private key is matching certificate signing key.
        """
        self._validate_keys_size(self.RSA_KEY_MIN_SIZE)

        if not self.rsa_keys_matching:
            raise ValidationError("private key does not match public key")

    def _validate_ec_keys(self):
        """
        Validates that EC key used for signing has min required size and
        that private key is matching certificate signing key.
        """
        self._validate_keys_size(self.EC_KEY_MIN_SIZE)

        if not self.ec_keys_matching:
            raise ValidationError("private key does not match public key")

    def _validate_keys_size(self, size):
        """
        Validates that private and public key are having at least given size.

        Args:
            size (int): Minimal size of private and certificate public key

        Raises:
            ValidationError
        """
        if key_get_size(self.private_key) < size:
            raise ValidationError(
                'Private key size smaller than {} bits'.format(
                    size))

        if key_get_size(self.cert.public_key()) < size:
            raise ValidationError(
                'Public key size smaller than {} bits'.format(
                    size))

    @property
    def basic_constraints(self):
        """
        BasicConstraints extension value from the certificate.

        Return:
            x509.BasicConstraints

        Raises:
            x509.ExtensionNotFound
        """

        basic_constraints_ext = self.cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS)

        return basic_constraints_ext.value

    @property
    def key_usage(self):
        """
        KeyUsage extension value from the certificate.

        Return:
            x509.BasicConstraints

        Raises:
            x509.ExtensionNotFound
        """

        key_usage_ext = self.cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE)

        return key_usage_ext.value

    @property
    def is_root(self):
        """
        Checks if certificate is a root ceritficate.

        Return:
            Boolean
        """
        return self.cert.issuer == self.cert.subject

    @property
    def ec_keys_matching(self):
        """
        Verify that the private and the public key share the same modulus.

        Retrun:
            Boolean if private and public key are matching
        """
        pubkey_pubnumbers = self.cert.public_key().public_numbers()
        privkey_pubnumbers = self.private_key.private_numbers().public_numbers

        # TODO(mh) Is this true?
        x_match = pubkey_pubnumbers.x == privkey_pubnumbers.x
        y_match = pubkey_pubnumbers.y == privkey_pubnumbers.y
        return x_match and y_match

    @property
    def rsa_keys_matching(self):
        """
        Verify that the private and the public key share the same modulus.

        Retrun:
            Boolean if private and public key are matching
        """
        pubkey_pubnumbers = self.cert.public_key().public_numbers()
        privkey_pubnumbers = self.private_key.private_numbers().public_numbers

        return pubkey_pubnumbers.n == privkey_pubnumbers.n

    def _keys_pubnumbers_matching(self, property_names=[]):
        # TODO(mh): Stat using this value
        pubnumbers = [
            self.cert.public_key().public_numbers(),
            self.private_key.private_numbers().public_numbers,
            ]

        for property_name in property_names:
            values = set()
            for pubnumber in pubnumbers:
                if not hasattr(pubnumber, property_name):
                    raise ValueError('property name {} not found'.format(property_name))
                values.add(getattr(pubnumber, property_name))
            # Can't match, more than one unique value for given property
            if len(values) > 1:
                return False

        return True

class ValidationError(Exception):
    """
    General custom CA certificate validation error
    """
    pass


def key_get_size(key):
    """
    Retrieve a key size from provided key.

    Args:
        key: Private or public key from cryptography module.

    Return:
        int: key size

    Raises:
        ValueError
    """
    if hasattr(key, 'key_size'):
        return key.key_size
    if hasattr(key, 'curve'):
        return key.curve.key_size
    raise ValueError('Key size could not be detected')


def load_pem_private_key(data):
    """Implement private key loading.

    Expect one of:
        - RSA PKCS#8 PEM private key (RFC 3447, traditional OpenSSL format).
        - EC PKCS#8 PEM private key

    Args:
        data (bytes): the bytes to verify.

    Returns:
        An object of type
        `cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`.

    Raises:
        ValidationError
    """
    try:
        private_key = serialization.load_pem_private_key(
            data=data,
            password=None,
            backend=cryptography_default_backend
            )
    except (ValueError, UnsupportedAlgorithm) as e:
        raise ValidationError('Invalid private key: %s' % e)

    if not isinstance(
            private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise ValidationError('Unexpected private key type (not RSA or EC)')

    return private_key


def load_pem_x509_cert(data):
    """
    Load X590 certificate from provided data array.

    - Expect a single certificate.

    - Expect a X.509 certificate in the "OpenSSL PEM format" (X.509
      certificate encoded using the ASN.1 DER, base64-encoded inbetween BEGIN
      CERTIFICATE and END CERTIFICATE lines).

    - Expect that the public key of the certificate is of type RSA or EC

    Note that if the certificate data blob contained more than one certificate
    definition, x509.load_pem_x509_certificate would silently read only the
    first one.

    Returns:
        `cert` is an object of type `cryptography.x509.Certificate`

    Raises:
        ValidationError
    """
    if data.count(b'BEGIN CERTIFICATE') > 1:
        raise ValidationError(
            'Certificate data contains more than one certificate definition.')

    try:
        cert = x509.load_pem_x509_certificate(
            data=data,
            backend=cryptography_default_backend
            )
    except ValueError as e:
        raise ValidationError('Invalid certificate: %s' % e)

    public_key = cert.public_key()

    if not isinstance(
            public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise ValidationError('Unexpected public key type (not RSA or EC)')

    return cert
