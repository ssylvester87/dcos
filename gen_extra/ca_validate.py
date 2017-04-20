# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
Validate the custom CA certificate and its related data.

Relevant parameters and their corresponding high-level description:

ca_certificate:

    A single X.509 CA certificate in the OpenSSL PEM format. Can be a root
    (self-issued) certificate or an intermediate (cross-certificate)
    certificate.


ca_certificate_key:

    The private key (either RSA or ECC) corresponding to the CA certificate,
    encoded in the PKCS#8 PEM format.


ca_certificate_chain:

    The complete CA certification chain required for end-entity certificate
    verification, in the OpenSSL PEM format.

    Must be left undefined if ca_certificate is a root CA certificate.

    If the ca_certificate is an intermediate CA certificate, this needs to
    contain all CA certificates comprising the complete sequence starting
    precisely with the CA certificate that was used to sign the certificate in
    ca_certificate and ending with a root CA certificate (where issuer and
    subject are the same entity), yielding a gapless certification path. The
    order is significant and the list must contain at least one certificate.
"""

import datetime
import itertools

import cryptography.hazmat.backends
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import  hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa


cryptography_default_backend = cryptography.hazmat.backends.default_backend()


class CustomCACertValidationError(Exception):
    pass


class CustomCACertValidator:

    # Minimal length for RSA type keys (in bits).
    RSA_KEY_MIN_SIZE = 2048

    # Minimal length for EC type keys (in bits).
    EC_KEY_MIN_SIZE = 256

    # Supported certificate signature hash algorithms.
    SUPPORTED_SIGNATURE_HASH_ALGORITHMS = (
        hashes.SHA256,
        hashes.SHA384,
        hashes.SHA512,
        # hashes.RIPEMD160,
        # hashes.Whirlpool,
        # hashes.BLAKE2b,
        # hashes.BLAKE2s,
    )

    # Minimal number of days days that the custom CA certificate needs to be
    # valid from now on.
    MIN_VALID_DAYS = 365

    def __init__(self, cert, key, chain=None):
        """
        Args:
            cert (str): X.509 CA certificate, encoded as text in the OpenSSL
                PEM format.

            key (str): Private key corresponding to the certificates provided
                via `cert`, encoded as text in the PKCS#8 PEM format.

            chain (str): Ordered chain of CA certificates in the OpenSSL
                PEM format. Required if the certificate `cert` is an
                intermediate CA certificate.
        """
        self.private_key = load_pem_private_key(key)
        self.cert = load_pem_x509_cert(cert)
        self.chain = chain

    def validate(self):
        """
        Perform the individual validation steps and raise a
        `CustomCACertValidationError` in case a check fails.

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
            constraints = self.get_basic_constraints(self.cert)
        except x509.ExtensionNotFound:
            raise CustomCACertValidationError(
                'The custom CA certificate is required to have a basic constraints extension')

        if not constraints.ca:
            raise CustomCACertValidationError(
                'The custom CA certificate must have the basic constraint `CA` set to `true`')

        # TODO(jp_: Let's make this a warning instead of a hard error.
        # path_length = self.basic_constraints.path_length
        # if path_length and path_length > 0:
        #    raise CustomCACertValidationError(
        #         'Certificate basic constraints path_length is > 0')

        try:
            if not self.key_usage.key_cert_sign:
                raise CustomCACertValidationError(
                    'The custom CA certificate must have a key usage extension '
                    'defining `keyCertSign` as `true`'
                    )
        except x509.ExtensionNotFound:
            raise CustomCACertValidationError(
                'The custom CA certificate is required to have a key '
                'usage extension'
                )

        if self.cert.not_valid_before > datetime.datetime.utcnow():
            raise CustomCACertValidationError(
                'The custom CA certificate `notBefore` date is in the future')

        if self.cert.not_valid_after < datetime.datetime.utcnow():
            raise CustomCACertValidationError(
                'The custom CA certificate `notAfter` date is in the past')

        valid_period = self.cert.not_valid_after - datetime.datetime.utcnow()
        if valid_period < datetime.timedelta(days=self.MIN_VALID_DAYS):
            raise CustomCACertValidationError(
                'The custom CA certificate must be valid for at least {} days'.format(
                    self.MIN_VALID_DAYS))

        if self.is_root:
            if self.chain is not None:
                raise CustomCACertValidationError(
                    'The custom CA certificate is a root CA certificate. '
                    'Therefore, no corresponding chain must be defined'
                    )
        else:
            self._validate_chain()


    def _validate_chain(self):
        """
        - Parse all certificates individually using OpenSSL (bindings), retain
          order.

        - Test that all certificates are CA certificates.

        - Test that the first (or only) cert’s subject is equal to the issuer of
          ca_certificate.

        - If this is a collection of multiple certificates, test that it defines
          a coherent chain: For N certificates and if N > 1: let i run from 1 to
          N-1, test that the issuer of certificate_i equals the subject of
          certificate_i+1

        - Test that the last (or only) certificate has matching issuer and
          subject (confirm that it is a root CA certificate).
        """
        if self.chain is None:
            raise CustomCACertValidationError(
                'Certificate chain must be provided')

        endmarker = '-----END CERTIFICATE-----'
        tokens = self.chain.split(endmarker)
        chaincerts = [
            load_pem_x509_cert(t + endmarker) for t in tokens if t.strip() != '']


        # TODO(JP): improve error messages to contain specifics that make it
        # easy to identify the bad certificate, or the bad pair of certificates
        # (emit subject or issuer or fingerprint or something like that).

        for chaincert in chaincerts:
            try:
                constraints = self.get_basic_constraints(chaincert)
            except x509.ExtensionNotFound:
                constraints = None

            if constraints is None or not constraints.ca:
                raise CustomCACertValidationError(
                    'All chain certificates must have the basic constraint '
                    '`CA` set to `true`')

        if self.cert.issuer != chaincerts[0].subject:
            raise CustomCACertValidationError(
                'The fist chain certificate must be the issuer of the custom CA certificate')

        if chaincerts[-1].issuer != chaincerts[-1].subject:
            raise CustomCACertValidationError(
                'The last chain certificate must have equivalent subject and '
                'issuer (must be a root CA certificate)')

        for childcert, parentcert in pairwise(chaincerts):
            if parentcert.subject != childcert.issuer:
                raise CustomCACertValidationError(
                    'The certificate chain is not coherent')


    def _validate_signature_hash_algorithm(self):
        """
        Validate certificate signature algorithm.

        Raises:
            CustomCACertValidationError
        """
        cert_algo = type(self.cert.signature_hash_algorithm)

        if cert_algo not in self.SUPPORTED_SIGNATURE_HASH_ALGORITHMS:
            # TODO(jp): improve error message, emit detail on mismatch.
            raise CustomCACertValidationError(
                'The custom CA certificate was signed with a unsupported hash algorithm')

    def _validate_rsa_keys(self):
        """
        Validates that RSA key used for signing has min required size and
        that private key is matching certificate signing key.
        """
        self._validate_keys_size(self.RSA_KEY_MIN_SIZE)

        if not self.rsa_keys_matching:
            raise CustomCACertValidationError(
                "private key does not match public key")

    def _validate_ec_keys(self):
        """
        Validates that EC key used for signing has min required size and
        that private key is matching certificate signing key.
        """
        self._validate_keys_size(self.EC_KEY_MIN_SIZE)

        if not self.ec_keys_matching:
            raise CustomCACertValidationError(
                "private key does not match public key")

    def _validate_keys_size(self, size):
        """
        Validates that private and public key are having at least given size.

        Args:
            size (int): Minimal size of private and certificate public key

        Raises:
            CustomCACertValidationError
        """
        if key_get_size(self.private_key) < size:
            raise CustomCACertValidationError(
                'Private key size smaller than {} bits'.format(
                    size))

        if key_get_size(self.cert.public_key()) < size:
            raise CustomCACertValidationError(
                'Public key size smaller than {} bits'.format(
                    size))

    def get_basic_constraints(self, cert):
        """
        BasicConstraints extension value from the certificate.

        Returns:
            x509.BasicConstraints

        Raises:
            x509.ExtensionNotFound
        """

        basic_constraints_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS)

        return basic_constraints_ext.value

    @property
    def key_usage(self):
        """
        KeyUsage extension value from the certificate.

        Returns:
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

        Returns:
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


def key_get_size(key):
    """
    Returns key size in bits for provided key.

    Args:
        key: Private or public key object from cryptography module.

    Returns:
        int: key size

    Raises:
        ValueError
    """
    if hasattr(key, 'key_size'):
        return key.key_size
    if hasattr(key, 'curve'):
        return key.curve.key_size
    raise ValueError('Key size could not be detected')


def load_pem_private_key(key_pem):
    """
    Load key from provided PEM/text representation.

    Expect one of:
        - RSA PKCS#8 PEM private key (RFC 3447, traditional OpenSSL format).
        - EC PKCS#8 PEM private key

    Args:
        key_pem (str): the PEM text representation of the data to verify.

    Returns:
        An object of type
        `cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`.

    Raises:
        CustomCACertValidationError
    """

    try:
        private_key = serialization.load_pem_private_key(
            data=key_pem.encode('utf-8'),
            password=None,
            backend=cryptography_default_backend
            )
    except (ValueError, UnsupportedAlgorithm) as e:
        raise CustomCACertValidationError('Invalid private key: %s' % e)

    if not isinstance(
            private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise CustomCACertValidationError(
            'Unexpected private key type (not RSA or EC)')

    return private_key


def load_pem_x509_cert(cert_pem):
    """
    Load X.590 certificate from the provided PEM/text representation.

    - Expect a single X.509 certificate in the "OpenSSL PEM format" (X.509
      certificate encoded using the ASN.1 DER, base64-encoded inbetween BEGIN
      CERTIFICATE and END CERTIFICATE lines).

    - Expect that the public key of the certificate is of type RSA or EC.

    Note that if the certificate text representations contains more than one
    certificate definition, x509.load_pem_x509_certificate would silently read
    only the first one.


    Args:
        cert_pem (str): the PEM text representation of the data to verify.

    Returns:
        `cert`, an object of type `cryptography.x509.Certificate`.

    Raises:
        CustomCACertValidationError
    """

    if cert_pem.count('BEGIN CERTIFICATE') > 1:
        raise CustomCACertValidationError(
            'Certificate data contains more than one certificate definition.')

    try:
        cert = x509.load_pem_x509_certificate(
            data=cert_pem.encode('utf-8'),
            backend=cryptography_default_backend
            )
    except ValueError as e:
        raise CustomCACertValidationError('Invalid certificate: %s' % e)

    public_key = cert.public_key()

    if not isinstance(
            public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise CustomCACertValidationError(
            'Unexpected public key type (not RSA or EC)')

    return cert


def pairwise(iterable):
    """
    >>> list(pairwise([]))
    []
    >>> list(pairwise([1]))
    []
    >>> list(pairwise([1,2]))
    [(1, 2)]
    >>> list(pairwise([1,2,3]))
    [(1, 2), (2, 3)]
    >>> list(pairwise([1,2,3,4]))
    [(1, 2), (2, 3), (3, 4)]

    From https://docs.python.org/3.5/library/itertools.html#itertools-recipes.
    """
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)
