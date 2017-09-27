# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

"""
Validate the custom CA certificate and its related data.

Relevant parameters and their corresponding high-level description:

ca_certificate_path:

    A single X.509 CA certificate in the OpenSSL PEM format. Can be a root
    (self-issued) certificate or an intermediate (cross-certificate)
    certificate.


ca_certificate_key_path:

    The private key (either RSA or ECC) corresponding to the CA certificate,
    encoded in the PKCS#8 PEM format.


ca_certificate_chain_path:

    The complete CA certification chain required for end-entity certificate
    verification, in the OpenSSL PEM format.

    Must be left undefined if ca_certificate_path is a root CA certificate.

    If the CA certificate is an intermediate CA certificate, this needs to
    contain all CA certificates comprising the complete sequence starting
    precisely with the CA certificate that was used to sign the certificate in
    ca_certificate_path and ending with a root CA certificate (where issuer and
    subject are the same entity), yielding a gapless certification path. The
    order is significant and the list must contain at least one certificate.
"""

import datetime
import itertools
import os
import subprocess
from collections import OrderedDict
from tempfile import NamedTemporaryFile

import cryptography.hazmat.backends
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, SignatureAlgorithmOID

cryptography_default_backend = cryptography.hazmat.backends.default_backend()


class CertName:
    """
    An X.509 name (subject or issuer) is an ordered list of sets of attributes
    whereas each attribute has its own structured object identifier (OID). An
    established and simplified representation of that data structure is a
    comma-separated string (text) where each attribute name is abbreviated with
    letters like CN or O. This is more or less well-standardized via RFC 5280
    and RFC 1779.

    Example usage:

        >>> from cryptography import x509
        >>> from cryptography.hazmat.backends import default_backend
        >>> pemdata = open('cert.crt', 'rb').read()
        >>> cert = x509.load_pem_x509_certificate(pemdata, default_backend())
        >>> CertName(cert).subject
        'C=US, ST=CA, L=San Francisco, O=Mesosphere, Inc., CN=Root CA'

    Refs:
        - https://tools.ietf.org/html/rfc5280#section-4.1.2.4 (defines the set
            of attributes to be expected)
        - https://tools.ietf.org/html/rfc1779 (defines how distinguished names
            should be represented as strings, defines some shortnames)
    """

    _longname_shortname_mapping = {
        'commonName': 'CN',
        'countryName': 'C',
        'organizationalUnit': 'OU',
        'stateOrProvinceName': 'ST',
        'localityName': 'L',
        'organizationName': 'O',
        }

    def __init__(self, cert):
        """
        Args:
            cert: an object of type `cryptography.x509.Certificate`

        The resulting object has the attributes `subject` and `issuer`, both
        being text representations (type `str`) of the subject and issuer
        data in the provided certificate.
        """
        if not isinstance(cert, x509.Certificate):
            raise ValueError('cert must be x509.Certificate instance')

        subject_parts = []
        for nameattr in cert.subject:
            try:
                key = self._longname_shortname_mapping[nameattr.oid._name]
            except KeyError:
                # Fall back to long name.
                key = nameattr.oid._name
            subject_parts.append('{}={}'.format(key, nameattr.value))
        self.subject = ', '.join(subject_parts)

        issuer_parts = []
        for nameattr in cert.issuer:
            try:
                key = self._longname_shortname_mapping[nameattr.oid._name]
            except KeyError:
                # Fall back to long name.
                key = nameattr.oid._name
            issuer_parts.append('{}={}'.format(key, nameattr.value))
        self.issuer = ', '.join(issuer_parts)


class CustomCACertValidationError(Exception):
    pass


class CustomCACertValidator:

    # Minimal length for RSA type keys (in bits).
    RSA_KEY_MIN_SIZE = 2048

    # Minimal length for EC type keys (in bits).
    EC_KEY_MIN_SIZE = 256

    # Supported certificate signature algorithms OIDs.
    SUPPORTED_SIGNATURE_ALGORITHM_OIDS = (
        # RSA
        SignatureAlgorithmOID.RSA_WITH_SHA256,
        SignatureAlgorithmOID.RSA_WITH_SHA384,
        SignatureAlgorithmOID.RSA_WITH_SHA512,
        # ECDSA
        SignatureAlgorithmOID.ECDSA_WITH_SHA256,
        SignatureAlgorithmOID.ECDSA_WITH_SHA384,
        SignatureAlgorithmOID.ECDSA_WITH_SHA512,
    )

    # We support only NIST P-256 and P-384 curves that are widely accepted
    # by various software.
    # See: DCOS-15766
    SUPPORTED_EC_CURVES = (
        ec.SECP256R1,
        ec.SECP384R1,
    )

    # Minimal number of days days that the custom CA certificate needs to be
    # valid from now on.
    MIN_VALID_DAYS = 365

    # Path where the private key is expected on the master nodes
    PRIVATE_KEY_PATH_ON_MASTERS = '/var/lib/dcos/pki/tls/CA/private/custom_ca.key'

    def __init__(self, cert, key, chain=None, allow_ec_key=True):
        """
        Args:
            cert (str): X.509 CA certificate, encoded as text in the OpenSSL
                PEM format.

            key (str): Private key corresponding to the certificate provided
                via `cert`, encoded as text in the PKCS#8 PEM format.

            chain (str): Ordered chain of CA certificates in the OpenSSL
                PEM format. The `chain` is required if the certificate
                provided in `cert` is an intermediate CA certificate
                and must form a chain from `cert` to a root CA certificate.

            allow_ec_keys (bool): Enable or disable support for EC private key.
        """
        self.private_key = load_pem_private_key(key, allow_ec_key=allow_ec_key)
        self.cert = load_pem_x509_cert(cert, allow_ec_cert=allow_ec_key)
        self.chain = chain

    def validate(self):
        """
        Perform the individual validation steps and raise a
        `CustomCACertValidationError` in case a check fails.
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
            if not self.key_usage().key_cert_sign:
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

        if self.is_root():
            if self.chain is not None:
                raise CustomCACertValidationError(
                    'The custom CA certificate is a root CA certificate. '
                    'Therefore, no corresponding chain must be defined'
                    )
        else:
            self._validate_chain()

    def _validate_chain(self):
        """
        Validate given CA certificate chain. The goal is to detect various kinds
        of pitfalls early on and to provide insightful error messages in case
        a problem is detected.

        First, perform basic logical checks that do not involve signature
        verification:

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

        Subsequently, verify the chain cryptographically.
        """
        if self.chain is None:
            raise CustomCACertValidationError(
                'Certificate chain must be provided')

        endmarker = '-----END CERTIFICATE-----\n'
        tokens = self.chain.split(endmarker)
        chaincerts_pem = [t + endmarker for t in tokens if t.strip()]
        chaincerts = [load_pem_x509_cert(c) for c in chaincerts_pem]

        for chaincert in chaincerts:
            try:
                constraints = self.get_basic_constraints(chaincert)
            except x509.ExtensionNotFound:
                constraints = None

            if constraints is None or not constraints.ca:
                raise CustomCACertValidationError(
                    'The chain certificate with subject `{}` does not have the '
                    'basic constraint `CA` set to `true`'.format(
                        CertName(chaincert).subject))

        if self.cert.issuer != chaincerts[0].subject:
            raise CustomCACertValidationError(
                'The first chain certificate (subject `{}`) must be the issuer '
                'of the custom CA certificate'.format(
                    CertName(chaincerts[0]).subject))

        if chaincerts[-1].issuer != chaincerts[-1].subject:
            raise CustomCACertValidationError(
                'The last chain certificate (subject `{}`) must have equivalent '
                'subject and issuer (must be a root CA certificate)'.format(
                    CertName(chaincerts[-1]).subject))

        for childcert, parentcert in pairwise(chaincerts):
            if parentcert.subject != childcert.issuer:
                raise CustomCACertValidationError(
                    'The certificate chain is not coherent: the issuer of the '
                    'child certificate with the subject `{}` is not equivalent '
                    'to the subject `{}` of the parent certificate'.format(
                        CertName(childcert).subject,
                        CertName(parentcert).subject
                        )
                    )

        for childcert_pem, parentcert_pem in pairwise(chaincerts_pem):

            # Verify that the (alleged) parent certificate cryptographically
            # signed the (alleged) child certificate. Only after this
            # verification step it is sure if the inspected pair really is in a
            # proper parent/child relationship.

            with NamedTemporaryFile() as pfile, NamedTemporaryFile() as cfile:

                # The temporary files are automatically removed upon closing
                # them, i.e. upon leaving this context.
                pfile.write(parentcert_pem.encode('utf-8'))
                pfile.flush()
                cfile.write(childcert_pem.encode('utf-8'))
                cfile.flush()

                # Process executing the validation runs in a `alpine` docker
                # container that contains all dependencies built by `pkgpanda`
                # including the `openssl`. Unfortunately `openssl` package
                # depends on `glibc` which we don't build and expect to be
                # on a host machine. `alpine` linux doesn't come with `glibc`
                # and thus `openssl` built by `pkgpanda` cannot run in `alpine`
                # container.
                # https://github.com/dcos/dcos/blob/b261b8545da8b7e550b494cd353dc378b087096c/gen/build_deploy/bash/Dockerfile.in
                #
                # To override this problem we install `openssl` provided by
                # `alpine` package system. As this python file is executed
                # in context of `pkgpanda` build packages we have to remove
                # custom `bin` directory from path in order to launch `openssl`
                # binary that will work in `alpine` system.

                openssl_binary = 'openssl'
                process_env = os.environ.copy()

                if '/opt/mesosphere/bin' in os.environ['PATH']:
                    openssl_binary = '/usr/bin/openssl'
                    process_env.pop('LD_LIBRARY_PATH', None)

                # Props to https://security.stackexchange.com/q/118062/103960
                cmd = [
                    openssl_binary,
                    'verify',
                    '-CApath', '/dev/null',
                    '-partial_chain',
                    '-trusted', pfile.name,
                    cfile.name
                    ]

                p = subprocess.Popen(
                    cmd,
                    stderr=subprocess.STDOUT,
                    stdout=subprocess.PIPE,
                    env=process_env,
                    )
                stdout_bytes, _ = p.communicate()
                stdout = stdout_bytes.decode('utf-8', errors='backslashreplace')

            if 'OK' not in stdout:
                raise CustomCACertValidationError(
                    'The certificate chain is not coherent: the child '
                    'certificate with the subject `{}` is not signed by '
                    'the parent certificate with the subject `{}`. OpenSSL '
                    'output:\n{}'.format(
                        CertName(childcert).subject,
                        CertName(parentcert).subject,
                        stdout
                        ))

    def _validate_signature_hash_algorithm(self):
        """
        Validate certificate signature algorithm.

        Raises:
            CustomCACertValidationError
        """
        algo_oid = self.cert.signature_algorithm_oid
        if algo_oid not in self.SUPPORTED_SIGNATURE_ALGORITHM_OIDS:
            raise CustomCACertValidationError(
                'The custom CA certificate was signed with the `{hash_algo}` '
                'hash algorithm which is unsupported.'.format(
                    hash_algo=algo_oid._name,
                    ))

    def _validate_rsa_keys(self):
        """
        Validates that RSA key used for signing has min required size and
        that private key is matching certificate signing key.
        """
        self._validate_keys_size(self.RSA_KEY_MIN_SIZE)

        if not self.rsa_keys_matching():
            raise CustomCACertValidationError(
                "private key does not match public key")

    def _validate_ec_keys(self):
        """
        Validates that:

        - The key has min required size
        - EC key curve is supported
        - The private key is matching certificate signing key
        """
        self._validate_keys_size(self.EC_KEY_MIN_SIZE)

        if self.private_key.curve.__class__ not in self.SUPPORTED_EC_CURVES:
            raise CustomCACertValidationError(
                "private key was generated with unsupported curve `{}`".format(
                    self.private_key.curve.name)
                )

        if not self.ec_keys_matching():
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
        if get_key_size(self.private_key) < size:
            raise CustomCACertValidationError(
                'Private key size smaller than {} bits'.format(
                    size))

        if get_key_size(self.cert.public_key()) < size:
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

    def is_root(self):
        """
        Checks if certificate is a root ceritficate.

        Returns:
            Boolean
        """
        return self.cert.issuer == self.cert.subject

    def ec_keys_matching(self):
        """
        Verify that the private and the public key share the same modulus.

        Retruns:
            Boolean if private and public key are matching
        """
        pubkey_pubnumbers = self.cert.public_key().public_numbers()
        privkey_pubnumbers = self.private_key.private_numbers().public_numbers

        x_match = pubkey_pubnumbers.x == privkey_pubnumbers.x
        y_match = pubkey_pubnumbers.y == privkey_pubnumbers.y
        return x_match and y_match

    def rsa_keys_matching(self):
        """
        Verify that the private and the public key share the same modulus.

        Retrun:
            Boolean if private and public key are matching
        """
        pubkey_pubnumbers = self.cert.public_key().public_numbers()
        privkey_pubnumbers = self.private_key.private_numbers().public_numbers

        return pubkey_pubnumbers.n == privkey_pubnumbers.n


def get_key_size(key):
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


def load_pem_private_key(key_pem, allow_ec_key=True):
    """
    Load key from provided PEM/text representation.

    Expect one of:
        - RSA PKCS#8 PEM private key (RFC 3447, traditional OpenSSL format).
        - EC PKCS#8 PEM private key

    Args:
        key_pem (str): the PEM text representation of the data to verify.
        allow_ec_key (bool): True if EC key is supported.

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

    supported_keys = OrderedDict([(rsa.RSAPrivateKey, 'RSA')])
    if allow_ec_key:
        supported_keys[ec.EllipticCurvePrivateKey] = 'EC'

    if not isinstance(private_key, tuple(supported_keys.keys())):
        names = list(supported_keys.values())
        if len(names) > 1:
            names_str = ', '.join(names[:-1]) + ' or ' + names[-1]
        else:
            names_str = names[0]

        raise CustomCACertValidationError(
            'Unexpected private key type (not {})'.format(names_str))

    return private_key


def load_pem_x509_cert(cert_pem, allow_ec_cert=True):
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
        allow_ec_cert (bool): True if EC public key is supported.

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

    supported_keys = OrderedDict([(rsa.RSAPublicKey, 'RSA')])
    if allow_ec_cert:
        supported_keys[ec.EllipticCurvePublicKey] = 'EC'

    if not isinstance(public_key, tuple(supported_keys.keys())):
        names = list(supported_keys.values())
        if len(names) > 1:
            names_str = ', '.join(names[:-1]) + ' or ' + names[-1]
        else:
            names_str = names[0]

        raise CustomCACertValidationError(
            'Unexpected public key type (not {})'.format(names_str))

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
