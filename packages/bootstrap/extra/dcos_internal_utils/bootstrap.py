import argparse
import base64
import json
import logging
import os
import random
import shutil
import stat
import subprocess
import uuid


import kazoo.exceptions
from kazoo.client import KazooClient
from kazoo.retry import KazooRetry
from kazoo.security import ACL, ANYONE_ID_UNSAFE, Permissions
from kazoo.security import make_acl, make_digest_acl


import gen
from dcos_internal_utils import ca
from dcos_internal_utils import iam
from dcos_internal_utils import utils
from dcos_internal_utils import DCOS_CA_TRUST_BUNDLE_FILE_PATH


log = logging.getLogger(__name__)


ANYONE_CR = [ACL(Permissions.CREATE | Permissions.READ, ANYONE_ID_UNSAFE)]
ANYONE_READ = [ACL(Permissions.READ, ANYONE_ID_UNSAFE)]
ANYONE_ALL = [ACL(Permissions.ALL, ANYONE_ID_UNSAFE)]
LOCALHOST_ALL = [make_acl('ip', '127.0.0.1', all=True)]
ZOOKEEPER_ADDR = 'zk-1.zk:2181,zk-2.zk:2181,zk-3.zk:2181,zk-4.zk:2181,zk-5.zk:2181'

vault_config_template = """
disable_mlock = true

backend "zookeeper" {
  address = "%(zookeeper_addr)s"
  advertise_addr = "%(advertise_addr)s"
  path = "dcos/vault/default"
  %(znode_owner)s
  %(auth_info)s
}

listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = 1
}
"""


class Bootstrapper(object):
    def __init__(self, opts):
        self.opts = opts

        zk_creds = None
        if opts.zk_super_creds:
            log.info("Using super credentials for Zookeeper")
            zk_creds = opts.zk_super_creds
        elif opts.zk_agent_creds:
            log.info("Using agent credentials for Zookeeper")
            zk_creds = opts.zk_agent_creds

        conn_retry_policy = KazooRetry(max_tries=-1, delay=0.1, max_delay=0.1)
        cmd_retry_policy = KazooRetry(max_tries=3, delay=0.3, backoff=1, max_delay=1, ignore_expire=False)
        zk = KazooClient(hosts=opts.zk, connection_retry=conn_retry_policy, command_retry=cmd_retry_policy)
        zk.start()
        if zk_creds:
            zk.add_auth('digest', zk_creds)
        self.zk = zk

        self.iam_url = opts.iam_url
        self.ca_url = opts.ca_url
        self.secrets = {}

        self.agent_services = [
            'dcos_diagnostics_agent',
            'dcos_checks_agent',
            'dcos_adminrouter_agent',
            'dcos_agent',
            'dcos_mesos_agent',
            'dcos_mesos_agent_public',
            'dcos_metrics_agent',
            'dcos_minuteman_agent',
            'dcos_navstar_agent',
            'dcos_spartan_agent'
        ]

    def close(self):
        self.zk.stop()
        self.zk.close()

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        self.close()

    def cluster_id(self, path='/var/lib/dcos/cluster-id', readonly=False):
        dirpath = os.path.dirname(os.path.abspath(path))
        log.info('Opening {} for locking'.format(dirpath))
        with utils.Directory(dirpath) as d:
            log.info('Taking exclusive lock on {}'.format(dirpath))
            with d.lock():
                if readonly:
                    zkid = None
                else:
                    zkid = str(uuid.uuid4()).encode('ascii')
                zkid = self._consensus('/cluster-id', zkid, ANYONE_READ)
                zkid = zkid.decode('ascii')

                if os.path.exists(path):
                    fileid = utils.read_file_line(path)
                    if fileid == zkid:
                        log.info('Cluster ID in ZooKeeper and file are the same: {}'.format(zkid))
                        return zkid

                log.info('Writing cluster ID from ZK to {} via rename'.format(path))

                tmppath = path + '.tmp'
                with open(tmppath, 'w') as f:
                    f.write(zkid + '\n')
                os.rename(tmppath, path)

                log.info('Wrote cluster ID to {}'.format(path))

                return zkid

    def init_zk_acls(self):
        if not self.opts.config['zk_acls_enabled']:
            return

        paths = {
            '/': ANYONE_CR + LOCALHOST_ALL,
            '/cosmos': ANYONE_ALL,
            '/dcos': ANYONE_READ,
            '/dcos/vault': ANYONE_READ,
            '/zookeeper': ANYONE_READ,
            '/zookeeper/quotas': ANYONE_READ,
        }
        for path in sorted(paths):
            log.info('Initializing ACLs for znode {}'.format(path))
            acl = paths[path]
            self.ensure_zk_path(path, acl=acl)

    def _create_secrets(self, basepath, secrets, acl):
        for k, v in secrets.items():
            leaf = True
            for vv in v.values():
                if isinstance(vv, dict):
                    leaf = False
                    break

            if not leaf:
                path = '/'.join([basepath, k])
                self._create_secrets(path, v, acl)
                continue

            self.ensure_zk_path(basepath, acl=acl)

            path = '/'.join([basepath, k])
            js = json.dumps(v, ensure_ascii=True).encode('ascii')
            js = self._consensus(path, js, acl)
            secrets[k] = json.loads(js.decode('ascii'))

            # set ACLs again in case znode already existed but with outdated ACLs
            if acl:
                self.zk.set_acls(path, acl)

        return secrets

    def write_signing_CA_key(self, user):
        """
        Write PEM-encoded private key corresponding to the "signing CA
        certificate" to /run/dcos/pki/CA/private/signing-ca.key. Set file owner to
        `user` and set the file access permissions down to 0o600.

        Args:
            user (str):
                Set the owner of the file to this system/unix user name.
        """
        # This file must not be read by any component besides the DC/OS CA.
        path = '/run/dcos/pki/CA/private/signing-ca.key'
        key = self.secrets['CA']['RootCA']['key'].encode('utf-8')
        log.info('Writing signing CA cert private key to {}'.format(path))
        _write_file_bytes(path, key, 0o600)
        shutil.chown(path, user=user)

    def write_signing_CA_certificate(self, user):
        """
        Write the PEM-encoded "signing CA certificate" to a file located at
        '/run/dcos/pki/CA/certs/signing-ca.crt'. Set file owner to `user` and
        set the file access permissions to 0o600: while certificates are
        non-sensitive data in general, this file is intended to be accessed
        exclusively by the DC/OS CA (cfssl) process. The signing CA certificate
        is either a custom CA certificate (root or intermediate) or an
        auto-generated root CA certificate.

        Args:
            user (str):
                Set the owner of the file to this system/unix user name.
        """
        # This file should not be read by any component besides the DC/OS CA.
        path = '/run/dcos/pki/CA/certs/signing-ca.crt'
        certbytes = self.secrets['CA']['RootCA']['certificate'].encode('utf-8')
        log.info('Writing signing CA cert to {}'.format(path))
        _write_file_bytes(path, certbytes, 0o644)
        shutil.chown(path, user=user)

    def write_CA_certificate_chain(self, path='/run/dcos/pki/CA/ca-chain.crt'):
        """
        Write the CA certificate chain (comprised of exclusively intermediate
        CA certificates) to a file.
        """
        chainbytes = None

        if 'CA' in self.secrets:
            chainbytes = self.secrets['CA']['RootCA']['chain'].encode('utf-8')

        # Note(JP): Is this the fallback for agent nodes (where
        # `create_master_secrets()` has not been called?
        chainbytes = self._consensus('/dcos/CAChain', chainbytes, ANYONE_READ)
        log.info('Writing CA cert chain (of intermediate certs) to {}'.format(path))

        _write_file_bytes(path, chainbytes, 0o644)

    def write_CA_certificate_chain_with_root_cert(
            self, path='/run/dcos/pki/CA/ca-chain-inclroot.crt'):
        """
        Like `write_CA_certificate_chain()`, but add the root CA certificate.
        """
        chainbytes = None

        if 'CA' in self.secrets:
            chain = (
                self.secrets['CA']['RootCA']['chain'] +
                self.secrets['CA']['RootCA']['root']
                )
            chainbytes = chain.encode('utf-8')

        chainbytes = self._consensus(
            '/dcos/CAChainInclRoot', chainbytes, ANYONE_READ)

        log.info('Writing CA cert chain (including root) to {}'.format(path))
        _write_file_bytes(path, chainbytes, 0o644)

    def write_CA_trust_bundle(self):
        """
        Write the DC/OS CA trust bundle file. It is intended to contain the
        trust anchor(s) to be used for certificate verification by various
        DC/OS-internal components. That is, for security reasons it is important
        that this bundle contains the smallest set of trust anchors that is
        conceptually required.

        The file is written to `DCOS_CA_TRUST_BUNDLE_FILE_PATH`, where other
        DC/OS-internal components but also readers of the public-facing docs
        expect the DC/OS CA trust bundle file to exist.

        Note(JP): For now, the DC/OS CA trust bundle file only contains a single
        item; the root CA certificate corresponding to the DC/OS Certificate
        Authority. In the future we might allow operators to inject their own
        trust anchors (via the DC/OS configuration), in which case this method
        here must be amended correspondingly.
        """

        if 'CA' in self.secrets:
            certbytes_proposal = self.secrets['CA']['RootCA']['root'].encode('utf-8')
        else:
            # On agents the `'CA'` key does not exist in `self.secrets`. A
            # proposed value of `None` in the consensus procedure invoked below
            # reads out the result of the consensus procedure between the master
            # nodes.
            certbytes_proposal = None

        certbytes = self._consensus('/dcos/RootCA', certbytes_proposal, ANYONE_READ)

        log.info(
            'Writing CA trust bundle (root CA certificate) to %s',
            DCOS_CA_TRUST_BUNDLE_FILE_PATH)

        _write_file_bytes(DCOS_CA_TRUST_BUNDLE_FILE_PATH, certbytes, 0o644)

    def write_CA_trust_bundle_for_libcurl(self):
        """
        Write the DC/OS CA trust bundle (currently expected to contain just
        a single root CA certificate) to a known location that is picked up
        by DC/OS' curl/libcurl.

        Note(JP): In the moment we allow customization of the DC/OS CA trust
        bundle (e.g. via dcos-config.yaml) this routine needs to be amended.

        /var/lib/dcos/pki/tls/certs is the directory of trusted CA certificates
        that curl/libcurl is configured to pick up. Certificates are looked up
        by subject hash which is why modification of directory contents usually
        requires a subsequent OpenSSL certificate directory rehash procedure:
        https://github.com/openssl/openssl/blob/OpenSSL_1_0_2-stable/tools/c_rehash.in#L150

        The curl/libcurl trusted certificates directory path is set via:
        https://github.com/dcos/dcos/blob/4f5f15e363025327139b313737ab4d7fbb0b389d/packages/curl/build#L43-L44
        """
        curl_trusted_certs_dir_path = '/var/lib/dcos/pki/tls/certs'

        # Create directory if not yet existing. Allow anyone to list / traverse
        # directory, but only allow root to write new trust anchors.
        os.makedirs(curl_trusted_certs_dir_path, exist_ok=True)
        os.chmod(curl_trusted_certs_dir_path, 0o755)

        # Make sure that the DC/OS CA trust bundle file is written to the file
        # system (to `DCOS_CA_TRUST_BUNDLE_FILE_PATH`).
        self.write_CA_trust_bundle()

        # Copy that file to curl's trust bundle directory, with a new filename.
        # Set file permissions to 0o644 (same as for the original file).
        certfilepath = os.path.join(
            curl_trusted_certs_dir_path, 'dcos-root-ca-cert.crt')
        shutil.copy2(DCOS_CA_TRUST_BUNDLE_FILE_PATH, certfilepath)
        os.chmod(certfilepath, 0o644)

        # Hash the certificate subject.
        p = subprocess.Popen(
            ['openssl', 'x509', '-hash', '-noout', '-in', certfilepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            )
        stdout_bytes, stderr_bytes = p.communicate()

        if p.returncode != 0:
            log.error('OpenSSL error: `{}`'.format(stderr_bytes.decode('utf-8', errors='backslashreplace')))
            raise Exception('Failed to hash certificate subject')

        # Create a symlink with the subject hash in its name (following OpenSSL
        # convention, for it to discover the file knowing the subject).
        cert_hash = stdout_bytes.decode('ascii').strip() + '.0'
        cert_hash_path = os.path.join(curl_trusted_certs_dir_path, cert_hash)
        if not os.path.islink(cert_hash_path):
            os.symlink(certfilepath, cert_hash_path)
            os.chmod(cert_hash_path, 0o644)

    def get_CA_private_key_type(self):
        """
        Retrieves type of private key used for CA certificate.

        Returns:
            Class representing key type:
            - rsa.RSAPrivateKey
            - ec.EllipticCurvePrivateKey
        """
        private_key_type_name = None

        if 'CA' in self.secrets:
            private_key = utils.load_pem_private_key(
                self.secrets['CA']['RootCA']['key'])
            private_key_type_name = utils.get_private_key_type_name_from_object(
                private_key).encode('utf-8')

        private_key_type_name = self._consensus(
            '/dcos/CACertKeyType', private_key_type_name, ANYONE_READ)

        return utils.get_private_key_type_from_name(
            private_key_type_name.decode('utf-8'))

    def create_master_secrets(self):
        creds = self.opts.zk_master_creds

        if creds:
            user, password = creds.split(':', 1)
            acl = [make_digest_acl(user, password, read=True)]
            log.info('Creating master secrets with user {}'.format(user))
        else:
            acl = None

        zk_creds = {}
        if self.opts.config['zk_acls_enabled']:
            service_account_zk_creds = [
                'dcos_bouncer',
                'dcos_ca',
                'dcos_cockroach',
                'dcos_cosmos',
                'dcos_marathon',
                'dcos_mesos_master',
                'dcos_metronome',
                'dcos_secrets',
                'dcos_vault_default'
            ]
            for account in service_account_zk_creds:
                zk_creds[account] = {
                    'scheme': 'digest',
                    'username': account,
                    'password': utils.random_string(64),
                }

        master_service_accounts = [
            'dcos_diagnostics_master',
            'dcos_checks_master',
            'dcos_adminrouter',
            'dcos_backup_master',
            'dcos_history_service',
            'dcos_marathon',
            'dcos_mesos_dns',
            'dcos_mesos_master',
            'dcos_metrics_master',
            'dcos_metronome',
            'dcos_minuteman_master',
            'dcos_navstar_master',
            'dcos_networking_api_master',
            'dcos_signal_service',
            'dcos_spartan_master'
        ]

        if self.opts.config['security'] == 'permissive':
            master_service_accounts.append('dcos_anonymous')

        service_account_creds = {}
        for account in master_service_accounts:
            service_account_creds[account] = {
                'scheme': 'RS256',
                'uid': account,
                'private_key': utils.generate_RSA_keypair(2048)[0],
            }

        self.upgrade_19_to_110_secret_root_ca(acl)

        ca_crt, ca_key, ca_chain, ca_root = self._load_or_generate_ca_cert(
            self.cluster_id())
        ca_certs = {
            'RootCA': {
                'key': ca_key,
                'certificate': ca_crt,
                'chain': ca_chain,
                'root': ca_root
            }
        }

        private_keys = {
            'dcos_bouncer': utils.generate_RSA_keypair(2048)[0]
        }

        secrets = {
            'zk': zk_creds,
            'services': service_account_creds,
            'CA': ca_certs,
            'private_keys': private_keys
        }

        path = '/dcos/master/secrets'
        secrets = self._create_secrets(path, secrets, acl)
        utils.dict_merge(self.secrets, secrets)
        return secrets

    def _load_or_generate_ca_cert(self, cluster_id):
        """
        Get data for 'the signing CA certificate': load custom CA certificate or
        generate new root CA certificate.

        The 'custom CA certificate' is a root or intermediate CA certificate
        that is intended to be used by the DC/OS CA as 'the signing CA
        certificate', i.e. for signing (issuing) the individual component
        (end-entity) certificates.

        If a custom CA certificate was provided the corresponding configuration
        data is loaded from the file located at `/opt/mesosphere/etc/ca.json`.
        The file is expected to contain a JSON document specifying the keys
        `ca_certificate` and `ca_certificate_chain`. If the certificate encoded
        by `ca_certificate` is not a root CA certificate, `ca_certificate_chain`
        is expected to contain all CA certificates comprising the complete
        sequence starting precisely with the CA certificate that was used to
        sign the certificate in `ca_certificate` and ending with a root CA
        certificate (where issuer and subject are the same entity), yielding a
        gapless certification path (the order is significant). The private key
        corresponding to the custom CA certificate is loaded from the file
        located at `/var/lib/dcos/pki/tls/CA/private/custom_ca.key`.

        If no custom CA certitificate was not configured then generate a
        globally unique root CA certificate is created.

        Returns:
            ca_crt (str): The signing CA certificate (PEM-encoded). Intended to
                be used for signing component (end-entity) certificates. A newly
                generated globally unique root CA certificate or the custom CA
                certificate.

            ca_key (str): Private key (PEM-encoded) corresponding to the
                certificate encoded in `ca_crt`.

            ca_chain (str): If the custom CA certificate is an intermediate CA
                certificate then this string includes the custom CA certificate
                and all intermediate CA certificates in the hierarchy between
                the custom CA certificate and the root CA certificate
                (PEM-encoded). `ca_chain` is an empty string when the custom CA
                certificate is a root CA certificate or when no
                custom CA certificate has been provided.

            ca_root (str): root CA certificate (PEM-encoded). When generating a
                new globally unique root CA certificate or when the custom CA
                certificate `ca_crt` is a root CA certificate then this value is
                identical to `ca_crt`.
        """

        # Filesystem paths where custom CA parts are expected to be found.
        custom_ca_cert_conf_path = '/opt/mesosphere/etc/ca.json'
        custom_ca_priv_key_path = '/var/lib/dcos/pki/tls/CA/private/custom_ca.key'

        # Handle the case when a custom CA certificate was provided.
        if os.path.isfile(custom_ca_cert_conf_path):

            with open(custom_ca_cert_conf_path, 'rb') as f:
                custom_ca_cert_config = json.loads(
                    f.read().decode('utf-8'))

            # Use the custom CA certificate as 'the signing CA certificate'.
            ca_crt = custom_ca_cert_config['ca_certificate']

            # If the `'ca_certificate_chain'` key has set an empty string value
            # it precisely means that the custom CA certificate is a root CA
            # certificate.
            if custom_ca_cert_config['ca_certificate_chain'] == '':
                ca_root = custom_ca_cert_config['ca_certificate']
                ca_chain = ''

            else:
                # Make it so that `ca_chain` contains all CA certificates
                # (including the signing CA certificate) but not the root CA
                # certificate.
                endmarker = '-----END CERTIFICATE-----\n'
                all_ca_certs = (
                    ca_crt +
                    custom_ca_cert_config['ca_certificate_chain']
                    ).split(endmarker)
                all_ca_certs = [c + endmarker for c in all_ca_certs if c.strip()]
                ca_root = all_ca_certs[-1]
                ca_chain = ''.join(all_ca_certs[:-1])

            # Expect private key file at pre-defined location, read key.
            with open(custom_ca_priv_key_path, 'rb') as custom_ca_key_file:
                try:
                    ca_key = custom_ca_key_file.read().decode('utf-8')
                except OSError as err:
                    raise Exception(
                        'Failed to read custom CA certificate private key '
                        'from file `%s`. Error: %s' % (
                            custom_ca_priv_key_path, err)
                        )

        # Handle the case where no custom CA certificate data was provided:
        # generate a new globally unique root CA certificate plus its
        # corresponding private key.
        else:
            ca_key, ca_crt = utils.generate_CA_key_certificate(
                valid_days=3650,
                cn_suffix=cluster_id,
                )
            ca_root = ca_crt
            ca_chain = ''

        return ca_crt, ca_key, ca_chain, ca_root

    def create_agent_secrets(self, digest):
        if self.opts.config['zk_acls_enabled']:
            # kazoo.exceptions.MarshallingError here probably means
            # that digest is None
            acl = [make_acl('digest', digest, read=True)]
        else:
            acl = None

        service_account_creds = {}
        for account in self.agent_services:
            service_account_creds[account] = {
                'scheme': 'RS256',
                'uid': account,
                'private_key': utils.generate_RSA_keypair(2048)[0]}

        secrets = {
            'services': service_account_creds,
        }

        path = '/dcos/agent/secrets'
        secrets = self._create_secrets(path, secrets, acl)
        utils.dict_merge(self.secrets, secrets)
        return secrets

    def read_agent_secrets(self):
        self.secrets['services'] = {}

        for svc in self.agent_services:
            path = '/dcos/agent/secrets/services/' + svc
            js = self._consensus(path, None)
            self.secrets['services'][svc] = json.loads(js.decode('ascii'))

        return self.secrets

    def read_dcos_diagnostics_agent_secrets(self):
        path = '/dcos/agent/secrets/services/dcos_diagnostics_agent'
        js = self._consensus(path, None)
        self.secrets['services'] = {
            'dcos_diagnostics_agent': json.loads(js.decode('ascii'))
        }
        return self.secrets

    def write_service_account_credentials(self, uid, filename):
        creds = self.secrets['services'][uid].copy()
        creds['login_endpoint'] = self.iam_url + '/acs/api/v1/auth/login'
        creds = bytes(json.dumps(creds), 'ascii')

        log.info('Writing {} service account credentials to {}'.format(uid, filename))
        # credentials file that service can read, but not overwrite
        _write_file_bytes(filename, creds, 0o400)

    def write_private_key(self, name, filename):
        private_key = self.secrets['private_keys'][name]
        private_key = bytes(private_key, 'ascii')
        log.info('Writing {} private key to {}'.format(name, filename))
        # private key that service can read, but not overwrite
        _write_file_bytes(filename, private_key, 0o400)

    def create_service_account(self, uid, superuser, zk_secret=True):
        if zk_secret:
            account = self.secrets['services'][uid]
        else:
            account = {
                'scheme': 'RS256',
                'uid': uid,
                'private_key': utils.generate_RSA_keypair(2048)[0]
            }
        assert uid == account['uid']
        assert account['scheme'] == 'RS256'

        log.info('Creating service account {}'.format(uid))

        private_key = utils.load_pem_private_key(account['private_key'])
        pubkey_pem = utils.public_key_pem(private_key)
        account['public_key'] = pubkey_pem

        iamcli = iam.IAMClient(self.iam_url)
        iamcli.create_service_account(uid, public_key=pubkey_pem, exist_ok=True)

        # TODO fine-grained permissions for all service accounts
        if superuser:
            iamcli.add_user_to_group(uid, 'superusers')

        return account

    def create_agent_service_accounts(self):
        for svc in self.agent_services:
            self.create_service_account(svc, superuser=True)

    def _consensus(self, path, value, acl=None):
        if value is not None:
            log.info('Reaching consensus about znode {}'.format(path))
            try:
                self.zk.create(path, value, acl=acl)
                log.info('Consensus znode {} created'.format(path))
            except kazoo.exceptions.NodeExistsError:
                log.info('Consensus znode {} already exists'.format(path))
                pass

        self.zk.sync(path)
        return self.zk.get(path)[0]

    def make_service_acl(self, service, **kwargs):
        u = self.secrets['zk'][service]['username']
        p = self.secrets['zk'][service]['password']
        return make_digest_acl(u, p, **kwargs)

    def ensure_zk_path(self, path, acl=None):
        log.info('ensure_zk_path({}, {})'.format(path, acl))
        self.zk.ensure_path(path, acl=acl)
        if acl:
            self.zk.set_acls(path, acl)

    def mesos_zk_acls(self):
        acl = None
        if self.opts.config['zk_acls_enabled']:
            acl = ANYONE_READ + LOCALHOST_ALL + [self.make_service_acl('dcos_mesos_master', all=True)]
        self.ensure_zk_path('/mesos', acl=acl)

    def marathon_zk_acls(self):
        acl = None
        if self.opts.config['zk_acls_enabled']:
            acl = ANYONE_READ + LOCALHOST_ALL + [self.make_service_acl('dcos_marathon', all=True)]
        self.ensure_zk_path('/marathon', acl=acl)

    def marathon_iam_permissions(self):
        if self.opts.config['security'] == 'permissive':
            permissive_rid_action_pairs = [
                ('dcos:mesos:master:framework', 'create'),
                ('dcos:mesos:master:reservation', 'create'),
                ('dcos:mesos:master:reservation', 'delete'),
                ('dcos:mesos:master:task', 'create'),
                ('dcos:mesos:master:volume', 'create'),
                ('dcos:mesos:master:volume', 'delete'),
                ('dcos:mesos:agent:task', 'create')
            ]

            iamcli = iam.IAMClient(self.iam_url)
            iamcli.grant_permissions(permissive_rid_action_pairs, 'dcos_marathon')

        elif self.opts.config['security'] == 'strict':
            # Can only register with 'slave_public' role,
            # only create volumes/reservations in that role,
            # only destroy volumes/reservations created by 'dcos_marathon',
            # only run tasks as linux user 'nobody',
            # but can create apps in any folder/namespace.
            strict_rid_action_pairs = [
                ('dcos:mesos:master:framework:role:slave_public', 'create'),
                ('dcos:mesos:master:reservation:role:slave_public', 'create'),
                ('dcos:mesos:master:reservation:principal:dcos_marathon', 'delete'),
                ('dcos:mesos:master:task:user:nobody', 'create'),
                ('dcos:mesos:master:task:app_id', 'create'),
                ('dcos:mesos:master:volume:principal:dcos_marathon', 'delete'),
                ('dcos:mesos:master:volume:role:slave_public', 'create'),
                ('dcos:mesos:agent:task:user:nobody', 'create'),
                ('dcos:mesos:agent:task:app_id', 'create')
            ]

            iamcli = iam.IAMClient(self.iam_url)
            iamcli.grant_permissions(strict_rid_action_pairs, 'dcos_marathon')

    def metronome_zk_acls(self):
        acl = None
        if self.opts.config['zk_acls_enabled']:
            acl = ANYONE_READ + LOCALHOST_ALL + [self.make_service_acl('dcos_metronome', all=True)]
        self.ensure_zk_path('/metronome', acl=acl)

    def metronome_iam_permissions(self):
        if self.opts.config['security'] == 'permissive':
            permissive_rid_action_pairs = [
                ('dcos:mesos:master:framework', 'create'),
                ('dcos:mesos:master:task', 'create'),
                ('dcos:mesos:agent:task', 'create')
            ]

            iamcli = iam.IAMClient(self.iam_url)
            iamcli.grant_permissions(permissive_rid_action_pairs, 'dcos_metronome')

        elif self.opts.config['security'] == 'strict':
            # Can only register with '*' role,
            # only run tasks as linux user 'nobody',
            # but can create jobs in any folder/namespace.
            strict_rid_action_pairs = [
                ('dcos:mesos:master:framework:role:*', 'create'),
                ('dcos:mesos:master:task:app_id', 'create'),
                ('dcos:mesos:master:task:user:nobody', 'create'),
                ('dcos:mesos:agent:task:user:nobody', 'create'),
                ('dcos:mesos:agent:task:app_id', 'create')
            ]

            iamcli = iam.IAMClient(self.iam_url)
            iamcli.grant_permissions(strict_rid_action_pairs, 'dcos_metronome')

    def cosmos_acls(self):
        acl = None
        if self.opts.config['zk_acls_enabled']:
            acl = ANYONE_READ + LOCALHOST_ALL + [self.make_service_acl('dcos_cosmos', all=True)]
        self.ensure_zk_path('/cosmos', acl=acl)

    def bouncer_acls(self):
        acl = None
        if self.opts.config['zk_acls_enabled']:
            acl = LOCALHOST_ALL + [self.make_service_acl('dcos_bouncer', all=True)]
        self.ensure_zk_path('/bouncer', acl=acl)

    def cockroach_acls(self):
        """Create ZNode's and Zookeeper ACLs for the CockroachDB component."""
        acl = None
        if self.opts.config['zk_acls_enabled']:
            acl = LOCALHOST_ALL + [self.make_service_acl('dcos_cockroach', all=True)]
        self.ensure_zk_path('/cockroach', acl=acl)
        self.ensure_zk_path('/cockroach/nodes', acl=acl)
        self.ensure_zk_path('/cockroach/locking', acl=acl)

    def dcos_ca_acls(self):
        acl = None
        if self.opts.config['zk_acls_enabled']:
            acl = LOCALHOST_ALL + [self.make_service_acl('dcos_ca', all=True)]
        self.ensure_zk_path('/dcos/ca', acl=acl)

    def dcos_secrets_acls(self):
        acl = None
        if self.opts.config['zk_acls_enabled']:
            acl = LOCALHOST_ALL + [self.make_service_acl('dcos_secrets', all=True)]
        self.ensure_zk_path('/dcos/secrets', acl=acl)

    def dcos_vault_default_acls(self):
        acl = None
        if self.opts.config['zk_acls_enabled']:
            acl = LOCALHOST_ALL + [self.make_service_acl('dcos_vault_default', all=True)]
        self.ensure_zk_path('/dcos/vault/default', acl=acl)

    def write_dcos_ca_creds(self, src, dst):
        with open(src, 'rb') as fh:
            ca_conf = json.loads(fh.read().decode('utf-8'))
        assert 'data_source' in ca_conf
        assert ca_conf['data_source'][:5] == 'file:'

        if self.opts.config['zk_acls_enabled']:
            zk_creds = self.secrets['zk']['dcos_ca']
            ca_conf['data_source'] = 'file:{}:{}@{}'.format(
                zk_creds['username'],
                zk_creds['password'],
                ca_conf['data_source'][5:]
            )

        blob = json.dumps(ca_conf, sort_keys=True, indent=True, ensure_ascii=False).encode('utf-8')
        _write_file_bytes(dst, blob, 0o400)
        shutil.chown(dst, user=self.opts.dcos_ca_user)

    def write_bouncer_env(self, filename):
        env = 'SQLALCHEMY_DB_URL=cockroachdb://root@{my_ip}:26257/iam\n'.format(
            my_ip=utils.detect_ip())
        if self.opts.config['zk_acls_enabled']:
            zk_creds = self.secrets['zk']['dcos_bouncer']
            env += 'DATASTORE_ZK_USER={username}\nDATASTORE_ZK_SECRET={password}\n'.format(
                username=zk_creds['username'],
                password=zk_creds['password'])

        env = bytes(env, 'ascii')

        log.info('Writing Bouncer environment and credentials to {}'.format(filename))
        _write_file_bytes(filename, env, 0o600)

    def write_cockroach_env(self, filename):
        """Write CockroachDB's Zookeeper credentials to a dedicated environment file."""
        if not self.opts.config['zk_acls_enabled']:
            return

        zk_creds = self.secrets['zk']['dcos_cockroach']

        env = 'DATASTORE_ZK_USER={username}\nDATASTORE_ZK_SECRET={password}\n'
        env = bytes(env.format_map(zk_creds), 'ascii')

        log.info('Writing CockroachDB ZK credentials to {}'.format(filename))
        _write_file_bytes(filename, env, 0o600)

    def write_vault_config(self, filename):
        if self.opts.config['zk_acls_enabled']:
            zk_creds = self.secrets['zk']['dcos_vault_default']
            user = zk_creds['username']
            pw = zk_creds['password']
            acl = make_digest_acl(user, pw, all=True)
            znode_owner = 'znode_owner = "digest:{}"'.format(acl.id.id)
            auth_info = 'auth_info = "digest:{}:{}"'.format(user, pw)
        else:
            znode_owner = ''
            auth_info = ''

        if self.opts.config['ssl_enabled']:
            scheme = 'https://'
        else:
            scheme = 'http://'

        ip = utils.detect_ip()
        advertise_addr = scheme + ip + '/vault/default'

        params = {
            'znode_owner': znode_owner,
            'auth_info': auth_info,
            'advertise_addr': advertise_addr,
            'zookeeper_addr': ZOOKEEPER_ADDR
        }
        cfg = vault_config_template % params
        cfg = cfg.strip() + '\n'
        cfg = cfg.encode('ascii')

        log.info('Writing Vault config to {}'.format(filename))
        _write_file_bytes(filename, cfg, 0o400)
        shutil.chown(filename, user=self.opts.dcos_vault_user)

    def write_secrets_env(self, filename):
        if not self.opts.config['zk_acls_enabled']:
            return

        zk_creds = self.secrets['zk']['dcos_secrets']
        user = zk_creds['username']
        pw = zk_creds['password']

        acl = make_digest_acl(user, pw, all=True)

        env = 'SECRETS_AUTH_INFO=digest:{}:{}\nSECRETS_ZNODE_OWNER=digest:{}\n'
        env = env.format(user, pw, acl.id.id)
        env = bytes(env, 'ascii')

        log.info('Writing Secrets ZK credentials to {}'.format(filename))
        _write_file_bytes(filename, env, 0o600)

    def write_executor_secret_key(self, path):
        if os.path.isfile(path):
            return

        if os.path.exists(path):
            raise Exception('Mesos executor secret key path "{}" was found, ' +
                            'but is not a regular file'.format(path))

        key = utils.generate_executor_secret_key()
        _write_file_bytes(path, key, 0o600)

    def write_mesos_master_env(self, filename):
        if not self.opts.config['zk_acls_enabled']:
            return

        zk_creds = self.secrets['zk']['dcos_mesos_master']
        zk_creds['zookeeper_addr'] = ZOOKEEPER_ADDR

        env = 'MESOS_ZK=zk://{username}:{password}@{zookeeper_addr}/mesos\n'
        env = env.format_map(zk_creds)
        env = bytes(env, 'ascii')

        log.info('Writing Mesos Master ZK credentials to {}'.format(filename))
        _write_file_bytes(filename, env, 0o600)

    def write_cosmos_env(self, env_fn):
        if not self.opts.config['zk_acls_enabled']:
            return

        zk_creds = self.secrets['zk']['dcos_cosmos']
        env = 'ZOOKEEPER_USER={username}\nZOOKEEPER_SECRET={password}\n'
        env = env.format_map(zk_creds)
        env = bytes(env, 'ascii')

        log.info('Writing Cosmos environment to {}'.format(env_fn))
        # environment file is owned by root because systemd reads it
        _write_file_bytes(env_fn, env, 0o600)

    def write_metronome_env(self, key_fn, crt_fn, ca_fn, env_fn):
        pfx_fn = os.path.splitext(key_fn)[0] + '.pfx'
        jks_fn = os.path.splitext(key_fn)[0] + '.jks'

        try:
            os.remove(jks_fn)
        except OSError:
            pass

        zk_creds = self.secrets['zk']['dcos_metronome']
        zk_creds['zookeeper_addr'] = ZOOKEEPER_ADDR
        env1 = 'METRONOME_ZK_URL=zk://{username}:{password}@{zookeeper_addr}/metronome\n'
        env1 = env1.format_map(zk_creds)

        keystore_password = utils.random_string(64)
        env2 = 'METRONOME_PLAY_SERVER_HTTPS_KEYSTORE_PASSWORD={keystore_password}\n'
        env2 = env2.format(keystore_password=keystore_password)

        env = bytes(env1 + env2, 'ascii')

        log.info('Writing Metronome environment to {}'.format(env_fn))
        _write_file_bytes(env_fn, env, 0o600)

        service_name = 'metronome'

        cmd = [
            '/opt/mesosphere/bin/openssl',
            'pkcs12',
            '-export',
            '-out', pfx_fn,
            '-inkey', key_fn,
            '-in', crt_fn,
            '-chain',
            '-CAfile', ca_fn,
            '-name', service_name,
            '-password', 'env:SSL_KEYSTORE_PASSWORD',
        ]
        log.info('Converting PEM to PKCS12: {}'.format(' '.join(cmd)))
        env = {
            'SSL_KEYSTORE_PASSWORD': keystore_password,
            'RANDFILE': '/tmp/.rnd',
        }

        subprocess.check_call(cmd, preexec_fn=_set_umask, env=env)

        os.chmod(pfx_fn, stat.S_IRUSR | stat.S_IWUSR)

        cmd = [
            '/opt/mesosphere/bin/keytool',
            '-importkeystore',
            '-noprompt',
            '-srcalias', service_name,
            '-srckeystore', pfx_fn,
            '-srcstoretype', 'PKCS12',
            '-destkeystore', jks_fn,
            '-srcstorepass', keystore_password,
            '-deststorepass', keystore_password,
        ]
        log.info('Importing PKCS12 into Java KeyStore: {}'.format(' '.join(cmd)))
        proc = subprocess.Popen(cmd, shell=False, preexec_fn=_set_umask)
        if proc.wait() != 0:
            raise Exception('keytool failed')

        os.chmod(jks_fn, stat.S_IRUSR | stat.S_IWUSR)
        os.remove(pfx_fn)

    def write_marathon_zk_env(self, env_fn):
        zk_creds = self.secrets['zk']['dcos_marathon']
        zk_creds['zookeeper_addr'] = ZOOKEEPER_ADDR
        env = 'MARATHON_ZK=zk://{username}:{password}@{zookeeper_addr}/marathon\n'
        env = env.format_map(zk_creds)
        env = bytes(env, 'ascii')

        log.info('Writing Marathon ZK environment to {}'.format(env_fn))
        _write_file_bytes(env_fn, env, 0o600)

    def write_marathon_tls_env(self, key_fn, crt_fn, ca_fn, env_fn):
        pfx_fn = os.path.splitext(key_fn)[0] + '.pfx'
        jks_fn = os.path.splitext(key_fn)[0] + '.jks'

        try:
            os.remove(jks_fn)
        except OSError:
            pass

        password = utils.random_string(256)
        env = 'SSL_KEYSTORE_PASSWORD={}\n'.format(password)
        env = bytes(env, 'ascii')

        _write_file_bytes(env_fn, env, 0o600)

        service_name = 'marathon'

        cmd = [
            '/opt/mesosphere/bin/openssl',
            'pkcs12',
            '-export',
            '-out', pfx_fn,
            '-inkey', key_fn,
            '-in', crt_fn,
            '-chain',
            '-CAfile', ca_fn,
            '-name', service_name,
            '-password', 'env:SSL_KEYSTORE_PASSWORD',
        ]
        log.info('Converting PEM to PKCS12: {}'.format(' '.join(cmd)))
        env = {
            'SSL_KEYSTORE_PASSWORD': password,
            'RANDFILE': '/tmp/.rnd',
        }
        proc = subprocess.Popen(cmd, shell=False, preexec_fn=_set_umask, env=env)
        if proc.wait() != 0:
            raise Exception('openssl failed')

        keytool = shutil.which('keytool')
        if not keytool:
            raise Exception('keytool not found')

        # TODO this will temporarily expose the password during bootstrap
        cmd = [
            keytool,
            '-importkeystore',
            '-noprompt',
            '-srcalias', service_name,
            '-srckeystore', pfx_fn,
            '-srcstoretype', 'PKCS12',
            '-destkeystore', jks_fn,
            '-srcstorepass', password,
            '-deststorepass', password,
        ]
        log.info('Importing PKCS12 into Java KeyStore: {}'.format(' '.join(cmd)))
        subprocess.check_call(cmd, preexec_fn=_set_umask)
        os.remove(pfx_fn)

    def write_java_truststore_with_dcos_ca_bundle(self):
        """
        Write Java TrustStore to file located at
        `/run/dcos/pki/CA/certs/cacerts.jks` which is expected by e.g. Marathon,
        Cosmos, Metronome, but also by Admin Router for exposing the
        `/ca/cacerts.jks` HTTP endpoint).

        Note(JP): We copy Java's default trust database into the new TrustStore,
        but it's unclear to me why we do so. I am not sure if we actually want
        Marathon and Metronome to trust "the Internet". In addition, we copy the
        trust anchors (certificates) from the DC/OS CA bundle file located at
        `DCOS_CA_TRUST_BUNDLE_FILE_PATH` which is the canonical DC/OS CA bundle
        location.
        """
        ts_filepath = '/run/dcos/pki/CA/certs/cacerts.jks'
        ca_bundle_filepath = DCOS_CA_TRUST_BUNDLE_FILE_PATH

        keytool = shutil.which('keytool')
        if not keytool:
            raise Exception('keytool not found')

        try:
            os.remove(ts_filepath)
            log.info("Removed existing TrustStore file: %s", ts_filepath)
        except FileNotFoundError:
            log.info("TrustStore file does not yet exist: %s", ts_filepath)

        cmd = [
            keytool,
            '-importkeystore',
            '-noprompt',
            '-srckeystore',
            '/opt/mesosphere/active/java/usr/java/jre/lib/security/cacerts',
            '-srcstorepass', 'changeit',
            '-deststorepass', 'changeit',
            '-destkeystore', ts_filepath
        ]

        log.info('Copying Java TrustStore: {}'.format(' '.join(cmd)))
        proc = subprocess.Popen(cmd, shell=False, preexec_fn=_set_umask)
        if proc.wait() != 0:
            raise Exception('keytool failed')

        cmd = [
            keytool,
            '-import',
            '-noprompt',
            '-trustcacerts',
            '-alias', 'dcos_root_ca',
            '-file', ca_bundle_filepath,
            '-keystore', ts_filepath,
            '-storepass', 'changeit',
        ]
        log.info('Importing CA bundle into TrustStore: {}'.format(' '.join(cmd)))
        proc = subprocess.Popen(cmd, shell=False, preexec_fn=_set_umask)
        if proc.wait() != 0:
            raise Exception('keytool failed')

        os.chmod(ts_filepath, 0o644)

    def service_auth_token(self, uid, exp=None):
        iam_cli = iam.IAMClient(self.iam_url)
        acc = self.secrets['services'][uid]
        log.info('Service account login as service {}'.format(uid))
        token = iam_cli.service_account_login(uid, private_key=acc['private_key'], exp=exp)
        return token

    def write_service_auth_token(self, uid, filename=None, exp=None):
        """Create service authentication token for given `uid` and `exp`.

        Create and return an environment variable declaration string
        of the format

            SERVICE_AUTH_TOKEN=<authtoken>\n

        If `filename` is given, write the environment variable declaration
        string to that file path.

        Returns:
            bytes: environment variable declaration
        """
        token = self.service_auth_token(uid, exp)
        env = bytes('SERVICE_AUTH_TOKEN={}\n'.format(token), 'ascii')
        if filename is not None:
            _write_file_bytes(filename, env, 0o600)
        return env

    def create_key_certificate(self, cn, key_filename, crt_filename,
                               service_account=None, master=False,
                               marathon=False, extra_san=None,
                               key_mode=0o600, private_key_type=None,
                               use_exact_cn=False):
        """Creates a private key and certificate.

        Args:
            cn (str):
                Defines the value of the "common name" attribute of the subject of
                the X.509 certificate: the certificate subject field contains an
                X.500 distinguished name (DN). The subject DN itself is comprised
                of multiple attributes. This parameter defines the value of the
                attribute with OID 2.5.4.3 (usually abbreviated "CN"). By default,
                the current machine's internal IP address as returned by
                `detect_ip()` is appended to the name. Set the `use_exact_cn`
                parameter to True to prevent that modification from happening.
            key_filename (str):
                The path to the key.
            crt_filename (str):
                The path to the certificate.
            service_account (string, optional):
                The name of the service account to
                authenticate as when requesting that the CSR be signed.
            master (bool):
                If True the master DNS entries will be added to the
                list of SANs. Defaults to False.
            marathon (bool):
                If True the Marathon DNS entries will be added to
                the list of SANs. Defaults to False.
            extra_san (list of cryptography.GeneralName, optional):
                A list of additional SANs to be added to the certificate.
            key_mode (int):
                The permission bits for the key being generated.
                Defaults to 0o600.
            private_key_type (rsa.RSAPrivateKey or ec.EllipticCurvePrivateKey):
                The type of private key to generate.
            use_exact_cn (bool):
                If `use_exact_cn` is False the value of `cn` is modified
                for use as the CommonName in the certificate. If True,
                the value of `cn` is used exactly as the CommonName in the
                certificate.
        """
        log.info('Generating CSR for key {}'.format(key_filename))
        privkey_pem, csr_pem = utils.generate_key_CSR(
            cn,
            master=master,
            marathon=marathon,
            extra_san=extra_san,
            private_key_type=private_key_type,
            use_exact_cn=use_exact_cn)

        headers = {}
        if service_account:
            token = self.service_auth_token(service_account)
            headers = {'Authorization': 'token=' + token}
        cacli = ca.CAClient(self.ca_url, headers)

        msg_fmt = 'Signing CSR at {} with service account {}'
        log.info(msg_fmt.format(self.ca_url, service_account))
        crt = cacli.sign(csr_pem)

        crt = self._append_ca_chain_to_certificate(crt)

        _write_file_bytes(key_filename, bytes(privkey_pem, 'ascii'), key_mode)
        _write_file_bytes(crt_filename, bytes(crt, 'ascii'), 0o644)

    def _append_ca_chain_to_certificate(self, crt):
        """
        Appends CA chain to the certificate
        """
        if 'CA' in self.secrets:
            crt += self.secrets['CA']['RootCA']['chain']
        else:
            crt += self._consensus(
                '/dcos/CAChain', None, ANYONE_READ).decode('ascii')

        return crt

    def _key_cert_is_valid(self, key_filename, crt_filename):
        try:
            with open(crt_filename) as fh:
                crt = fh.read()
        except FileNotFoundError:
            log.warn('Certificate was not found')
            return False
        if 'BEGIN CERTIFICATE' not in crt:
            log.warn('Certificate is invalid')
            return False
        # Certificate validity (expiration, issuing CA, etc.) is not checked.
        # An administrator wishing to rotate a certificate should remove the
        # old certificate and key and restart the service.
        try:
            with open(key_filename) as fh:
                key = fh.read()
        except FileNotFoundError:
            log.warn('Private key was not found')
            return False
        if 'PRIVATE KEY' not in key:
            log.warn('Private key is invalid')
            return False

        return True

    def ensure_key_certificate(
            self, cn, key_filename, crt_filename, service_account=None,
            master=False, marathon=False, extra_san=None, key_mode=0o600,
            use_exact_cn=False):
        """Creates a private key and certificate.

        If the key and ceritificate already exist and are valid the function
        exits without performing any modification.

        Args:
            cn (str):
                Defines the value of the "common name" attribute of the subject of
                the X.509 certificate: the certificate subject field contains an
                X.500 distinguished name (DN). The subject DN itself is comprised
                of multiple attributes. This parameter defines the value of the
                attribute with OID 2.5.4.3 (usually abbreviated "CN"). By default,
                the current machine's internal IP address as returned by
                `detect_ip()` is appended to the name. Set the `use_exact_cn`
                parameter to True to prevent that modification from happening.
            key_filename (str):
                The path to the key.
            crt_filename (str):
                The path to the certificate.
            service_account (string, optional):
                The name of the service account to
                authenticate as when requesting that the CSR be signed.
            master (bool):
                If True the master DNS entries will be added to the
                list of SANs. Defaults to False.
            marathon (bool):
                If True the Marathon DNS entries will be added to
                the list of SANs. Defaults to False.
            extra_san ([cryptography.GeneralName], optional):
                A list of additional SANs to be added to the certificate.
            key_mode (int):
                The permission bits for the key being generated.
                Defaults to 0o600.
            use_exact_cn (bool):
                If `use_exact_cn` is False the value of `cn` is modified
                for use as the CommonName in the certificate. If True,
                the value of `cn` is used exactly as the CommonName in the
                certificate.
        """
        # TODO(gpaul): this method should be idempotent. See DCOS-16332
        if not self._key_cert_is_valid(key_filename, crt_filename):
            log.info('Generating certificate {}'.format(crt_filename))
            self.create_key_certificate(cn, key_filename, crt_filename,
                                        service_account, master, marathon,
                                        extra_san, key_mode,
                                        self.get_CA_private_key_type(),
                                        use_exact_cn)
        else:
            log.debug('Certificate {} already exists'.format(crt_filename))

    def write_jwks_public_keys(self, filename):
        iamcli = iam.IAMClient(self.iam_url)
        jwks = iamcli.jwks()
        output = utils.jwks_to_public_keys(jwks)
        _write_file_bytes(filename, bytes(output, 'ascii'), 0o644)

    def upgrade_19_to_110_secret_root_ca(self, acl=None):
        """
        Runs an upgrade procedure when upgrading a cluster from 1.9.x to
        1.10. Enterprise DC/OS 1.10 expects two additional top-level keys in
        the JSON document stored in the /dcos/master/secrets/CA/RootCA z node.

        The upgrade procedure (idempotent, no need to lock to single worker):

        - Try to read value from `/dcos/master/secrets/CA/RootCA`
        - If exists, deserialize JSON, see if only `key` and `certificate`
          keys are present. If that is the case, proceed with the upgrade procedure
        - Calculate values for `root` and `chain` from loaded data
        - Serialize data into new JSON document, and write it with given ACL

        Args:
            acl (dict): ACLs to apply to zookeeper node
        """
        zk_path = '/dcos/master/secrets/CA/RootCA'

        try:
            root_ca_bytes = self.zk.get(zk_path)[0]
        except kazoo.exceptions.NoNodeError:
            log.info(
                '`%s` does not contain any value, nothing to upgrade', zk_path)
            return

        root_ca = json.loads(root_ca_bytes.decode('ascii'))

        has_length_2 = len(root_ca) == 2
        has_key = 'key' in root_ca
        has_certificate = 'certificate' in root_ca
        if not (has_length_2 and has_key and has_certificate):
            log.info(
                '`RootCA` data structure does not look like 1.9.x, no upgrade')
            return

        # Add missing keys.
        root_ca['chain'] = ''
        root_ca['root'] = root_ca['certificate']

        root_ca_bytes = json.dumps(root_ca, ensure_ascii=True).encode('ascii')

        self.zk.set(zk_path, root_ca_bytes)
        self.zk.sync(zk_path)
        log.info(
            '`RootCA` data has been upgraded from the 1.9.x '
            'serialization format to the 1.10.x serialization format.'
            )

        if acl:
            self.zk.set_acls(zk_path, acl)


def _write_file_bytes(path, data, mode):
    """Write byte sequence `data` to regular file located at `path`.

    Set file permissions to `mode` (given in octal notation such as
    `0o600`). Use canonical umask when applying mode.
    """
    dirpath = os.path.dirname(os.path.abspath(path))
    with utils.Directory(dirpath) as d:
        with d.lock():
            umask_original = os.umask(0)
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                log.info('Writing {} with mode {:o}'.format(path, mode))
                with os.fdopen(os.open(path, flags, mode), 'wb') as f:
                    f.write(data)
            finally:
                os.umask(umask_original)


def _set_umask():
    os.setpgrp()
    # prevent other users from reading files created by this process
    os.umask(0o077)


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('services', nargs='+')
    parser.add_argument(
        '--statedir',
        default='/var/lib/dcos',
        help='State direcotry')
    parser.add_argument(
        '--zk',
        default=None,
        help='Host string passed to Kazoo client constructor.')
    parser.add_argument(
        '--zk_super_creds',
        default='/opt/mesosphere/etc/zk_super_credentials',
        help='File with ZooKeeper super credentials')
    parser.add_argument(
        '--zk_master_creds',
        default='/opt/mesosphere/etc/zk_master_credentials',
        help='File with ZooKeeper master credentials')
    parser.add_argument(
        '--zk_agent_creds',
        default='/opt/mesosphere/etc/zk_agent_credentials',
        help='File with ZooKeeper agent credentials')
    parser.add_argument(
        '--zk_agent_digest',
        default='/opt/mesosphere/etc/zk_agent_digest',
        help='File with ZooKeeper agent digest')
    parser.add_argument(
        '--master_count',
        default='/opt/mesosphere/etc/master_count',
        help='File with number of master servers')
    parser.add_argument(
        '--iam_url',
        default=None,
        help='IAM Service (Bouncer) URL')
    parser.add_argument(
        '--ca_url',
        default=None,
        help='CA URL')
    parser.add_argument(
        '--config-path',
        default='/opt/mesosphere/etc/bootstrap-config.json',
        help='Path to config file for bootstrap')

    opts = parser.parse_args()

    with open(opts.config_path, 'rb') as f:
        opts.config = json.loads(f.read().decode('ascii'))

    opts.bouncer_user = 'dcos_bouncer'
    opts.dcos_secrets_user = 'dcos_secrets'
    opts.dcos_vault_user = 'dcos_vault'
    opts.dcos_ca_user = 'dcos_ca'
    opts.dcos_cosmos_user = 'dcos_cosmos'
    opts.dcos_mesos_dns_user = 'dcos_mesos_dns'

    def _verify_and_set_zk_creds(credentials_path, credentials_type=None):
        if os.path.exists(credentials_path):
            log.info('Reading {credentials_type} credentials from {credentials_path}'.format(
                credentials_type=credentials_type, credentials_path=credentials_path))
            return utils.read_file_line(credentials_path)
        log.info('{credentials_type} credentials not available'.format(credentials_type=credentials_type))
        return None

    if opts.config['security'] == 'disabled':
        opts.zk_super_creds = None
        opts.zk_master_creds = None
        opts.zk_agent_creds = None
        opts.zk_agent_digest = None
    else:
        opts.zk_super_creds = _verify_and_set_zk_creds(opts.zk_super_creds, "ZooKeeper super")
        opts.zk_master_creds = _verify_and_set_zk_creds(opts.zk_master_creds, "ZooKeeper master")
        opts.zk_agent_creds = _verify_and_set_zk_creds(opts.zk_agent_creds, "ZooKeeper agent")
        opts.zk_agent_digest = _verify_and_set_zk_creds(opts.zk_agent_digest, "ZooKeeper agent digest")

    if os.path.exists('/opt/mesosphere/etc/roles/master'):
        zk_default = '127.0.0.1:2181'
        iam_default = 'http://127.0.0.1:8101'
        ca_default = 'http://127.0.0.1:8888'
    else:
        if os.getenv('MASTER_SOURCE') == 'master_list':
            # Spartan agents with static master list
            with open('/opt/mesosphere/etc/master_list', 'r') as f:
                master_list = json.load(f)
            assert len(master_list) > 0
            leader = random.choice(master_list)
        elif os.getenv('EXHIBITOR_ADDRESS'):
            # Spartan agents on AWS
            leader = os.getenv('EXHIBITOR_ADDRESS')
        else:
            # any other agent service
            leader = 'leader.mesos'

        zk_default = leader + ':2181'
        if opts.config['ssl_enabled']:
            iam_default = 'https://' + leader
            ca_default = 'https://' + leader
        else:
            iam_default = 'http://' + leader
            ca_default = 'http://' + leader

    if not opts.zk:
        opts.zk = zk_default
    if not opts.iam_url:
        opts.iam_url = iam_default
    if not opts.ca_url:
        opts.ca_url = ca_default

    return opts


def make_run_dirs():
    rundir_abspath = '/run/dcos/'
    subdirs_relpaths = [
        'etc',
        'etc/dcos-diagnostics',
        'etc/dcos-checks',
        'etc/dcos-backup',
        'etc/dcos-ca',
        'etc/dcos-metrics',
        'etc/history-service',
        'etc/marathon',
        'etc/mesos',
        'etc/mesos-dns',
        'etc/metronome',
        'etc/signal-service',
        'pki/CA/certs',
        'pki/CA/private',
        'pki/tls/certs',
        'pki/tls/private',
        # cockroachdb 1.0 expects the CA and end entity certs and keys in the same directory.
        # See https://github.com/cockroachdb/cockroach/issues/15760
        'pki/cockroach'
    ]

    # Build all absolute directory paths.
    dirpaths = [rundir_abspath + sd for sd in subdirs_relpaths]

    # Create directories with the `mkdir -p` equivalent.
    for path in dirpaths:
        log.info('Make sure directory exists: %s', path)
        os.makedirs(path, exist_ok=True)


def dcos_bouncer(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()
    b.bouncer_acls()

    keypath = opts.rundir + '/pki/tls/private/bouncer.key'
    b.write_private_key('dcos_bouncer', keypath)
    shutil.chown(keypath, user=opts.bouncer_user)

    path = opts.rundir + '/etc/bouncer'
    b.write_bouncer_env(path)


def dcos_cockroach(b, opts):
    """Prepare the Zookeeper ACLs, environment, run directory and ceritificates for the dcos-cockroach service."""
    b.init_zk_acls()
    b.create_master_secrets()
    b.cockroach_acls()

    path = opts.rundir + '/etc/cockroach'
    b.write_cockroach_env(path)

    cockroachdir = opts.rundir + '/pki/cockroach'
    # Copy CA cert to cockroach cert dir. They don't support specifying separate
    # cert paths in v1.0. CockroachDB requires the CA bundle to be
    # named `ca.crt`.
    capath = cockroachdir + '/ca.crt'
    shutil.copy2(opts.rundir + '/pki/CA/ca-bundle.crt', capath)

    # Create the TLS key pair for this CockroachDB instance.
    keypath = cockroachdir + '/node.key'
    crtpath = cockroachdir + '/node.crt'
    # The ceritificate CN must be "node" as cockroachdb explicitly checks
    # it to make sure the correct certificate is being used
    # for inter-node communications.
    b.ensure_key_certificate('node', keypath, crtpath, master=True, use_exact_cn=True)
    shutil.chown(keypath, user='dcos_cockroach')
    shutil.chown(crtpath, user='dcos_cockroach')

    # Generate the key pair used by the IAM to connect as the root user to the
    # database. Password login as root is not possible, which is great.
    keypath = cockroachdir + '/client.root.key'
    crtpath = cockroachdir + '/client.root.crt'
    # The ceritificate CN must be "root" as cockroachdb explicitly checks for
    # that string as a poor man's authentication mechanism.
    # See `security.RootUser` defined here:
    # https://github.com/cockroachdb/cockroach/blob/4f89174c1c36a6d94794d44f6a14af7e8eec3282/pkg/security/auth.go#L30
    b.ensure_key_certificate('root', keypath, crtpath, master=True, use_exact_cn=True)
    # As these will be used by the IAM they must be owned by the IAM user.
    shutil.chown(keypath, user='dcos_bouncer')
    shutil.chown(crtpath, user='dcos_bouncer')


def dcos_secrets(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()
    b.dcos_secrets_acls()

    if opts.config['ssl_enabled']:
        keypath = opts.rundir + '/pki/tls/private/dcos-secrets.key'
        crtpath = opts.rundir + '/pki/tls/certs/dcos-secrets.crt'
        b.ensure_key_certificate('Secrets', keypath, crtpath, master=True)
        shutil.chown(keypath, user=opts.dcos_secrets_user)
        shutil.chown(crtpath, user=opts.dcos_secrets_user)

    path = opts.rundir + '/etc/dcos-secrets.env'
    b.write_secrets_env(path)

    secrets_dir = opts.statedir + '/secrets'
    try:
        os.makedirs(secrets_dir)
    except FileExistsError:
        pass
    shutil.chown(secrets_dir, user=opts.dcos_secrets_user)


def dcos_vault_default(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()
    b.dcos_vault_default_acls()

    vault_dir = opts.statedir + '/secrets/vault'
    try:
        os.makedirs(vault_dir, exist_ok=True)
    except FileExistsError:
        pass

    vault_default_dir = opts.statedir + '/secrets/vault/default'
    try:
        os.makedirs(vault_default_dir, exist_ok=True)
    except FileExistsError:
        pass
    # secrets writes keys into this directory
    shutil.chown(vault_default_dir, user=opts.dcos_secrets_user)

    hcl = opts.rundir + '/etc/vault.hcl'
    b.write_vault_config(hcl)


def dcos_ca(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()
    b.dcos_ca_acls()

    path = opts.rundir + '/etc/dcos-ca/dbconfig.json'
    b.write_dcos_ca_creds(src='/opt/mesosphere/etc/dcos-ca/dbconfig.json', dst=path)

    b.write_signing_CA_certificate(user=opts.dcos_ca_user)
    b.write_signing_CA_key(user=opts.dcos_ca_user)
    b.write_CA_certificate_chain()
    b.write_CA_trust_bundle()
    b.write_CA_trust_bundle_for_libcurl()


def dcos_mesos_master(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()
    b.mesos_zk_acls()

    b.write_mesos_master_env(opts.rundir + '/etc/mesos-master')

    if opts.config['ssl_enabled']:
        keypath = opts.rundir + '/pki/tls/private/mesos-master.key'
        crtpath = opts.rundir + '/pki/tls/certs/mesos-master.crt'
        b.ensure_key_certificate('Mesos Master', keypath, crtpath, master=True)

    # Service account needed to retrieve ACLs from bouncer.
    # As a result, we always create this account.
    b.create_service_account('dcos_mesos_master', superuser=True)
    svc_acc_creds_fn = opts.rundir + '/etc/mesos/master_service_account.json'
    b.write_service_account_credentials('dcos_mesos_master', svc_acc_creds_fn)

    # agent secrets are needed for it to contact the master
    b.create_agent_secrets(opts.zk_agent_digest)

    b.create_agent_service_accounts()

    # If permissive security is enabled, create the 'dcos_anonymous' account.
    if opts.config['security'] == 'permissive':
        # TODO(greggomann): add proper ACLs for 'dcos_anonymous'.
        # For now, we make dcos_anonymous a superuser, so security-ignorant scripts/frameworks
        # can still access Mesos endpoints and register however they like.
        b.create_service_account('dcos_anonymous', superuser=True)


def dcos_mesos_slave(b, opts):
    b.read_agent_secrets()
    b.write_CA_trust_bundle()
    b.write_CA_trust_bundle_for_libcurl()

    if opts.config['ssl_enabled']:
        keypath = opts.rundir + '/pki/tls/private/mesos-slave.key'
        crtpath = opts.rundir + '/pki/tls/certs/mesos-slave.crt'
        b.ensure_key_certificate('Mesos Agent', keypath, crtpath, service_account='dcos_agent')

    if opts.config['executor_secret_generation_enabled']:
        b.write_executor_secret_key(opts.config['executor_secret_key_path'])

    # Service account needed to
    # a) authenticate with master, and/or
    # b) retrieve ACLs from bouncer, and/or
    # c) fetch secrets
    # As a result, we always create this account.
    svc_acc_creds_fn = opts.rundir + '/etc/mesos/agent_service_account.json'
    b.write_service_account_credentials('dcos_mesos_agent', svc_acc_creds_fn)

    # TODO(adam): orchestration API should handle this in the future
    if opts.config['ssl_enabled']:
        keypath = opts.rundir + '/pki/tls/private/scheduler.key'
        crtpath = opts.rundir + '/pki/tls/certs/scheduler.crt'
        b.ensure_key_certificate('Mesos Schedulers', keypath, crtpath, service_account='dcos_agent', key_mode=0o644)


def dcos_mesos_slave_public(b, opts):
    b.read_agent_secrets()

    if opts.config['ssl_enabled']:
        b.write_CA_trust_bundle()

        keypath = opts.rundir + '/pki/tls/private/mesos-slave.key'
        crtpath = opts.rundir + '/pki/tls/certs/mesos-slave.crt'
        b.ensure_key_certificate('Mesos Public Agent', keypath, crtpath, service_account='dcos_agent')

    if opts.config['executor_secret_generation_enabled']:
        b.write_executor_secret_key(opts.config['executor_secret_key_path'])

    # Service account needed to
    # a) authenticate with master, and/or
    # b) retrieve ACLs from bouncer, and/or
    # c) fetch secrets
    # As a result, we always create this account.
    svc_acc_creds_fn = opts.rundir + '/etc/mesos/agent_service_account.json'
    b.write_service_account_credentials('dcos_mesos_agent_public', svc_acc_creds_fn)

    # TODO(adam): orchestration API should handle this in the future
    if opts.config['ssl_enabled']:
        keypath = opts.rundir + '/pki/tls/private/scheduler.key'
        crtpath = opts.rundir + '/pki/tls/certs/scheduler.crt'
        b.ensure_key_certificate('Mesos Schedulers', keypath, crtpath, service_account='dcos_agent', key_mode=0o644)


def dcos_marathon(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()
    b.marathon_zk_acls()

    if opts.config['zk_acls_enabled']:
        # Must be run after create_master_secrets.
        env = opts.rundir + '/etc/marathon/zk.env'
        b.write_marathon_zk_env(env)
        shutil.chown(env, user='dcos_marathon')

    # For libmesos scheduler SSL or Marathon UI/API SSL.
    if opts.config['ssl_enabled'] or opts.config['marathon_https_enabled']:
        key = opts.rundir + '/pki/tls/private/marathon.key'
        crt = opts.rundir + '/pki/tls/certs/marathon.crt'
        b.ensure_key_certificate('Marathon', key, crt, master=True, marathon=True)
        shutil.chown(key, user='dcos_marathon')
        shutil.chown(crt, user='dcos_marathon')

        b.write_CA_trust_bundle()

        ca_chain_with_root_cert = opts.rundir + '/pki/CA/ca-chain-inclroot.crt'
        b.write_CA_certificate_chain_with_root_cert(ca_chain_with_root_cert)

    # For Marathon UI/API SSL.
    if opts.config['marathon_https_enabled']:

        b.write_java_truststore_with_dcos_ca_bundle()

        env = opts.rundir + '/etc/marathon/tls.env'
        b.write_marathon_tls_env(key, crt, ca_chain_with_root_cert, env)
        shutil.chown(env, user='dcos_marathon')
        shutil.chown(opts.rundir + '/pki/tls/private/marathon.jks', user='dcos_marathon')

    # For framework authentication.
    if opts.config['framework_authentication_enabled']:
        b.create_service_account('dcos_marathon', superuser=False)
        svc_acc_creds_fn = opts.rundir + '/etc/marathon/service_account.json'
        b.write_service_account_credentials('dcos_marathon', svc_acc_creds_fn)
        shutil.chown(svc_acc_creds_fn, user='dcos_marathon')

    # Permissions in the IAM must be granted after creating the service account.
    b.marathon_iam_permissions()


def dcos_metronome(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()
    b.metronome_zk_acls()

    # For libmesos scheduler SSL.
    if opts.config['ssl_enabled']:
        key = opts.rundir + '/pki/tls/private/metronome.key'
        crt = opts.rundir + '/pki/tls/certs/metronome.crt'
        b.ensure_key_certificate('Metronome', key, crt, master=True)
        shutil.chown(key, user='dcos_metronome')
        shutil.chown(crt, user='dcos_metronome')
        # ca-bundle.crt also only for libmesos SSL.
        b.write_CA_trust_bundle()

        ca_chain_with_root_cert = opts.rundir + '/pki/CA/ca-chain-inclroot.crt'
        b.write_CA_certificate_chain_with_root_cert(ca_chain_with_root_cert)

        b.write_java_truststore_with_dcos_ca_bundle()

        env = opts.rundir + '/etc/metronome/tls.env'
        b.write_metronome_env(key, crt, ca_chain_with_root_cert, env)
        shutil.chown(env, user='dcos_metronome')
        shutil.chown(opts.rundir + '/pki/tls/private/metronome.jks', user='dcos_metronome')

    # For framework authentication.
    if opts.config['framework_authentication_enabled']:
        b.create_service_account('dcos_metronome', superuser=False)
        svc_acc_creds_fn = opts.rundir + '/etc/metronome/service_account.json'
        b.write_service_account_credentials('dcos_metronome', svc_acc_creds_fn)
        shutil.chown(svc_acc_creds_fn, user='dcos_metronome')

    shutil.chown(opts.rundir + '/etc/metronome', user='dcos_metronome')

    # IAM ACLs must be created after the service account.
    b.metronome_iam_permissions()


def dcos_mesos_dns(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()
    b.create_service_account('dcos_mesos_dns', superuser=True)

    if opts.config['ssl_enabled']:
        b.write_CA_trust_bundle()

        # Generate client certificate (In strict security mode, Mesos-DNS is
        # required to present this to the Mesos master during the TLS handshake).
        keypath = opts.rundir + '/pki/tls/private/mesos-dns.key'
        crtpath = opts.rundir + '/pki/tls/certs/mesos-dns.crt'
        b.ensure_key_certificate('Mesos DNS', keypath, crtpath, master=True)
        shutil.chown(keypath, user=opts.dcos_mesos_dns_user)
        shutil.chown(crtpath, user=opts.dcos_mesos_dns_user)

    if opts.config['mesos_authenticate_http']:
        svc_acc_creds_fn = opts.rundir + '/etc/mesos-dns/iam.json'
        b.write_service_account_credentials('dcos_mesos_dns', svc_acc_creds_fn)
        shutil.chown(svc_acc_creds_fn, user='dcos_mesos_dns')


def dcos_adminrouter(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()
    b.create_service_account('dcos_adminrouter', superuser=True)

    extra_san = []
    internal_lb = os.getenv('INTERNAL_MASTER_LB_DNSNAME')
    if internal_lb:
        extra_san.append(utils.SanEntry('dns', internal_lb))
    external_lb = os.getenv('MASTER_LB_DNSNAME')
    if external_lb:
        extra_san.append(utils.SanEntry('dns', external_lb))

    machine_pub_ip = subprocess.check_output(
        ['/opt/mesosphere/bin/detect_ip_public'],
        stderr=subprocess.DEVNULL).decode('ascii').strip()
    gen.calc.validate_ipv4_addresses([machine_pub_ip])
    # We add ip as both DNS and IP entry so that old/broken software that does
    # not support IPAddress type SAN can still use it.
    extra_san.append(utils.SanEntry('dns', machine_pub_ip))
    extra_san.append(utils.SanEntry('ip', machine_pub_ip))

    if opts.config['ssl_enabled']:
        keypath = opts.rundir + '/pki/tls/private/adminrouter.key'
        crtpath = opts.rundir + '/pki/tls/certs/adminrouter.crt'
        b.ensure_key_certificate('AdminRouter', keypath, crtpath, master=True, extra_san=extra_san)

    b.write_jwks_public_keys(opts.rundir + '/etc/jwks.pub')

    # Generate SERVICE_AUTH_TOKEN=<authtoken> env var declaration.
    # Strip trailing newline returned by  `write_service_auth_token()`.
    service_auth_token_env_declaration = b.write_service_auth_token(
        uid='dcos_adminrouter',
        exp=0,
        filename=None).decode('ascii').strip()

    env_file_lines = [service_auth_token_env_declaration]

    # Optionally generate EXHIBITOR_ADMIN_HTTPBASICAUTH_CREDS=<creds> declaration.
    if opts.config['exhibitor_admin_password_enabled'] is True:
        pw = opts.config['exhibitor_admin_password']

        # Build HTTP Basic auth credential string.
        exhibitor_admin_basic_auth_creds = base64.b64encode(
            'admin:{}'.format(pw).encode('ascii')).decode('ascii')

        env_file_lines.append(
            'EXHIBITOR_ADMIN_HTTPBASICAUTH_CREDS={}'.format(
                exhibitor_admin_basic_auth_creds))

    env_file_contents_bytes = '\n'.join(env_file_lines).encode('ascii')
    env_file_path = opts.rundir + '/etc/adminrouter.env'
    _write_file_bytes(env_file_path, env_file_contents_bytes, 0o600)


def dcos_adminrouter_agent(b, opts):
    b.read_agent_secrets()

    if opts.config['ssl_enabled']:
        b.write_CA_trust_bundle()

        keypath = opts.rundir + '/pki/tls/private/adminrouter-agent.key'
        crtpath = opts.rundir + '/pki/tls/certs/adminrouter-agent.crt'
        b.ensure_key_certificate('Adminrouter Agent', keypath, crtpath, service_account='dcos_agent')

    b.write_jwks_public_keys(opts.rundir + '/etc/jwks.pub')

    # write_service_auth_token must follow
    # write_CA_certificate on agents to allow
    # for a verified HTTPS connection on login
    b.write_service_auth_token('dcos_adminrouter_agent', opts.rundir + '/etc/adminrouter.env', exp=0)


def dcos_backup_master(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()

    b.create_service_account('dcos_backup_master', superuser=True)

    svc_acc_creds_fn = opts.rundir + '/etc/dcos-backup/master_service_account.json'
    b.write_service_account_credentials('dcos_backup_master', svc_acc_creds_fn)
    shutil.chown(svc_acc_creds_fn, user='dcos_backup')

    backup_dir = opts.statedir + '/backup'
    try:
        os.makedirs(backup_dir)
    except FileExistsError:
        pass
    shutil.chown(backup_dir, user='dcos_backup')


def dcos_spartan(b, opts):
    if os.path.exists('/opt/mesosphere/etc/roles/master'):
        return dcos_spartan_master(b, opts)
    else:
        return dcos_spartan_agent(b, opts)


def dcos_spartan_master(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()

    if opts.config['ssl_enabled']:
        b.write_CA_trust_bundle()
        b.write_CA_certificate_chain_with_root_cert()

        b.write_CA_certificate_chain()

        key = opts.rundir + '/pki/tls/private/spartan.key'
        crt = opts.rundir + '/pki/tls/certs/spartan.crt'
        b.ensure_key_certificate('Spartan Master', key, crt, master=True)


def dcos_spartan_agent(b, opts):
    b.read_agent_secrets()

    if opts.config['ssl_enabled']:
        b.write_CA_trust_bundle()

        # Note(JP): Do we really need both?
        b.write_CA_certificate_chain_with_root_cert()
        b.write_CA_certificate_chain()

        keypath = opts.rundir + '/pki/tls/private/spartan.key'
        crtpath = opts.rundir + '/pki/tls/certs/spartan.crt'
        b.ensure_key_certificate('Spartan Agent', keypath, crtpath, service_account='dcos_agent')


def dcos_erlang_service(servicename, b, opts):
    if servicename == 'networking_api':
        for file in ['/opt/mesosphere/active/networking_api/networking_api/releases/0.0.1/vm.args.2.config',
                     '/opt/mesosphere/active/networking_api/networking_api/releases/0.0.1/sys.config.2.config']:
            if not os.path.exists(file):
                open(file, 'a').close()
                shutil.chown(file, user='dcos_networking_api')
        shutil.chown('/opt/mesosphere/active/networking_api/networking_api', user='dcos_networking_api')
        shutil.chown('/opt/mesosphere/active/networking_api/networking_api/log', user='dcos_networking_api')
    if os.path.exists('/opt/mesosphere/etc/roles/master'):
        log.info('%s master bootstrap', servicename)
        return dcos_erlang_service_master(servicename, b, opts)
    else:
        log.info('%s agent bootstrap', servicename)
        return dcos_erlang_service_agent(servicename, b, opts)


def dcos_erlang_service_master(servicename, b, opts):
    b.init_zk_acls()
    b.create_master_secrets()
    b.create_service_account('dcos_{}_master'.format(servicename), superuser=True)

    user = 'dcos_' + servicename

    b.write_CA_trust_bundle()

    # Note(JP): do we really need both? I believe we should be able to get rid of
    # `write_CA_certificate_chain()`.
    b.write_CA_certificate_chain_with_root_cert()
    b.write_CA_certificate_chain()

    friendly_name = servicename[0].upper() + servicename[1:]
    key = opts.rundir + '/pki/tls/private/{}.key'.format(servicename)
    crt = opts.rundir + '/pki/tls/certs/{}.crt'.format(servicename)
    b.ensure_key_certificate(friendly_name, key, crt)
    if servicename == 'networking_api':
        shutil.chown(key, user=user)
        shutil.chown(crt, user=user)

    auth_env = opts.rundir + '/etc/{}_auth.env'.format(servicename)
    b.write_service_auth_token('dcos_{}_master'.format(servicename), auth_env, exp=0)
    if servicename == 'networking_api':
        shutil.chown(auth_env, user=user)


def dcos_erlang_service_agent(servicename, b, opts):
    b.read_agent_secrets()

    user = 'dcos_' + servicename

    if opts.config['ssl_enabled']:
        b.write_CA_trust_bundle()

        # Note(JP): do we really need both?
        b.write_CA_certificate_chain_with_root_cert()
        b.write_CA_certificate_chain()

        friendly_name = servicename[0].upper() + servicename[1:]
        key = opts.rundir + '/pki/tls/private/{}.key'.format(servicename)
        crt = opts.rundir + '/pki/tls/certs/{}.crt'.format(servicename)
        b.ensure_key_certificate(friendly_name, key, crt, service_account='dcos_agent')

    if servicename == 'networking_api':
        shutil.chown(key, user=user)
        shutil.chown(crt, user=user)

    auth_env = opts.rundir + '/etc/{}_auth.env'.format(servicename)
    b.write_service_auth_token('dcos_{}_agent'.format(servicename), auth_env, exp=0)
    if servicename == 'networking_api':
        shutil.chown(auth_env, user=user)


def dcos_cosmos(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()
    b.cosmos_acls()

    key = opts.rundir + '/pki/tls/private/cosmos.key'
    crt = opts.rundir + '/pki/tls/certs/cosmos.crt'
    b.ensure_key_certificate('Cosmos', key, crt, master=True)
    shutil.chown(key, user='dcos_cosmos')
    shutil.chown(crt, user='dcos_cosmos')

    b.write_CA_trust_bundle()

    b.write_java_truststore_with_dcos_ca_bundle()

    b.write_cosmos_env(env_fn='/run/dcos/etc/cosmos.env')


def dcos_signal(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()
    b.create_service_account('dcos_signal_service', superuser=True)

    svc_acc_creds_fn = opts.rundir + '/etc/signal-service/service_account.json'
    b.write_service_account_credentials('dcos_signal_service', svc_acc_creds_fn)
    shutil.chown(svc_acc_creds_fn, user='dcos_signal')


def dcos_metrics_master(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()

    b.create_service_account('dcos_metrics_master', superuser=True)

    svc_acc_creds_fn = opts.rundir + '/etc/dcos-metrics/service_account.json'
    b.write_service_account_credentials('dcos_metrics_master', svc_acc_creds_fn)
    shutil.chown(svc_acc_creds_fn, user='dcos_metrics')


def dcos_metrics_agent(b, opts):
    b.read_agent_secrets()

    b.cluster_id(readonly=True)

    svc_acc_creds_fn = opts.rundir + '/etc/dcos-metrics/service_account.json'
    b.write_service_account_credentials('dcos_metrics_agent', svc_acc_creds_fn)
    shutil.chown(svc_acc_creds_fn, user='dcos_metrics')


def dcos_diagnostics_master(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()

    b.create_service_account('dcos_diagnostics_master', superuser=True)
    svc_acc_creds_fn = opts.rundir + '/etc/dcos-diagnostics/master_service_account.json'
    b.write_service_account_credentials('dcos_diagnostics_master', svc_acc_creds_fn)
    shutil.chown(svc_acc_creds_fn, user='dcos_diagnostics')

    # dcos-diagnostics agent secrets are needed for it to contact the
    b.create_agent_secrets(opts.zk_agent_digest)
    b.create_service_account('dcos_diagnostics_agent', superuser=True)


def dcos_diagnostics_agent(b, opts):
    b.read_dcos_diagnostics_agent_secrets()
    svc_acc_creds_fn = opts.rundir + '/etc/dcos-diagnostics/agent_service_account.json'
    b.write_service_account_credentials('dcos_diagnostics_agent', svc_acc_creds_fn)
    shutil.chown(svc_acc_creds_fn, user='dcos_diagnostics')


def dcos_checks_master(b, opts):
    b.init_zk_acls()
    b.create_master_secrets()

    b.create_service_account('dcos_checks_master', superuser=True)

    svc_acc_creds_fn = opts.rundir + '/etc/dcos-checks/checks_service_account.json'
    b.write_service_account_credentials('dcos_checks_master', svc_acc_creds_fn)
    shutil.chown(svc_acc_creds_fn, user='dcos_diagnostics')

    # TODO: https://jira.mesosphere.com/browse/DCOS-16357
    # Checks does not require two service accounts. We needed to create two,
    # since the login endpoints for master and agent are different. This will
    # get cleaned up as part of cleaning up this file.
    b.create_agent_secrets(opts.zk_agent_digest)
    b.create_service_account('dcos_checks_agent', superuser=True)


def dcos_checks_agent(b, opts):
    b.read_agent_secrets()

    svc_acc_creds_fn = opts.rundir + '/etc/dcos-checks/checks_service_account.json'
    b.write_service_account_credentials('dcos_checks_agent', svc_acc_creds_fn)
    shutil.chown(svc_acc_creds_fn, user='dcos_diagnostics')


def dcos_history(b, opts):
    b.create_master_secrets()

    b.create_service_account('dcos_history_service', superuser=True)

    svc_acc_creds_fn = opts.rundir + '/etc/history-service/service_account.json'
    b.write_service_account_credentials('dcos_history_service', svc_acc_creds_fn)
    shutil.chown(svc_acc_creds_fn, user='dcos_history')

    b.write_CA_trust_bundle()

    os.makedirs(opts.statedir + '/dcos-history', exist_ok=True)
    shutil.chown(opts.statedir + '/dcos-history', user='dcos_history')


service_bootstrap_functions = {
    'dcos-adminrouter': dcos_adminrouter,
    'dcos-adminrouter-agent': dcos_adminrouter_agent,
    'dcos-backup-master': dcos_backup_master,
    'dcos-bouncer': dcos_bouncer,
    'dcos-ca': dcos_ca,
    'dcos-cockroach': dcos_cockroach,
    'dcos-cosmos': dcos_cosmos,
    'dcos-diagnostics-agent': dcos_diagnostics_agent,
    'dcos-diagnostics-master': dcos_diagnostics_master,
    'dcos-checks-agent': dcos_checks_agent,
    'dcos-checks-master': dcos_checks_master,
    'dcos-history': dcos_history,
    'dcos-marathon': dcos_marathon,
    'dcos-mesos-slave': dcos_mesos_slave,
    'dcos-mesos-slave-public': dcos_mesos_slave_public,
    'dcos-mesos-dns': dcos_mesos_dns,
    'dcos-mesos-master': dcos_mesos_master,
    'dcos-metrics-agent': dcos_metrics_agent,
    'dcos-metrics-master': dcos_metrics_master,
    'dcos-metronome': dcos_metronome,
    'dcos-minuteman': (lambda b, opts: dcos_erlang_service('minuteman', b, opts)),
    'dcos-navstar': (lambda b, opts: dcos_erlang_service('navstar', b, opts)),
    'dcos-networking_api': (lambda b, opts: dcos_erlang_service('networking_api', b, opts)),
    'dcos-secrets': dcos_secrets,
    'dcos-signal': dcos_signal,
    'dcos-spartan': dcos_spartan,
    'dcos-vault_default': dcos_vault_default
}
