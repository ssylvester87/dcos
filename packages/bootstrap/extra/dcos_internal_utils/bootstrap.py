import json
import logging
import os
import shutil
import stat
import subprocess
import uuid


import kazoo.exceptions
from kazoo.client import KazooClient
from kazoo.retry import KazooRetry
from kazoo.security import ACL, ANYONE_ID_UNSAFE, Permissions
from kazoo.security import make_acl, make_digest_acl


from dcos_internal_utils import ca
from dcos_internal_utils import iam
from dcos_internal_utils import utils

log = logging.getLogger(__name__)


ANYONE_CR = [ACL(Permissions.CREATE | Permissions.READ, ANYONE_ID_UNSAFE)]
ANYONE_READ = [ACL(Permissions.READ, ANYONE_ID_UNSAFE)]
ANYONE_ALL = [ACL(Permissions.ALL, ANYONE_ID_UNSAFE)]
LOCALHOST_ALL = [make_acl('ip', '127.0.0.1', all=True)]


class Bootstrapper(object):
    def __init__(self, zk_hosts, zk_creds, iam_url, ca_url):
        conn_retry_policy = KazooRetry(max_tries=-1, delay=0.1, max_delay=0.1)
        cmd_retry_policy = KazooRetry(max_tries=3, delay=0.3, backoff=1, max_delay=1, ignore_expire=False)
        zk = KazooClient(hosts=zk_hosts, connection_retry=conn_retry_policy, command_retry=cmd_retry_policy)
        zk.start()
        if zk_creds:
            zk.add_auth('digest', zk_creds)
        self.zk = zk

        self.iam_url = iam_url
        self.ca_url = ca_url
        self.secrets = {}

        self.CA_certificate = None
        self.CA_certificate_filename = None

        # TODO(adam): Only include agent_public or agent, not both.
        self.agent_services = [
            'dcos_agent',
            'dcos_mesos_agent',
            'dcos_mesos_agent_public',
            'dcos_adminrouter_agent',
            'dcos_3dt_agent',
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

    def cluster_id(self, path='/var/lib/dcos/cluster-id'):
        dirpath = os.path.dirname(os.path.abspath(path))
        log.info('Opening {} for locking'.format(dirpath))
        with utils.Directory(dirpath) as d:
            log.info('Taking exclusive lock on {}'.format(dirpath))
            with d.lock():
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

    def init_acls(self):
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
            self.ensure_path(path, acl=acl)

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

            self.ensure_path(basepath, acl=acl)

            path = '/'.join([basepath, k])
            js = bytes(json.dumps(v), 'ascii')
            js = self._consensus(path, js, acl)
            secrets[k] = json.loads(js.decode('ascii'))

            # set ACLs again in case znode already existed but
            # with outdated ACLs
            self.zk.set_acls(path, acl)

        return secrets

    def write_CA_key(self, filename):
        key = self.secrets['CA']['RootCA']['key']
        key = key.encode('ascii')
        log.info('Writing root CA key to {}'.format(filename))
        _write_file(filename, key, 0o600)
        return key

    def write_CA_certificate(self, filename='/run/dcos/pki/CA/certs/ca.crt'):
        """"
        CA_certificate on the masters will happen after
        consensus has been reached about the master secrets,
        which include the root CA key and certificate
        """
        if 'CA' in self.secrets:
            crt = self.secrets['CA']['RootCA']['certificate']
            crt = crt.encode('ascii')
        else:
            # consensus value will only be read
            crt = None

        crt = self._consensus('/dcos/RootCA', crt, ANYONE_READ)

        log.info('Writing root CA certificate to {}'.format(filename))
        _write_file(filename, crt, 0o644)

        self.CA_certificate = crt
        self.CA_certificate_filename = filename

        return crt

    def create_master_secrets(self, creds):
        user, password = creds.split(':', 1)
        acl = [make_digest_acl(user, password, read=True)]

        log.info('Creating master secrets with user {}'.format(user))

        service_account_zk_creds = [
            'dcos_mesos_master',
            'dcos_marathon',
            'dcos_metronome',
            'dcos_cosmos',
            'dcos_bouncer',
            'dcos_ca',
            'dcos_secrets',
            'dcos_vault_default']

        zk_creds = {}

        for account in service_account_zk_creds:
            zk_creds[account] = {'scheme': 'digest', 'username': account, 'password': utils.random_string(64)}

        master_service_accounts = [
            'dcos_adminrouter',
            'dcos_history_service',
            'dcos_marathon',
            'dcos_metronome',
            'dcos_minuteman_master',
            'dcos_navstar_master',
            'dcos_spartan_master',
            'dcos_networking_api_master',
            'dcos_signal_service',
            'dcos_mesos_dns',
            'dcos_3dt_master'
        ]

        service_account_creds = {}

        for account in master_service_accounts:
            service_account_creds[account] = {
                'scheme': 'RS256',
                'uid': account,
                'private_key': utils.generate_RSA_keypair(2048)[0]}

        ca_key, ca_crt = utils.generate_CA_key_certificate(3650)
        ca_certs = {
            'RootCA': {
                'key': ca_key,
                'certificate': ca_crt,
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

    def create_agent_secrets(self, digest):
        acl = [make_acl('digest', digest, read=True)]

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

    def read_3dt_agent_secrets(self):
        path = '/dcos/agent/secrets/services/dcos_3dt_agent'
        js = self._consensus(path, None)
        self.secrets['services'] = {
            'dcos_3dt_agent': json.loads(js.decode('ascii'))
        }
        return self.secrets

    def write_service_account_credentials(self, uid, filename):
        creds = self.secrets['services'][uid].copy()

        # hacks for mesos-dns
        creds['secret'] = creds['private_key']
        creds['login_endpoint'] = self.iam_url + '/acs/api/v1/auth/login'

        creds = bytes(json.dumps(creds), 'ascii')

        log.info('Writing {} service account credentials to {}'.format(uid, filename))
        _write_file(filename, creds, 0o600)

    def write_private_key(self, name, filename):
        private_key = self.secrets['private_keys'][name]
        private_key = bytes(private_key, 'ascii')
        log.info('Writing {} private key to {}'.format(name, filename))
        _write_file(filename, private_key, 0o600)

    def create_service_account(self, uid, zk_secret=True, secret_path=None):
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

        iamcli = iam.IAMClient(self.iam_url, self.CA_certificate_filename)
        iamcli.create_service_account(uid, public_key=pubkey_pem, exist_ok=True)

        # TODO if account already exists, verify that public key matches

        # TODO set up groups and acls, then verify permissions

        # TODO temporary hack to get going
        iamcli.add_user_to_group(uid, 'superusers')

        return account

    def create_agent_service_accounts(self):
        for svc in self.agent_services:
            self.create_service_account(svc)

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

    def ensure_path(self, path, acl=None):
        log.info('ensure_path({}, {})'.format(path, acl))
        self.zk.ensure_path(path, acl=acl)
        self.zk.set_acls(path, acl)

    def mesos_acls(self):
        acl = ANYONE_READ + LOCALHOST_ALL + [self.make_service_acl('dcos_mesos_master', all=True)]
        self.ensure_path('/mesos', acl=acl)

    def marathon_acls(self):
        acl = ANYONE_READ + LOCALHOST_ALL + [self.make_service_acl('dcos_marathon', all=True)]
        self.ensure_path('/marathon', acl=acl)

    def metronome_acls(self):
        acl = ANYONE_READ + LOCALHOST_ALL + [self.make_service_acl('dcos_metronome', all=True)]
        self.ensure_path('/metronome', acl=acl)

    def cosmos_acls(self):
        acl = ANYONE_READ + LOCALHOST_ALL + [self.make_service_acl('dcos_cosmos', all=True)]
        self.ensure_path('/cosmos', acl=acl)

    def bouncer_acls(self):
        acl = LOCALHOST_ALL + [self.make_service_acl('dcos_bouncer', all=True)]
        self.ensure_path('/bouncer', acl=acl)

    def dcos_ca_acls(self):
        acl = LOCALHOST_ALL + [self.make_service_acl('dcos_ca', all=True)]
        self.ensure_path('/dcos/ca', acl=acl)

    def dcos_secrets_acls(self):
        acl = LOCALHOST_ALL + [self.make_service_acl('dcos_secrets', all=True)]
        self.ensure_path('/dcos/secrets', acl=acl)

    def dcos_vault_default_acls(self):
        acl = LOCALHOST_ALL + [self.make_service_acl('dcos_vault_default', all=True)]
        self.ensure_path('/dcos/vault/default', acl=acl)

    def write_dcos_ca_creds(self, src, dst):
        zk_creds = self.secrets['zk']['dcos_ca']
        with open(src, 'rb') as fh:
            ca_conf = json.loads(fh.read().decode('utf-8'))
        assert 'data_source' in ca_conf
        assert ca_conf['data_source'][:5] == 'file:'
        ca_conf['data_source'] = 'file:{}:{}@{}'.format(zk_creds['username'],
                                                        zk_creds['password'],
                                                        ca_conf['data_source'][5:]
                                                        )
        blob = json.dumps(ca_conf, sort_keys=True, indent=True,
                          ensure_ascii=False).encode('utf-8')
        _write_file(dst, blob, 0o600)

    def write_bouncer_env(self, filename):
        zk_creds = self.secrets['zk']['dcos_bouncer']
        env = 'DATASTORE_ZK_USER={username}\nDATASTORE_ZK_SECRET={password}\n'
        env = bytes(env.format_map(zk_creds), 'ascii')

        log.info('Writing Bouncer ZK credentials to {}'.format(filename))
        _write_file(filename, env, 0o600)

    def write_vault_default_env(self, filename):
        zk_creds = self.secrets['zk']['dcos_vault_default']
        user = zk_creds['username']
        pw = zk_creds['password']

        acl = make_digest_acl(user, pw, all=True)

        env = 'VAULT_AUTH_INFO=digest:{}:{}\nVAULT_ZNODE_OWNER=digest:{}\n'
        env = env.format(user, pw, acl.id.id)
        env = bytes(env, 'ascii')

        log.info('Writing Vault ZK credentials to {}'.format(filename))
        _write_file(filename, env, 0o600)

    def write_secrets_env(self, filename):
        zk_creds = self.secrets['zk']['dcos_secrets']
        user = zk_creds['username']
        pw = zk_creds['password']

        acl = make_digest_acl(user, pw, all=True)

        env = 'SECRETS_AUTH_INFO=digest:{}:{}\nSECRETS_ZNODE_OWNER=digest:{}\n'
        env = env.format(user, pw, acl.id.id)
        env = bytes(env, 'ascii')

        log.info('Writing Secrets ZK credentials to {}'.format(filename))
        _write_file(filename, env, 0o600)

    def write_mesos_master_env(self, filename):
        zk_creds = self.secrets['zk']['dcos_mesos_master']

        env = 'MESOS_ZK=zk://{username}:{password}@127.0.0.1:2181/mesos\n'
        env = env.format_map(zk_creds)
        env = bytes(env, 'ascii')

        log.info('Writing Mesos Master ZK credentials to {}'.format(filename))
        _write_file(filename, env, 0o600)

    def write_cosmos_env(self, key_fn, crt_fn, ca_fn, env_fn):
        zk_creds = self.secrets['zk']['dcos_cosmos']
        env = 'ZOOKEEPER_USER={username}\nZOOKEEPER_SECRET={password}\n'
        env = env.format_map(zk_creds)
        env = bytes(env, 'ascii')

        log.info('Writing Cosmos environment to {}'.format(env_fn))
        _write_file(env_fn, env, 0o600)

    def write_metronome_env(self, key_fn, crt_fn, ca_fn, env_fn):
        pfx_fn = os.path.splitext(key_fn)[0] + '.pfx'
        jks_fn = os.path.splitext(key_fn)[0] + '.jks'

        try:
            os.remove(jks_fn)
        except OSError:
            pass

        zk_creds = self.secrets['zk']['dcos_metronome']
        env1 = 'METRONOME_ZK_URL=zk://{username}:{password}@127.0.0.1:2181/metronome\n'
        env1 = env1.format_map(zk_creds)

        keystore_password = utils.random_string(64)
        env2 = 'METRONOME_PLAY_SERVER_HTTPS_KEYSTORE_PASSWORD={keystore_password}\n'
        env2 = env2.format(keystore_password=keystore_password)

        env = bytes(env1 + env2, 'ascii')

        log.info('Writing Metronome environment to {}'.format(env_fn))
        _write_file(env_fn, env, 0o600)

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

    def write_history_service_env(self, ca_fn, env_fn):
        env = 'STATE_SUMMARY_URI=https://leader.mesos/mesos/state-summary\n' \
            'TLS_VERIFY={ca_fn}\n'
        env = env.format(ca_fn=ca_fn)
        env = bytes(env, 'ascii')

        log.info('Writing History Service environment to {}'.format(env_fn))
        _write_file(env_fn, env, 0o600)

    def write_marathon_env(self, key_fn, crt_fn, ca_fn, env_fn):
        pfx_fn = os.path.splitext(key_fn)[0] + '.pfx'
        jks_fn = os.path.splitext(key_fn)[0] + '.jks'

        try:
            os.remove(jks_fn)
        except OSError:
            pass

        zk_creds = self.secrets['zk']['dcos_marathon']
        env1 = 'MARATHON_ZK=zk://{username}:{password}@127.0.0.1:2181/marathon\n'
        env1 = env1.format_map(zk_creds)

        password = utils.random_string(256)
        env2 = 'SSL_KEYSTORE_PASSWORD={}\n'.format(password)

        env = bytes(env1 + env2, 'ascii')

        _write_file(env_fn, env, 0o600)

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

    def write_truststore(self, ts_fn, ca_fn):
        keytool = shutil.which('keytool')
        if not keytool:
            raise Exception('keytool not found')

        try:
            os.remove(ts_fn)
        except OSError:
            pass

        cmd = [
            keytool,
            '-importkeystore',
            '-noprompt',
            '-srckeystore',
            '/opt/mesosphere/active/java/usr/java/jre/lib/security/cacerts',
            '-srcstorepass', 'changeit',
            '-deststorepass', 'changeit',
            '-destkeystore', ts_fn
        ]
        log.info('Copying system TrustStore: {}'.format(' '.join(cmd)))
        proc = subprocess.Popen(cmd, shell=False, preexec_fn=_set_umask)
        if proc.wait() != 0:
            raise Exception('keytool failed')

        cmd = [
            keytool,
            '-import',
            '-noprompt',
            '-trustcacerts',
            '-alias', 'dcos_root_ca',
            '-file', ca_fn,
            '-keystore', ts_fn,
            '-storepass', 'changeit',
        ]
        log.info('Importing CA into TrustStore: {}'.format(' '.join(cmd)))
        proc = subprocess.Popen(cmd, shell=False, preexec_fn=_set_umask)
        if proc.wait() != 0:
            raise Exception('keytool failed')

    def service_auth_token(self, uid, exp=None):
        iam_cli = iam.IAMClient(self.iam_url, self.CA_certificate_filename)
        acc = self.secrets['services'][uid]
        log.info('Service account login as service {}'.format(uid))
        token = iam_cli.service_account_login(uid, private_key=acc['private_key'], exp=exp)
        return token

    def write_service_auth_token(self, uid, filename=None, exp=None):
        token = self.service_auth_token(uid, exp)
        env = bytes('SERVICE_AUTH_TOKEN={}\n'.format(token), 'ascii')
        _write_file(filename, env, 0o600)
        return token

    def write_key_certificate(self, cn, key_filename, crt_filename, service_account=None,
                              master=False, marathon=False, extra_san=[], key_mode=0o600):
        log.info('Generating CSR for key {}'.format(key_filename))
        privkey_pem, csr_pem = utils.generate_key_CSR(cn, master=master, marathon=marathon, extra_san=extra_san)

        headers = {}
        if service_account:
            token = self.service_auth_token(service_account)
            headers = {'Authorization': 'token=' + token}
        cacli = ca.CAClient(self.ca_url, headers, self.CA_certificate_filename)

        log.info('Signing CSR at {} with service account {}'.format(self.ca_url, service_account))
        crt = cacli.sign(csr_pem)

        _write_file(key_filename, bytes(privkey_pem, 'ascii'), key_mode)
        _write_file(crt_filename, bytes(crt, 'ascii'), 0o644)

    def write_jwks_public_keys(self, filename):
        iamcli = iam.IAMClient(self.iam_url, self.CA_certificate_filename)
        jwks = iamcli.jwks()
        output = utils.jwks_to_public_keys(jwks)
        _write_file(filename, bytes(output, 'ascii'), 0o644)


def _write_file(path, data, mode):
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
