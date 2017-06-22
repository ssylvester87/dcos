import hashlib
import logging
import os
import shutil
import stat
# temporary measure until we have time to switch to docker
import subprocess
from base64 import b64encode

import pytest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from kazoo.client import KazooClient
from kazoo.client import KazooRetry
# from kazoo.security import Permissions, ANYONE_ID_UNSAFE
from kazoo.security import make_digest_acl_credential
from requests import Session
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util import Retry

from dcos_internal_utils import bootstrap
from dcos_internal_utils import utils


logging.basicConfig(format='[%(levelname)s] %(message)s', level='INFO')
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


# TODO test might be leaking fds (based on logs)


def calculate_digest(credentials):
    username, password = credentials.split(':', 1)
    credential = username.encode('utf-8') + b":" + password.encode('utf-8')
    cred_hash = b64encode(hashlib.sha1(credential).digest()).strip()
    return username + ":" + cred_hash.decode('utf-8')


class TestContext:
    def __init__(self, security_level, zk_hosts, super_creds, zk, super_zk):
        self.security_level = security_level
        self.zk_hosts = zk_hosts
        self.super_creds = super_creds
        self.zk = zk
        self.super_zk = super_zk

        s = Session()
        retry = Retry(total=10, backoff_factor=0.1, status_forcelist=[500])
        s.mount('http://', HTTPAdapter(max_retries=retry))
        self.session = s

    def opts(self, services):
        # rundir = os.path.abspath('tmp/run/dcos')
        # statedir = os.path.abspath('tmp/var/lib/dcos')
        rundir = os.path.abspath('/run/dcos')
        statedir = os.path.abspath('/var/lib/dcos')

        args = [
            '--rundir=' + rundir,
            '--statedir=' + statedir,
            '--config-path=tests/' + self.security_level + '.json'
        ]
        args += services

        iam_url = 'http://127.0.0.1:8101'
        ca_url = 'http://127.0.0.1:8888'

        opts = bootstrap.parse_args(args, self.zk_hosts, iam_url, ca_url)

        # opts.bouncer_user = getpass.getuser()
        # opts.dcos_secrets_user = getpass.getuser()
        # opts.dcos_vault_user = getpass.getuser()
        # opts.dcos_ca_user = getpass.getuser()
        # opts.dcos_cosmos_user = getpass.getuser()

        if self.security_level == 'disabled':
            assert not opts.config['zk_acls_enabled']
        else:
            # TODO instead of doing this, write files are use parse_args in all its glory
            # override values typically read from files
            opts.zk_super_creds = self.super_creds
            opts.zk_master_creds = 'master_user:master_password'
            opts.zk_agent_creds = 'agent_user:agent_password'
            opts.zk_agent_digest = calculate_digest(opts.zk_agent_creds)
            assert opts.config['zk_acls_enabled']

        return opts


@pytest.fixture(scope="module", params=['disabled', 'permissive', 'strict'])
def testctx(request):
    zk_hosts = '127.0.0.1:2181'

    super_creds = 'super:secret'
    super_digest = calculate_digest(super_creds)
    zk_super_digest_jvmflags = "JVMFLAGS=-Dzookeeper.DigestAuthenticationProvider.superDigest=" + super_digest
    if request.param != 'disabled':
        with open("/opt/mesosphere/etc/exhibitor-extras", "w") as f:
            f.write(zk_super_digest_jvmflags)
    else:
        try:
            os.remove("/opt/mesosphere/etc/exhibitor-extras")
        except FileNotFoundError:
            pass

    # TODO only do this once per param
    subprocess.call(["systemctl", "stop", "dcos-exhibitor"])
    try:
        shutil.rmtree("/var/lib/dcos/exhibitor/zookeeper")
    except FileNotFoundError:
        pass
    subprocess.call(["systemctl", "start", "dcos-exhibitor"])

    conn_retry_policy = KazooRetry(max_tries=-1, delay=0.1, max_delay=0.1)
    cmd_retry_policy = KazooRetry(max_tries=3, delay=0.3, backoff=1, max_delay=1, ignore_expire=False)
    zk = KazooClient(hosts=zk_hosts, connection_retry=conn_retry_policy, command_retry=cmd_retry_policy)
    zk.start()
    if request.param != 'disabled':
        zk.add_auth('digest', super_creds)

    children = zk.get_children('/')
    for child in children:
        if child == 'zookeeper':
            continue
        zk.delete('/' + child, recursive=True)
    super_zk = zk

    zk = KazooClient(hosts=zk_hosts, connection_retry=conn_retry_policy, command_retry=cmd_retry_policy)
    zk.start()

    def fin():
        zk.stop()
        zk.close()
        super_zk.stop()
        super_zk.close()

    request.addfinalizer(fin)

    return TestContext(request.param, zk_hosts, super_creds, zk, super_zk)


def xsetup_class(self):
    self.tmpdir = os.path.abspath('tmp')
    os.makedirs(self.tmpdir, exist_ok=True)

    self.iam_url = 'http://127.0.0.1:8101'
    self.ca_url = 'http://127.0.0.1:8888'


def xteardown_class(self):
    self.zk.stop()
    self.zk.close()
    self.super_zk.stop()
    self.super_zk.close()


def xsetup_method(self, method):
    try:
        shutil.rmtree('tmp')
    except FileNotFoundError:
        pass


def xtest_generate_CA_key_certificate(self):
    key, crt = utils.generate_CA_key_certificate(1)


def test_make_run_dirs(testctx):
    opts = testctx.opts(services=['servicex'])
    try:
        shutil.rmtree(opts.rundir)
    except FileNotFoundError:
        pass
    bootstrap.make_run_dirs(opts)
    assert os.path.isdir(opts.rundir)
    assert os.path.isdir(opts.rundir + '/pki/tls/certs')


def test_dcos_bouncer(testctx):
    subprocess.call(["systemctl", "stop", "dcos-bouncer"])

    opts = testctx.opts(services=['dcos-bouncer'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_bouncer(b, opts)

    subprocess.call(["systemctl", "start", "dcos-bouncer"])

    r = testctx.session.get('http://127.0.0.1:8101/acs/api/v1/groups')
    r.raise_for_status()


def test_dcos_secrets(testctx):
    opts = testctx.opts(services=['dcos-secrets'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_secrets(b, opts)


def test_dcos_vault_default(testctx):
    opts = testctx.opts(services=['dcos-vault'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_vault_default(b, opts)


def test_dcos_ca(testctx):
    subprocess.call(["systemctl", "stop", "dcos-ca"])

    opts = testctx.opts(services=['dcos-ca'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_ca(b, opts)

    subprocess.call(["systemctl", "start", "dcos-ca"])

    r = testctx.session.post('http://127.0.0.1:8888/ca/api/v2/info', json={})
    r.raise_for_status()
    print(r.json())


def test_dcos_mesos_master(testctx):
    test_dcos_ca(testctx)
    test_dcos_bouncer(testctx)

    opts = testctx.opts(services=['dcos-mesos-master'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_mesos_master(b, opts)


def test_dcos_mesos_slave(testctx):
    test_dcos_ca(testctx)
    test_dcos_bouncer(testctx)
    test_dcos_mesos_master(testctx)

    opts = testctx.opts(services=['dcos-mesos-slave'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_mesos_slave(b, opts)


def test_dcos_mesos_slave_public(testctx):
    test_dcos_ca(testctx)
    test_dcos_bouncer(testctx)
    test_dcos_mesos_master(testctx)

    opts = testctx.opts(services=['dcos-mesos-slave-public'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_mesos_slave_public(b, opts)


def test_dcos_marathon(testctx):
    test_dcos_ca(testctx)
    test_dcos_bouncer(testctx)

    opts = testctx.opts(services=['dcos-marathon'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_marathon(b, opts)


def test_dcos_metronome(testctx):
    test_dcos_ca(testctx)
    test_dcos_bouncer(testctx)

    opts = testctx.opts(services=['dcos-metronome'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_metronome(b, opts)


def test_dcos_mesos_dns(testctx):
    test_dcos_ca(testctx)
    test_dcos_bouncer(testctx)

    opts = testctx.opts(services=['dcos-mesos-dns'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_mesos_dns(b, opts)


def test_dcos_adminrouter(testctx):
    test_dcos_ca(testctx)
    test_dcos_bouncer(testctx)

    opts = testctx.opts(services=['dcos-adminrouter'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_adminrouter(b, opts)


# TODO only run on agent machines
def xtest_dcos_adminrouter_agent(testctx):
    test_dcos_ca(testctx)
    test_dcos_bouncer(testctx)

    opts = testctx.opts(services=['dcos-adminrouter-agent'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)

    # this happens on the masters
    b.create_agent_secrets(opts.zk_agent_digest)

    bootstrap.dcos_adminrouter_agent(b, opts)


def xtest_dcos_spartan(self, config):
    pass


# TODO master & agent
def test_dcos_minuteman_master(testctx):
    test_dcos_ca(testctx)
    test_dcos_bouncer(testctx)

    opts = testctx.opts(services=['dcos-minuteman'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_erlang_service('minuteman', b, opts)


def xtest_dcos_navstar_master(self, config):
    pass


def test_dcos_networking_api(testctx):
    test_dcos_ca(testctx)
    test_dcos_bouncer(testctx)

    opts = testctx.opts(services=['dcos-networking_api'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_erlang_service('networking_api', b, opts)


def test_dcos_cosmos(testctx):
    test_dcos_ca(testctx)
    test_dcos_bouncer(testctx)

    opts = testctx.opts(services=['dcos-cosmos'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_cosmos(b, opts)


def test_dcos_signal(testctx):
    test_dcos_ca(testctx)
    test_dcos_bouncer(testctx)

    opts = testctx.opts(services=['dcos-signal'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_signal(b, opts)


def test_dcos_diagnostics_master(testctx):
    test_dcos_ca(testctx)
    test_dcos_bouncer(testctx)

    opts = testctx.opts(services=['dcos-diagnostics-master'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_diagnostics_master(b, opts)


def test_dcos_diagnostics_agent(testctx):
    test_dcos_ca(testctx)
    test_dcos_bouncer(testctx)

    opts = testctx.opts(services=['dcos-diagnostics-agent'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_diagnostics_agent(b, opts)


def test_dcos_history(testctx):
    test_dcos_ca(testctx)
    test_dcos_bouncer(testctx)

    opts = testctx.opts(services=['dcos-history'])
    bootstrap.make_run_dirs(opts)
    b = bootstrap.Bootstrapper(opts)
    bootstrap.dcos_history(b, opts)


def xtest_bootstrap_parts(self):
    master_user = 'dcos_master'
    master_pass1 = 'secret'
    master_pass2 = 'sectet2'

    agentuser = 'dcos_agent'
    agentpass1 = 'secret'
    agentpass2 = 'secret2'

    b = bootstrap.Bootstrapper(self.zk_hosts, self.super_creds, self.iam_url, self.ca_url)

    b.init_acls()

    # TODO https://mesosphere.atlassian.net/browse/DCOS-8189
    # acls, st = self.zk.get_acls('/')
    # assert len(acls) == 1
    # assert acls[0].perms == Permissions.CREATE | Permissions.READ
    # assert acls[0].id == ANYONE_ID_UNSAFE

    b.init_acls()

    master_creds = master_user + ':' + master_pass1
    secrets1 = b.create_master_secrets(master_creds)
    self.check_master_secrets(secrets1)

    # repeat with a different password to make sure
    # acls are updated after the node exists
    master_creds = master_user + ':' + master_pass2
    secrets2 = b.create_master_secrets(master_creds)

    assert secrets1 == secrets2

    agent_digest = make_digest_acl_credential(agentuser, agentpass1)
    secrets1 = b.create_agent_secrets(agent_digest)

    assert set(b.agent_services) == set(secrets1['services'].keys())

    # repeat with a different password to make sure
    # acls are updated after the node exists
    agent_digest = make_digest_acl_credential(agentuser, agentpass2)
    secrets2 = b.create_agent_secrets(agent_digest)

    assert secrets1 == secrets2

    b.mesos_zk_acls()
    b.marathon_zk_acls()
    b.cosmos_acls()
    b.bouncer_acls()
    b.dcos_ca_acls()
    b.dcos_secrets_acls()
    b.dcos_vault_default_acls()

    try:
        os.remove(self.tmpdir + '/cluster-id')
    except FileNotFoundError:
        pass

    id1 = b.cluster_id(path=self.tmpdir + '/cluster-id')
    # repeat to test reading from file
    id2 = b.cluster_id(path=self.tmpdir + '/cluster-id')
    assert id1 == id2

    bouncer_zk_user = b.secrets['zk']['dcos_bouncer']['username']
    bouncer_zk_pass = b.secrets['zk']['dcos_bouncer']['password']
    subprocess.check_call([
        "docker", "run", "-d", "--name=bouncer", "--net=host",
        "-v", "/home/albert/repos/bouncer:/usr/local/src/bouncer",
        "-e", "DATASTORE_ZK_USER=" + bouncer_zk_user,
        "-e", "DATASTORE_ZK_SECRET=" + bouncer_zk_pass,
        "mesosphere/bouncer-devkit:latest",
        "tools/run-gunicorn-testconfig.sh", "--ZK"
        ])

    s = Session()
    retry = Retry(total=10, backoff_factor=0.1, status_forcelist=[500])
    s.mount('http://', HTTPAdapter(max_retries=retry))
    r = s.get(self.iam_url)
    assert r.status_code == 404

    b.create_service_account('dcos_adminrouter', superuser=True)
    # test exist_ok=True
    b.create_service_account('dcos_adminrouter', superuser=True)

    b.create_service_account('dcos_agent', superuser=True)
    b.create_service_account('dcos_foo', superuser=False, zk_secret=False)

    b.write_bouncer_env(self.tmpdir + '/bouncer.env')
    b.write_vault_default_env(self.tmpdir + '/dcos-vault_default.env')
    b.write_secrets_env(self.tmpdir + '/dcos-secrets.env')
    b.write_mesos_master_env(self.tmpdir + '/mesos-master.env')

    b.write_service_auth_token('dcos_adminrouter', self.tmpdir + '/adminrouter.env', exp=0)

    # TODO(mh): Add bundle and new tests?
    ca_fn = self.tmpdir + '/ca.crt'
    b.write_CA_certificate(filename=ca_fn)
    b.write_CA_key(self.tmpdir + '/ca.key')

    subprocess.check_call([
        "docker", "run", "-d", "--name=dcos-ca", "--net=host",
        "-v", "/home/albert/repos/gopath/src/github.com/mesosphere/dcos-ca:/dcos-ca:ro",
        "-v", self.tmpdir + "/ca.crt:/opt/ca-config/ca.crt:ro",
        "-v", self.tmpdir + "/ca.key:/opt/ca-config/ca.key:ro",
        "mesosphere/dcos-ca-devkit:full",
        "/dcos-ca/dcos-ca",
        "-loglevel", "0",
        "serve",
        "-address=0.0.0.0", "-port=8888",
        "-ca", "/opt/ca-config/ca.crt",
        "-ca-key", "/opt/ca-config/ca.key",
        "-config", "/opt/ca-config/ca-config-noauth.json",
        "-db-config", "/opt/ca-config/ca-dbconfig.json"
        ])

    r = s.get(self.ca_url)
    assert r.status_code == 404

    key_fn = self.tmpdir + '/svc1.key'
    crt_fn = self.tmpdir + '/svc1.crt'
    b.ensure_key_certificate('common name', key_fn, crt_fn, extra_san=[utils.SanEntry('dns', 'foo')])
    assert os.stat(key_fn)[stat.ST_MODE] == 0o100600

    key_fn = self.tmpdir + '/svc2.key'
    crt_fn = self.tmpdir + '/svc2.crt'
    b.ensure_key_certificate('common name', key_fn, crt_fn, extra_san=[utils.SanEntry('dns', 'foo')], key_mode=0o644)
    assert os.stat(key_fn)[stat.ST_MODE] == 0o100644

    b.write_marathon_env(key_fn, crt_fn, ca_fn, self.tmpdir + '/marathon.env')
    b.write_metronome_env(key_fn, crt_fn, ca_fn, self.tmpdir + '/metronome.env')
    b.write_cosmos_env(key_fn, crt_fn, ca_fn, self.tmpdir + '/cosmos.env')

    b.create_agent_service_accounts()

    # test agent mode
    b.secrets = {}
    b.write_CA_certificate(filename=(self.tmpdir + '/ca2.crt'))

    b.write_jwks_public_keys(self.tmpdir + '/jwks.pub')


def check_master_secrets(self, secrets):
    assert 'zk' in secrets
    zk = secrets['zk']
    assert 'dcos_mesos_master' in zk
    assert 'dcos_marathon' in zk
    assert 'dcos_cosmos' in zk
    assert 'dcos_bouncer' in zk
    assert 'dcos_ca' in zk
    assert 'dcos_secrets' in zk
    assert 'dcos_vault_default' in zk
    assert 'services' in secrets
    services = secrets['services']
    assert 'dcos_adminrouter' in services
    assert 'dcos_history_service' in services
    assert 'dcos_marathon' in services
    assert 'dcos_minuteman_master' in services
    assert 'dcos_navstar_master' in services
    assert 'dcos_mesos_dns' in services


def xtest_if_certificates_are_not_overwritten(self, tmpdir):
    super_creds = 'super:secret'
    crtfile = tmpdir.join("tmp.crt")
    keyfile = tmpdir.join("tmp.key")
    assert not crtfile.check()
    assert not keyfile.check()
    b = bootstrap.Bootstrapper(self.zk_hosts, super_creds, self.iam_url, self.ca_url)
    b.ensure_key_certificate('some cert for testing if stuff is not overwritten', str(crtfile), str(keyfile))
    assert crtfile.check()
    assert keyfile.check()
    crt_digest = hashlib.sha256(crtfile.read()).hexdigest()
    key_digest = hashlib.sha256(keyfile.read()).hexdigest()
    b.ensure_key_certificate('some other cert for testing if stuff is not overwritten', str(crtfile), str(keyfile))
    assert crtfile.check()
    assert keyfile.check()
    new_crt_digest = hashlib.sha256(crtfile.read()).hexdigest()
    new_key_digest = hashlib.sha256(keyfile.read()).hexdigest()
    assert new_crt_digest == crt_digest
    assert new_key_digest == key_digest


def common_name_from_cert(filename):
    with open(filename, 'r') as file:
        pem_data = file.read().decode('ascii')
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    return cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME).value


def test_use_exact_dn_false(tmpdir, testctx):
    b = bootstrap.Bootstrapper()
    crtfile = tmpdir.join("tmp.crt")
    keyfile = tmpdir.join("tmp.key")
    b.ensure_key_certificate('tmp', str(crtfile), str(keyfile))
    assert common_name_from_cert(crtfile) == b'tmp on 127.0.0.1'


def test_use_exact_dn_true(tmpdir, testctx):
    b = bootstrap.Bootstrapper()
    crtfile = tmpdir.join("tmp.crt")
    keyfile = tmpdir.join("tmp.key")
    b.ensure_key_certificate('tmp', str(crtfile), str(keyfile))
    assert common_name_from_cert(crtfile) == b'tmp'
