import logging
import os
import stat
# temporary measure until we have time to switch to docker
import subprocess


from kazoo.client import KazooClient
from kazoo.client import KazooRetry
from kazoo.security import Permissions, ANYONE_ID_UNSAFE
from kazoo.security import make_digest_acl_credential
from requests.packages.urllib3.util import Retry
from requests.adapters import HTTPAdapter
from requests import Session


from dcos_internal_utils import bootstrap
from dcos_internal_utils import utils


logging.basicConfig(format='[%(levelname)s] %(message)s', level='INFO')
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class TestBootstrap():
    def setup_class(self):
        self.tmpdir = os.path.abspath('tmp')
        os.makedirs(self.tmpdir, exist_ok=True)

        self.iam_url = 'http://127.0.0.1:8101'
        self.ca_url = 'http://127.0.0.1:8888'

        # TODO use a docker container instead
        # clean out zookeeper to get of all ACLs
        subprocess.check_call(["sudo", "systemctl", "stop", "zookeeper"])

        subprocess.check_call(["sudo", "rm", "-rf", "/var/lib/zookeeper/data"])
        subprocess.check_call(["sudo", "mkdir", "-p", "/var/lib/zookeeper/data"])
        subprocess.check_call(["sudo", "chown", "zookeeper.zookeeper", "/var/lib/zookeeper/data"])

        subprocess.check_call(["sudo", "rm", "-rf", "/var/lib/zookeeper/log"])
        subprocess.check_call(["sudo", "mkdir", "-p", "/var/lib/zookeeper/log"])
        subprocess.check_call(["sudo", "chown", "zookeeper.zookeeper", "/var/lib/zookeeper/log"])

        subprocess.check_call(["sudo", "systemctl", "start", "zookeeper"])

        subprocess.call(["docker", "rm", "-f", "bouncer"])
        subprocess.call(["docker", "rm", "-f", "dcos-ca"])

        self.zk_hosts = '127.0.0.1:2181'

        conn_retry_policy = KazooRetry(max_tries=-1, delay=0.1, max_delay=0.1)
        cmd_retry_policy = KazooRetry(max_tries=3, delay=0.3, backoff=1, max_delay=1, ignore_expire=False)
        zk = KazooClient(hosts=self.zk_hosts, connection_retry=conn_retry_policy, command_retry=cmd_retry_policy)
        zk.start()
        zk.add_auth('digest', 'super:secret')

        children = zk.get_children('/')
        for child in children:
            if child == 'zookeeper':
                continue
            zk.delete('/' + child, recursive=True)
        self.super_zk = zk

        zk = KazooClient(hosts=self.zk_hosts, connection_retry=conn_retry_policy, command_retry=cmd_retry_policy)
        zk.start()
        self.zk = zk

    def teardown_class(self):
        self.zk.stop()
        self.zk.close()
        self.super_zk.stop()
        self.super_zk.close()

        subprocess.call(["docker", "rm", "-f", "dcos-ca"])
        subprocess.call(["docker", "rm", "-f", "bouncer"])
        subprocess.check_call(["sudo", "systemctl", "stop", "zookeeper"])

    def test_generate_CA_key_certificate(self):
        key, crt = utils.generate_CA_key_certificate(1)

    def test_bootstrap(self):
        super_creds = 'super:secret'

        master_user = 'dcos_master'
        master_pass1 = 'secret'
        master_pass2 = 'sectet2'

        agentuser = 'dcos_agent'
        agentpass1 = 'secret'
        agentpass2 = 'secret2'

        b = bootstrap.Bootstrapper(self.zk_hosts, super_creds, self.iam_url, self.ca_url)

        b.init_acls()

        # TODO https://mesosphere.atlassian.net/browse/DCOS-8189
        #acls, st = self.zk.get_acls('/')
        #assert len(acls) == 1
        #assert acls[0].perms == Permissions.CREATE | Permissions.READ
        #assert acls[0].id == ANYONE_ID_UNSAFE

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

        b.mesos_acls()
        b.marathon_acls()
        b.cosmos_acls()
        b.bouncer_acls()
        b.dcos_ca_acls()
        b.dcos_secrets_acls()
        b.dcos_vault_default_acls()

        try:
            os.remove(self.tmpdir + '/cluster-id')
        except FileNotFoundError:
            pass

        id1 = b.cluster_id(self.tmpdir + '/cluster-id')
        # repeat to test reading from file
        id2 = b.cluster_id(self.tmpdir + '/cluster-id')
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

        b.create_service_account('dcos_adminrouter')
        # test exist_ok=True
        b.create_service_account('dcos_adminrouter')

        b.create_service_account('dcos_agent')
        b.create_service_account('dcos_foo', zk_secret=False)

        b.write_bouncer_env(self.tmpdir + '/bouncer.env')
        b.write_vault_default_env(self.tmpdir + '/dcos-vault_default.env')
        b.write_secrets_env(self.tmpdir + '/dcos-secrets.env')
        b.write_mesos_master_env(self.tmpdir + '/mesos-master.env')

        b.write_service_auth_token('dcos_adminrouter', self.tmpdir + '/adminrouter.env', exp=0)

        ca_fn = self.tmpdir + '/ca.crt'
        b.write_CA_certificate(ca_fn)
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
        b.write_key_certificate('common name', key_fn, crt_fn, extra_san=['foo'])
        assert os.stat(key_fn)[stat.ST_MODE] == 0o100600

        key_fn = self.tmpdir + '/svc2.key'
        crt_fn = self.tmpdir + '/svc2.crt'
        b.write_key_certificate('common name', key_fn, crt_fn, extra_san=['foo'], key_mode=0o644)
        assert os.stat(key_fn)[stat.ST_MODE] == 0o100644

        b.write_marathon_env(key_fn, crt_fn, ca_fn, self.tmpdir + '/marathon.env')
        b.write_metronome_env(key_fn, crt_fn, ca_fn, self.tmpdir + '/metronome.env')
        b.write_cosmos_env(key_fn, crt_fn, ca_fn, self.tmpdir + '/cosmos.env')

        b.create_agent_service_accounts()

        # test agent mode
        b.secrets = {}
        b.write_CA_certificate(self.tmpdir + '/ca2.crt')

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
