import json
import os
import sys

from typing import List, Optional

import pkg_resources
import yaml

from cli import dcoscli_fixture

from pkgpanda.util import load_yaml, logger
from test_util import test_upgrade_vpc
from test_util.dcos_api_session import DcosApiSession, DcosUser
from test_util.helpers import session_tempfile


def token(host):
    cli = dcoscli_fixture()
    cli.exec_command(
        ["dcos", "config", "set", "core.dcos_url", host.public_ip])

    cli.exec_command(["dcos", "config", "set", "core.ssl_verify", "False"])

    stdout, stderr = cli.exec_command(["dcos", "auth", "login", "--username=testadmin",
                                       "--password=testpassword"])

    auth_stdout, stderr = cli.exec_command(
        ["dcos", "config", "show", "core.dcos_acs_token"])
    if stderr == '':
        auth_token = auth_stdout.strip('\n')
        return auth_token

    return None


def add_detect_ip_public_contents_to_yaml(yaml_file_path: Optional[str]) -> Optional[str]:
    """Create a new file and add the property `ip_detect_public_contents` with the contents of ip-detect/aws_public.sh
    :param yaml_file_path: file to start from
    :return: file path the newly created file with the additional ip_detect_public_contents property
    """
    if yaml_file_path is None:
        doc = {}
    else:
        doc = load_yaml(yaml_file_path)
    doc['ip_detect_public_contents'] = yaml.dump(pkg_resources.resource_string('gen', 'ip-detect/aws_public.sh')
                                                 .decode('utf-8'))
    yaml_str = yaml.safe_dump(doc)
    yaml_bytes = yaml_str.encode('utf-8')
    return session_tempfile(yaml_bytes)


def load_config(filepath: Optional[str]) -> dict:
    if filepath is None:
        return {}
    return load_yaml(filepath)


class EEVpcClusterUpgradeTest(test_upgrade_vpc.VpcClusterUpgradeTest):

    def mesos_metrics_snapshot(self, cluster, host):
        if host in cluster.masters:
            port = 5050
        else:
            port = 5051

        if self.acs_token is None:
            self.acs_token = token(host)

        with cluster.ssher.tunnel(host) as tunnel:
            security = self.dcos_api_session_factory_upgrade.config['security']
            protocol = "https"

            if security == 'disabled':
                protocol = "http"

            return json.loads(
                tunnel.remote_cmd(
                    test_upgrade_vpc.curl_cmd + ['--cacert /run/dcos/pki/CA/certs/ca.crt',
                                                 '-H "Authorization: token={}"'.format(self.acs_token),
                                                 '{}://{}:{}/metrics/snapshot'.format(protocol, host.private_ip, port)]
                ).decode('utf-8')
            )


class EEDcosApiSessionFactory(test_upgrade_vpc.VpcClusterUpgradeTestDcosApiSessionFactory):
    def __init__(self, config: dict):
        self.config = config

    def apply(self, dcos_url: str, masters: List[str], slaves: List[str],
              public_slaves: List[str], default_os_user: str) -> DcosApiSession:
        uid = os.environ['TEST_ADD_ENV_DCOS_LOGIN_UNAME']
        password = os.environ['TEST_ADD_ENV_DCOS_LOGIN_PW']
        auth_json = {'uid': uid, 'password': password}
        superuser = DcosUser(auth_json)

        # here we're abusing some pre-existing config knowledge that by default strict and permissive mode
        # requires ssl for admin router access.
        # Ideally we'd be able to resolve a full config object from the config yaml passed in, and evaluate
        # ssl enabled-ness on it's own.
        security = self.config['security']
        if security == 'strict' or security == 'permissive':
            url = dcos_url.replace('http', 'https')
            os_user = 'nobody'
            logger.normal('Attempt to get CA bundle via CA HTTP API')
            dcos_api = DcosApiSession(url, masters, slaves, public_slaves,
                                      os_user, superuser)
            r = dcos_api.post('ca/api/v2/info', json={'profile': ''}, verify=False)

            assert r.status_code == 200
            data = r.json()
            crt = data['result']['certificate']
            ca_cert_path = session_tempfile(crt.encode())
            dcos_api.session.verify = ca_cert_path  # eww object mutation :(
            return dcos_api
        else:
            return DcosApiSession(dcos_url, masters, slaves, public_slaves, default_os_user,
                                  superuser)


if __name__ == '__main__':

    num_masters = int(os.getenv('MASTERS', '3'))
    num_agents = int(os.getenv('AGENTS', '2'))
    num_public_agents = int(os.getenv('PUBLIC_AGENTS', '1'))

    stable_installer_url = os.environ['STABLE_INSTALLER_URL']
    installer_url = os.environ['INSTALLER_URL']
    aws_region = os.getenv('DEFAULT_AWS_REGION', 'eu-central-1')
    aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')

    config_yaml_override_install = add_detect_ip_public_contents_to_yaml(os.getenv('CONFIG_YAML_OVERRIDE_INSTALL'))
    config_yaml_override_upgrade = add_detect_ip_public_contents_to_yaml(os.getenv('CONFIG_YAML_OVERRIDE_UPGRADE'))

    install_config = load_config(config_yaml_override_install)
    upgrade_config = load_config(config_yaml_override_upgrade)

    test = EEVpcClusterUpgradeTest(num_masters, num_agents, num_public_agents,
                                   stable_installer_url, installer_url,
                                   aws_region, aws_access_key_id, aws_secret_access_key,
                                   "root",
                                   config_yaml_override_install, config_yaml_override_upgrade,
                                   EEDcosApiSessionFactory(install_config),
                                   EEDcosApiSessionFactory(upgrade_config))
    status = test.run_test()

    sys.exit(status)
