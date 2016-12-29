import logging
import os

from ee_helpers import bootstrap_config

from test_util.cluster_api import ClusterApi, get_args_from_env
from test_util.helpers import DcosUser, session_tempfile


class EnterpriseClusterApi(ClusterApi):
    @property
    def iam(self):
        return self.get_client('acs/api/v1')

    @property
    def secrets(self):
        return self.get_client('secrets/v1')

    @property
    def ca(self):
        return self.get_client('ca/api/v2')


def make_session_fixture():
    cluster_args = get_args_from_env()
    # make superuser for this cluster
    uid = os.environ['DCOS_LOGIN_UNAME']
    password = os.environ['DCOS_LOGIN_PW']
    auth_json = {'uid': uid, 'password': password}
    superuser = DcosUser(auth_json)
    superuser.uid = uid
    superuser.password = password
    cluster_args['web_auth_default_user'] = superuser

    if bootstrap_config['ssl_enabled']:
        cluster_args['dcos_url'] = cluster_args['dcos_url'].replace('http', 'https')

    if bootstrap_config['security'] == 'strict':
        cluster_args['default_os_user'] = 'nobody'

    cluster_api = EnterpriseClusterApi(**cluster_args)

    # If SSL enabled and no CA cert is given, then grab it
    if bootstrap_config['ssl_enabled'] and not cluster_args['ca_cert_path']:
        logging.info('Attempt to get CA bundle via CA HTTP API')
        r = cluster_api.post('ca/api/v2/info', json={'profile': ''}, verify=False)

        assert r.status_code == 200
        data = r.json()
        crt = data['result']['certificate']
        ca_cert_path = session_tempfile(crt.encode())
        cluster_api.ca_cert_path = ca_cert_path

    cluster_api.wait_for_dcos()

    # Set RIDs
    cluster_api.initial_resource_ids = []
    r = cluster_api.iam.get('/acls')
    for o in r.json()['array']:
        cluster_api.initial_resource_ids.append(o['rid'])

    return cluster_api
