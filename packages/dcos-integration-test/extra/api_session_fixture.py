import logging
import os

from ee_helpers import bootstrap_config

from test_util.dcos_api_session import DcosApiSession, DcosUser, get_args_from_env
from test_util.helpers import session_tempfile


class EnterpriseApiSession(DcosApiSession):
    @property
    def iam(self):
        new = self.copy()
        new.default_url = self.default_url.copy(path='acs/api/v1')
        return new

    @property
    def secrets(self):
        new = self.copy()
        new.default_url = self.default_url.copy(path='secrets/v1')
        return new

    @property
    def ca(self):
        new = self.copy()
        new.default_url = self.default_url.copy(path='ca/api/v2')
        return new


def make_session_fixture():
    cluster_args = get_args_from_env()
    # make superuser for this cluster
    uid = os.environ['DCOS_LOGIN_UNAME']
    password = os.environ['DCOS_LOGIN_PW']
    auth_json = {'uid': uid, 'password': password}
    superuser = DcosUser(auth_json)
    superuser.uid = uid
    superuser.password = password
    cluster_args['auth_user'] = superuser

    if bootstrap_config['ssl_enabled']:
        cluster_args['dcos_url'] = cluster_args['dcos_url'].replace('http', 'https')

    if bootstrap_config['security'] == 'strict':
        cluster_args['default_os_user'] = 'nobody'

    cluster_api = EnterpriseApiSession(**cluster_args)

    # If SSL enabled and no CA cert is given, then grab it
    if bootstrap_config['ssl_enabled']:
        logging.info('Attempt to get CA bundle via CA HTTP API')
        r = cluster_api.post('ca/api/v2/info', json={'profile': ''}, verify=False)

        assert r.status_code == 200
        data = r.json()
        crt = data['result']['certificate']
        cluster_api.session.verify = session_tempfile(crt.encode())

    cluster_api.wait_for_dcos()

    # Set RIDs
    cluster_api.initial_resource_ids = []
    r = cluster_api.iam.get('/acls')
    for o in r.json()['array']:
        cluster_api.initial_resource_ids.append(o['rid'])

    return cluster_api
