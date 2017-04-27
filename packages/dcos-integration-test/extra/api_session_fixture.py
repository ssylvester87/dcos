import logging
import os

import iam_helper

from ee_helpers import bootstrap_config

from test_util.dcos_api_session import DcosApiSession, DcosUser
from test_util.helpers import session_tempfile


class MesosNodeClientMixin:
    """ This Mixin allows any request to be made against a master or agent
    mesos HTTP port by providing the keyword 'mesos_node'. Thus, the user
    does not have to specify the master/agent port or which arbitrary host
    in the cluster meeting that role
    """
    def api_request(self, method, path_extension, *, scheme=None, host=None, query=None,
                    fragment=None, port=None, mesos_node=None, **kwargs):
        if mesos_node is not None:
            assert port is None, 'Usage error: mesos_node keyword will set port'
            assert host is None, 'Usage error: mesos_node keyword will set host'
            if mesos_node == 'master':
                port = 5050
                host = self.masters[0]
            elif mesos_node == 'agent':
                port = 5051
                host = self.slaves[0]
            else:
                raise AssertionError('Mesos node type not recognized: {}'.format(mesos_node))
        return super().api_request(method, path_extension, scheme=scheme, host=host, query=query,
                                   fragment=fragment, port=port, **kwargs)


class EnterpriseApiSession(MesosNodeClientMixin, DcosApiSession):
    @property
    def iam(self):
        return iam_helper.Iam(self.default_url.copy(path='acs/api/v1'),
                              session=self.copy().session)

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
    cluster_args = DcosApiSession.get_args_from_env()
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
        logging.info('Attempt to get CA bundle via Admin Router')
        r = cluster_api.get('/ca/dcos-ca.crt', verify=False)
        assert r.status_code == 200
        cluster_api.session.verify = session_tempfile(r.content)

    cluster_api.wait_for_dcos()

    # Set RIDs
    cluster_api.initial_resource_ids = []
    r = cluster_api.iam.get('/acls')
    for o in r.json()['array']:
        cluster_api.initial_resource_ids.append(o['rid'])

    return cluster_api
