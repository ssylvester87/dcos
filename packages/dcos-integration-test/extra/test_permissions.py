"""
Test authorization behavior of various components.
Note: requests to the superuser_api_session fixture uses super by default
"""
import logging
import uuid

import ee_helpers

import pytest


log = logging.getLogger(__name__)

pytestmark = [pytest.mark.security]

AUTHENTICATED_USERS_ENDPOINTS = [
    '/capabilities',
    '/metadata',
    '/navstar/lashup/key']


@pytest.fixture
def set_user_permission(superuser_api_session):
    def set_permission(rid, uid, action):
        rid = rid.replace('/', '%252F')
        # Create ACL if it does not yet exist.
        r = superuser_api_session.iam.put('/acls/{}'.format(rid), json={'description': 'jope'})
        assert r.status_code == 201 or r.status_code == 409
        # Set the permission triplet.
        r = superuser_api_session.iam.put('/acls/{}/users/{}/{}'.format(rid, uid, action))
        r.raise_for_status()
    return set_permission


class TestAdminRouterOpsEndpoints:

    @pytest.mark.usefixtures("iam_verify_and_reset")
    @pytest.mark.parametrize("endpoint", ee_helpers.OPS_ENDPOINTS)
    def test_three_auth_states(self, endpoint, superuser_api_session, peter_api_session, noauth_api_session):

        # Test anonymous auth state.
        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401
        assert r.headers['WWW-Authenticate'] == 'acsjwt'

        # Test unprivileged.
        r = peter_api_session.get(endpoint)
        assert r.status_code == 403

        # Test as superuser.
        r = superuser_api_session.get(endpoint)
        if '/ca/api/v2' in endpoint:
            assert r.status_code == 405
            return
        assert r.status_code == 200

    @pytest.mark.usefixtures(
        "iam_verify_and_reset",
        "with_peter_in_superuser_acl")
    @pytest.mark.parametrize("endpoint", ee_helpers.OPS_ENDPOINTS)
    def test_superuser_acl(self, endpoint, peter_api_session):
        r = peter_api_session.get(endpoint)
        if '/ca/api/v2' in endpoint:
            assert r.status_code == 405
            return
        assert r.status_code == 200

    @pytest.mark.usefixtures(
        "iam_verify_and_reset",
        "with_peter_in_superuser_group")
    @pytest.mark.parametrize("endpoint", ee_helpers.OPS_ENDPOINTS)
    def test_superuser_acl_through_superuser_group(self, peter_api_session, endpoint):
        r = peter_api_session.get(endpoint)
        if '/ca/api/v2' in endpoint:
            assert r.status_code == 405
            return
        assert r.status_code == 200


@pytest.mark.usefixtures("iam_verify_and_reset")
class TestAdminRouterAuthenticatedUsersEndpoints:

    @pytest.mark.parametrize("endpoint", AUTHENTICATED_USERS_ENDPOINTS)
    def test_two_auth_states(self, endpoint, peter_api_session, noauth_api_session):
        # Test anonymous auth state.
        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401
        assert r.headers['WWW-Authenticate'] == 'acsjwt'

        headers = {}
        # Need to treat capabilities as a special case.
        if endpoint == '/capabilities':
            headers['Accept'] = \
                'application/vnd.dcos.capabilities+json;charset=utf-8;version=v1'

        # Test unprivileged.
        r = peter_api_session.get(endpoint, headers=headers)
        assert r.status_code == 200


class TestAdminRouterServiceEndpoint:

    def test_access_to_base_marathon(self, superuser_api_session, peter_api_session, noauth_api_session):
        endpoint = '/service/marathon/'
        r = peter_api_session.get(endpoint)
        assert r.status_code == 403
        r = superuser_api_session.get(endpoint)
        assert r.status_code == 200
        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401

    def test_access_to_metronome(self, superuser_api_session, peter_api_session, noauth_api_session):
        endpoint = '/service/metronome/v1/jobs'
        r = peter_api_session.get(endpoint)
        assert r.status_code == 403
        r = superuser_api_session.get(endpoint)
        assert r.status_code == 200
        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401

    def test_access_to_unknown_service(self, superuser_api_session, peter_api_session, noauth_api_session):
        endpoint = '/service/unknown/'
        # As long as user is authNed, it's permitted to see 404s. The problem
        # here is that he/she may be requesting for one of:
        # * /service/unknown/
        # * /service/unknonw/foo
        # * /service/unknonw/foo/bar
        # * /service/unknonw/foo/bar/baz.js
        #
        # With nested services, its imposible to know which RID exactly needs
        # to be verified, without knowing which part of the URL is the service
        # name first. Possible RID candidates in this case are:
        # * dcos:adminrouter:service:unknown
        # * dcos:adminrouter:service:unknown/foo
        # * dcos:adminrouter:service:unknown/foo/bar
        # * dcos:adminrouter:service:unknown/foo/bar/baz.js
        #
        # Hence we only check if user was authNed.
        r = peter_api_session.get(endpoint)
        assert r.status_code == 404
        r = superuser_api_session.get(endpoint)
        assert r.status_code == 404
        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401


@pytest.mark.usefixtures("iam_verify_and_reset")
class TestSecretsACLs:
    def test_get_store_acl(self, peter_api_session):
        # TODO(JP): extend this test.
        r = peter_api_session.secrets.get('store')
        assert r.status_code == 403


@pytest.mark.usefixtures("iam_verify_and_reset")
class TestAdminRouterACLs:

    def test_adminrouter_acs(self, set_user_permission, peter, peter_api_session, noauth_api_session):
        endpoint = '/users'

        r = noauth_api_session.iam.get(endpoint)
        assert r.status_code == 401

        r = peter_api_session.iam.get(endpoint)
        assert r.status_code == 403

        set_user_permission(
            rid='dcos:adminrouter:acs',
            uid=peter.uid,
            action='full')

        r = peter_api_session.iam.get(endpoint)
        assert r.status_code == 200

    @pytest.mark.skip(reason="Disabled untill DCOS-8889 is addressed")
    def test_adminrouter_ops_ca_ro(self, set_user_permission, peter, peter_api_session, noauth_api_session):
        endpoint = '/certificates'

        r = noauth_api_session.ca.get(endpoint)
        assert r.status_code == 401

        r = peter_api_session.ca.get(endpoint)
        assert r.status_code == 403
        set_user_permission(
            rid='dcos:adminrouter:ops:ca:ro',
            uid=peter.uid,
            action='full')

        r = peter_api_session.ca.get(endpoint)
        assert r.status_code == 405

    def test_adminrouter_ops_ca_rw(self, peter, peter_api_session, noauth_api_session, set_user_permission):
        endpoint = '/newcert'

        r = noauth_api_session.ca.get(endpoint)
        assert r.status_code == 401

        r = peter_api_session.ca.get(endpoint)
        assert r.status_code == 403

        set_user_permission(
            rid='dcos:adminrouter:ops:ca:rw',
            uid=peter_api_session.auth_user.uid,
            action='full')

        data = {
            "request": {
                "hosts": ["www.example.com"],
                "names": [{"C": "US", "ST": "foo", "L": "bar", "O": "byzz"}],
                "CN": "www.example.com"
                }
            }
        r = peter_api_session.ca.post(endpoint, json=data)
        assert r.status_code == 200

    def test_adminrouter_ops_system_backup(self, peter, peter_api_session, noauth_api_session, set_user_permission):
        endpoint = '/system/v1/backup/v1/list'

        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401

        r = peter_api_session.get(endpoint)
        assert r.status_code == 403

        set_user_permission(
            rid='dcos:adminrouter:ops:system-backup',
            uid=peter_api_session.auth_user.uid,
            action='full')

        r = peter_api_session.get(endpoint)
        assert r.status_code == 200

    def test_adminrouter_ops_system_health(self, peter, peter_api_session, noauth_api_session, set_user_permission):
        endpoint = '/system/health/v1'

        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401

        r = peter_api_session.get(endpoint)
        assert r.status_code == 403

        set_user_permission(
            rid='dcos:adminrouter:ops:system-health',
            uid=peter.uid,
            action='full')

        r = peter_api_session.get(endpoint)
        assert r.status_code == 200

    def test_adminrouter_ops_system_metrics(self, peter, peter_api_session, noauth_api_session, set_user_permission):
        endpoint = '/system/v1/metrics/v0/node'

        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401

        r = peter_api_session.get(endpoint)
        assert r.status_code == 403

        set_user_permission(
            rid='dcos:adminrouter:ops:system-metrics',
            uid=peter_api_session.auth_user.uid,
            action='full')

        r = peter_api_session.get(endpoint)
        assert r.status_code == 200

    def test_adminrouter_ops_mesos(self, peter, peter_api_session, noauth_api_session, set_user_permission):

        endpoint = '/mesos'

        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401

        r = peter_api_session.get(endpoint)
        assert r.status_code == 403

        set_user_permission(
            rid='dcos:adminrouter:ops:mesos',
            uid=peter.uid,
            action='full')

        r = peter_api_session.get(endpoint)
        assert r.status_code == 200

    def test_adminrouter_package(self, peter, peter_api_session, noauth_api_session, set_user_permission):
        endpoint = '/package/search'

        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401

        r = peter_api_session.get(endpoint)
        assert r.status_code == 403

        set_user_permission(
            rid='dcos:adminrouter:package',
            uid=peter.uid,
            action='full')

        headers = {
            'Accept': 'application/vnd.dcos.package.search-response+json;charset=utf-8;version=v1',
            'Content-Type': 'application/vnd.dcos.package.search-request+json;charset=UTF-8;version=v1'}

        r = peter_api_session.post(
            '/package/search',
            json={},
            headers=headers)
        assert r.status_code == 200

    def test_adminrouter_ops_exhibitor(self, peter, peter_api_session, noauth_api_session, set_user_permission):
        endpoint = '/exhibitor'

        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401

        r = peter_api_session.get(endpoint)
        assert r.status_code == 403

        set_user_permission(
            rid='dcos:adminrouter:ops:exhibitor',
            uid=peter.uid,
            action='full')

        r = peter_api_session.get(endpoint)
        assert r.status_code == 200

    def test_adminrouter_ops_networking(self, peter, set_user_permission, peter_api_session, noauth_api_session):
        endpoint = '/networking/api/v1/vips'

        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401

        r = peter_api_session.get(endpoint)
        assert r.status_code == 403

        set_user_permission(
            rid='dcos:adminrouter:ops:networking',
            uid=peter.uid,
            action='full')

        r = peter_api_session.get(endpoint)
        assert r.status_code == 200

    def test_adminrouter_ops_slave(self, peter, superuser_api_session, set_user_permission,
                                   peter_api_session, noauth_api_session):
        # Obtain a valid agent ID.
        r = superuser_api_session.get('/mesos/master/state')
        agent_ids = sorted(x['id'] for x in r.json()['slaves'])
        log.info('Obtained these agent IDs: %s', agent_ids)

        endpoint = '/agent/{}/slave%281%29/state.json'.format(agent_ids[0])
        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401

        r = peter_api_session.get(endpoint)
        assert r.status_code == 403

        set_user_permission(
            rid='dcos:adminrouter:ops:slave',
            uid=peter.uid,
            action='full'
            )
        r = peter_api_session.get(endpoint)
        assert r.status_code == 200
        assert "id" in r.json()

    def test_adminrouter_service_marathon(self, peter, set_user_permission, peter_api_session, noauth_api_session):
        endpoint = '/service/marathon/ui'

        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401

        r = peter_api_session.get(endpoint)
        assert r.status_code == 403

        set_user_permission(
            rid='dcos:adminrouter:service:marathon',
            uid=peter.uid,
            action='full')

        r = peter_api_session.get(endpoint)
        assert r.status_code == 200

    def test_adminrouter_ops_metadata(self, peter, set_user_permission, peter_api_session, noauth_api_session):
        endpoint = '/pkgpanda/active.buildinfo.full.json'

        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401

        r = peter_api_session.get(endpoint)
        assert r.status_code == 403

        set_user_permission(
            rid='dcos:adminrouter:ops:metadata',
            uid=peter.uid,
            action='full')

        r = peter_api_session.get(endpoint)
        assert r.status_code == 200

    def test_adminrouter_ops_historyservice(self, peter, set_user_permission, peter_api_session, noauth_api_session):
        endpoint = '/dcos-history-service/'

        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401

        r = peter_api_session.get(endpoint)
        assert r.status_code == 403

        set_user_permission(
            rid='dcos:adminrouter:ops:historyservice',
            uid=peter.uid,
            action='full')

        r = peter_api_session.get(endpoint)
        assert r.status_code == 200

    def test_adminrouter_ops_mesos_dns(self, peter, peter_api_session, noauth_api_session, set_user_permission):
        endpoint = '/mesos_dns/v1/config'

        r = noauth_api_session.get(endpoint)
        assert r.status_code == 401

        r = peter_api_session.get(endpoint)
        assert r.status_code == 403

        set_user_permission(
            rid='dcos:adminrouter:ops:mesos-dns',
            uid=peter.uid,
            action='full')

        r = peter_api_session.get(endpoint)
        assert r.status_code == 200

    def test_adminrouter_ops_cosmos_service(
            self,
            superuser_api_session,
            peter_api_session,
            noauth_api_session,
            set_user_permission):
        endpoint = '/cosmos/service/start'

        r = noauth_api_session.post(endpoint)
        assert r.status_code == 401

        r = peter_api_session.post(endpoint)
        assert r.status_code == 403

        set_user_permission(
            rid='dcos:adminrouter:package',
            uid=peter_api_session.auth_user.uid,
            action='full'
        )

        r = peter_api_session.post(
            endpoint,
            headers={
                'Accept': (
                    'application/vnd.dcos.service.start-response+json;'
                    'charset=utf-8;version=v1'
                ),
                'Content-Type': (
                    'application/vnd.dcos.service.start-request+json;'
                    'charset=utf-8;version=v1'
                )
            },
            json={
                'packageName': 'cassandra'
            }
        )

        if (ee_helpers.dcos_config['cosmos_staged_package_storage_uri_flag'] and
                ee_helpers.dcos_config['cosmos_package_storage_uri_flag']):
            # If persistent storage is enable in cosmos then Cosmos should
            # return 400 because it is an bad request.
            assert r.status_code == 400, 'status = {}, content = {}'.format(
                r.status_code,
                r.content
            )
        else:
            # If persistent storage is not enabled the Cosmos should return a
            # 501, not implemented.
            assert r.status_code == 501, 'status = {}, content = {}'.format(
                r.status_code,
                r.content
            )


@pytest.mark.usefixtures("iam_verify_and_reset")
class TestMarathonAppDeployment:

    def test_anonymous_sleep_app(self, noauth_api_session):
        app = ee_helpers.sleep_app_definition("anonymous-%s" % str(uuid.uuid4()))
        r = noauth_api_session.marathon.post('/apps', json=app)
        assert r.status_code == 401

    def test_peter_sleep_app(self, peter_api_session):
        app = ee_helpers.sleep_app_definition("peter-%s" % str(uuid.uuid4()))
        r = peter_api_session.marathon.post('/apps', json=app)
        assert r.status_code == 403

    def test_superuser_sleep_app(self, superuser_api_session):
        app = ee_helpers.sleep_app_definition("super-%s" % str(uuid.uuid4()))
        with superuser_api_session.marathon.deploy_and_cleanup(app, check_health=False):
            pass
