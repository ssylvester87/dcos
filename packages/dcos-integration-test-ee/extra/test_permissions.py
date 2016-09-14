"""
Test authorization behavior of various components.
"""


import logging


import pytest
import requests

from dcostests import CAUrl, dcos, IAMUrl, Url
from dcostests.marathon import MarathonApp, sleep_app_definition


log = logging.getLogger(__name__)


pytestmark = [pytest.mark.security]


class TestAdminRouterOpsEndpoints:

    @pytest.mark.usefixtures("iam_verify_and_reset")
    @pytest.mark.parametrize("endpoint", dcos.ops_endpoints)
    def test_ops_endpoints_three_auth_states(self, endpoint, peter, superuser):

        url = str(Url(endpoint))
        # Test anonymous auth state.
        r = requests.get(url)
        assert r.status_code == 401
        assert r.headers['WWW-Authenticate'] == 'acsjwt'

        # Test unprivileged.
        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 403

        # Test as superuser.
        r = requests.get(url, headers=superuser.authheader)
        if '/ca/api/v2' in url:
            assert r.status_code == 405
            return
        assert r.status_code == 200

    @pytest.mark.usefixtures(
        "iam_verify_and_reset",
        "with_peter_in_superuser_acl"
        )
    @pytest.mark.parametrize("endpoint", dcos.ops_endpoints)
    def test_superuser_acl(self, endpoint, peter):

        url = str(Url(endpoint))
        r = requests.get(url, headers=peter.authheader)
        if '/ca/api/v2' in url:
            assert r.status_code == 405
            return
        assert r.status_code == 200

    @pytest.mark.usefixtures(
        "iam_verify_and_reset",
        "with_peter_in_superuser_group"
        )
    @pytest.mark.parametrize("endpoint", dcos.ops_endpoints)
    def test_superuser_acl_through_superuser_group(self, endpoint, peter):

        url = str(Url(endpoint))
        r = requests.get(url, headers=peter.authheader)
        if '/ca/api/v2' in url:
            assert r.status_code == 405
            return
        assert r.status_code == 200


@pytest.mark.usefixtures("iam_verify_and_reset")
class TestAdminRouterAuthenticatedUsersEndpoints:

    @pytest.mark.parametrize("endpoint", dcos.authenticated_users_endpoints)
    def test_two_auth_states(self, endpoint, peter):

        # Test anonymous auth state.
        r = requests.get(Url(endpoint))
        assert r.status_code == 401
        assert r.headers['WWW-Authenticate'] == 'acsjwt'

        headers = peter.authheader.copy()
        # Need to treat capabilities as a special case.
        if endpoint == '/capabilities':
            headers['Accept'] = \
                'application/vnd.dcos.capabilities+json;charset=utf-8;version=v1'

        # Test unprivileged.
        r = requests.get(Url(endpoint), headers=headers)
        assert r.status_code == 200


class TestAdminRouterServiceEndpoint:

    def test_access_to_base_marathon(self, peter, superuser):
        u = Url('/service/marathon/')
        r = requests.get(u, headers=peter.authheader)
        assert r.status_code == 403
        r = requests.get(u, headers=superuser.authheader)
        assert r.status_code == 200
        r = requests.get(u)
        assert r.status_code == 401

    def test_access_to_metronome(self, peter, superuser):
        u = Url('/service/metronome/v1/jobs')
        r = requests.get(u, headers=peter.authheader)
        assert r.status_code == 403
        r = requests.get(u, headers=superuser.authheader)
        assert r.status_code == 200
        r = requests.get(u)
        assert r.status_code == 401

    def test_access_to_unknown_service(self, peter, superuser):
        u = Url('/service/unknown/')
        r = requests.get(u, headers=peter.authheader)
        assert r.status_code == 403
        r = requests.get(u, headers=superuser.authheader)
        # An unknown service irritates the service endpoint.
        assert r.status_code == 500
        r = requests.get(u)
        assert r.status_code == 401


@pytest.mark.usefixtures("iam_verify_and_reset")
class TestSecretsACLs:

    def test_get_store_acl(self, peter):

        # TODO(JP): extend this test.
        r = requests.get(Url('/secrets/v1/store'), headers=peter.authheader)
        assert r.status_code == 403


@pytest.mark.usefixtures("iam_verify_and_reset")
class TestAdminRouterACLs:

    def test_adminrouter_acs(self, superuser, peter):

        url = IAMUrl('/users')

        r = requests.get(url)
        assert r.status_code == 401

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 403

        superuser.set_user_permission(
            rid='dcos:adminrouter:acs',
            uid=peter.uid,
            action='full'
            )

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 200

    @pytest.mark.skip(reason="Disabled untill DCOS-8889 is addressed")
    def test_adminrouter_ops_ca_ro(self, peter, superuser):

        url = CAUrl('/certificates')

        r = requests.get(url)
        assert r.status_code == 401

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 403

        superuser.set_user_permission(
            rid='dcos:adminrouter:ops:ca:ro',
            uid=peter.uid,
            action='full'
            )

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 405

    def test_adminrouter_ops_ca_rw(self, peter, superuser):

        url = CAUrl('/newcert')

        r = requests.get(url)
        assert r.status_code == 401

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 403

        superuser.set_user_permission(
            rid='dcos:adminrouter:ops:ca:rw',
            uid=peter.uid,
            action='full'
            )

        data = {
            "request": {
                "hosts": ["www.example.com"],
                "names": [{"C": "US", "ST": "foo", "L": "bar", "O": "byzz"}],
                "CN": "www.example.com"
                }
            }
        r = requests.post(url, json=data, headers=peter.authheader)
        assert r.status_code == 200

    def test_adminrouter_ops_system_health(self, peter, superuser):

        url = Url('/system/health/v1')

        r = requests.get(url)
        assert r.status_code == 401

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 403

        superuser.set_user_permission(
            rid='dcos:adminrouter:ops:system-health',
            uid=peter.uid,
            action='full'
            )

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 200

    def test_adminrouter_ops_mesos(self, peter, superuser):

        url = Url('/mesos')

        r = requests.get(url)
        assert r.status_code == 401

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 403

        superuser.set_user_permission(
            rid='dcos:adminrouter:ops:mesos',
            uid=peter.uid,
            action='full'
            )

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 200

    def test_adminrouter_package(self, peter, superuser):

        url = Url('/package/search')

        r = requests.get(url)
        assert r.status_code == 401

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 403

        superuser.set_user_permission(
            rid='dcos:adminrouter:package',
            uid=peter.uid,
            action='full'
            )

        headers = peter.authheader.copy()
        headers.update({
            'Accept': 'application/vnd.dcos.package.search-response+json;charset=utf-8;version=v1',
            'Content-Type': 'application/vnd.dcos.package.search-request+json;charset=UTF-8;version=v1'
            })

        r = requests.post(
            Url('/package/search'),
            json={},
            headers=headers
            )
        assert r.status_code == 200

    def test_adminrouter_ops_exhibitor(self, peter, superuser):

        url = Url('/exhibitor')

        r = requests.get(url)
        assert r.status_code == 401

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 403

        superuser.set_user_permission(
            rid='dcos:adminrouter:ops:exhibitor',
            uid=peter.uid,
            action='full'
            )

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 200

    def test_adminrouter_ops_networking(self, peter, superuser):

        url = Url('/networking/api/v1/vips')

        r = requests.get(url)
        assert r.status_code == 401

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 403

        superuser.set_user_permission(
            rid='dcos:adminrouter:ops:networking',
            uid=peter.uid,
            action='full'
            )

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 200

    def test_adminrouter_ops_slave(self, peter, superuser):
        # Obtain a valid agent ID.
        r = requests.get(
            Url('/mesos/master/state'),
            headers=superuser.authheader
            )
        agent_ids = sorted(x['id'] for x in r.json()['slaves'])
        log.info('Obtained these agent IDs: %s', agent_ids)

        url = Url('/agent/{}/slave%281%29/state.json'.format(agent_ids[0]))
        r = requests.get(url)
        assert r.status_code == 401

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 403

        superuser.set_user_permission(
            rid='dcos:adminrouter:ops:slave',
            uid=peter.uid,
            action='full'
            )
        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 200
        assert "id" in r.json()

    def test_adminrouter_service_marathon(self, peter, superuser):

        url = Url('/service/marathon/ui')

        r = requests.get(url)
        assert r.status_code == 401

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 403

        superuser.set_user_permission(
            rid='dcos:adminrouter:service:marathon',
            uid=peter.uid,
            action='full'
            )

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 200

    def test_adminrouter_ops_metadata(self, peter, superuser):

        url = Url('/pkgpanda/active.buildinfo.full.json')

        r = requests.get(url)
        assert r.status_code == 401

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 403

        superuser.set_user_permission(
            rid='dcos:adminrouter:ops:metadata',
            uid=peter.uid,
            action='full'
            )

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 200

    def test_adminrouter_ops_historyservice(self, peter, superuser):

        url = Url('/dcos-history-service/')

        r = requests.get(url)
        assert r.status_code == 401

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 403

        superuser.set_user_permission(
            rid='dcos:adminrouter:ops:historyservice',
            uid=peter.uid,
            action='full'
            )

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 200

    def test_adminrouter_ops_mesos_dns(self, peter, superuser):

        url = Url('/mesos_dns/v1/config')

        r = requests.get(url)
        assert r.status_code == 401

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 403

        superuser.set_user_permission(
            rid='dcos:adminrouter:ops:mesos-dns',
            uid=peter.uid,
            action='full'
            )

        r = requests.get(url, headers=peter.authheader)
        assert r.status_code == 200


@pytest.mark.usefixtures("iam_verify_and_reset")
class TestMarathonAppDeployment:

    def test_anonymous_sleep_app(self):
        app = MarathonApp(sleep_app_definition())
        r = app.deploy()
        assert r.status_code == 401

    def test_peter_sleep_app(self, peter):
        app = MarathonApp(sleep_app_definition())
        r = app.deploy(headers=peter.authheader)
        assert r.status_code == 403

    def test_superuser_sleep_app(self, superuser):
        app = MarathonApp(sleep_app_definition())
        r = app.deploy(headers=superuser.authheader)
        r.raise_for_status()
        app.wait(check_health=False, headers=superuser.authheader)
