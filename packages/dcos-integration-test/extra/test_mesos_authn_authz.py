import collections
import copy
import logging
import uuid

import pytest

from ee_helpers import bootstrap_config, sleep_app_definition

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.security,
    pytest.mark.usefixtures('iam_verify_and_reset')
]

Endpoint = collections.namedtuple('Endpoint', 'path, is_authenticated')


@pytest.fixture
def run_task(superuser_api_session):
    sleep_app = sleep_app_definition('mesos-authz-{}'.format(str(uuid.uuid4())))
    with superuser_api_session.marathon.deploy_and_cleanup(sleep_app, check_health=False):
        yield


def get_query_path(path, node_type):
    needs_query_paths = ['files/read', 'files/browse', 'files/download']
    if not any([p in path for p in needs_query_paths]):
        return None
    if node_type == 'master':
        return 'path=/master/log'
    elif node_type == 'agent':
        return 'path=/slave/log'
    else:
        raise AssertionError('Unknown node type: {}'.format(node_type))


def extract_endpoints(data):
    """ Loops through a dict created from a mesos help json and
    return a NamedTuple with path and a boolean for if the endpoint
    should have authentication. Note: v1 api's are skipped

    example of data:
    {
        "processes": [{
            "endpoints": [{
                "name": "/some_path",
                "text": "some description"},
                {...}],
            "id": "some_process"},
            {...}]
    }
    """
    needle = ('\n### AUTHENTICATION ###\n'
              'This endpoint requires authentication')
    for top_level in data['processes']:
        for endpoint in top_level['endpoints']:
            is_authenticated = needle in endpoint['text']
            path = top_level['id'] + endpoint['name']
            if 'api/v1' in path:
                # These are not expected to be locked down.
                continue
            yield Endpoint(path=path, is_authenticated=is_authenticated)


def get_authn_endpoint_responses(api_session):
    """
    1. loop through master endpoints first
    2. Handle special case that expects query parameters, and inject dummy
       that we know to exist, depending on master/slave state.
    3. If endpoint does not have authentication, ensure 401 not raised and pass
    4. Repeat for agent
    """
    def is_unauthenticated(endpoint, response):
        if not endpoint.is_authenticated:
            assert response.status_code != 401, 'unauthenticated url {} rejected ' \
                'request due to missing authentication'.format(response.request.url)
            return True
        return False

    for node_type in ['master', 'agent']:
        for e in extract_endpoints(api_session.get('/help', query='format=json', mesos_node=node_type).json()):
            query = get_query_path(e.path, node_type)
            r = api_session.get(e.path, query=query, mesos_node=node_type)
            if is_unauthenticated(e, r):
                continue
            log.info('Checking {} endpoint: {}'.format(node_type, r.request.url))
            yield r


class TestMesosAuthn:
    def test_superuser(self, superuser_api_session):
        for r in get_authn_endpoint_responses(superuser_api_session):
            assert r.status_code != 401, 'authenticated url {} does ' \
                'not accept authentication'.format(r.request.url)

    @pytest.mark.xfail(
        bootstrap_config['security'] in {'disabled', 'permissive'},
        reason='Mesos authN is disabled in security-disabled mode and unknown '
        'requests are elevated in permissive mode.', strict=True)
    def test_anonymous(self, noauth_api_session):
        for r in get_authn_endpoint_responses(noauth_api_session):
            if 'disabled' in r.text:
                assert r.status_code == 403, 'disabled url {} did not ' \
                    'return 403 as expected'.format(r.request.url)
            else:
                assert r.status_code == 401, 'authenticated url {} incorrectly ' \
                    'allows unauthenticated requests'.format(r.request.url)


def is_unfiltered(response, filtered_field):
    assert response.status_code == 200
    data = response.json()
    return filtered_field in data and data[filtered_field]


@pytest.mark.xfail(
    bootstrap_config['security'] in {'disabled', 'permissive'},
    reason='Mesos authZ is currently enabled only in strict mode.',
    strict=False)
class TestMesosAuthz:
    @pytest.mark.parametrize(("path", "targets"), [
        ("/logging/toggle", ["master", "agent"]),
        ("/metrics/snapshot", ["master", "agent"]),
        ("/files/read", ["master", "agent"]),
        ("/containers", ["agent"]),
        ("/monitor/statistics", ["agent"])])
    def test_endpoint(self, superuser_api_session, peter_api_session, path, targets):
        for node_type in targets:
            query = get_query_path(path, node_type)
            r = peter_api_session.get(path, query=query, mesos_node=node_type)
            assert r.status_code == 403
            r = superuser_api_session.get(path, query=query, mesos_node=node_type)
            assert r.status_code == 200

    def test_state_filtering(self, superuser_api_session, peter_api_session):
        for node_type in ['agent', 'master']:
            assert is_unfiltered(superuser_api_session.get('/state', mesos_node=node_type), 'flags')
            assert not is_unfiltered(peter_api_session.get('/state', mesos_node=node_type), 'flags')

    def test_task_filtering(self, superuser_api_session, peter_api_session, run_task):
        assert is_unfiltered(superuser_api_session.get('/tasks', mesos_node='master'), 'tasks')
        assert not is_unfiltered(peter_api_session.get('/tasks', mesos_node='master'), 'tasks')

    def test_mesos_weights_endpoint_authz(self, superuser_api_session, peter_api_session):
        """Test that Mesos weights-related endpoints perform authorization correctly"""
        set_weight = '[{"role": "test-weights-role", "weight": #WEIGHT#}]'
        try:
            r = peter_api_session.put(
                '/weights', mesos_node='master', data=set_weight.replace('#WEIGHT#', '2.5'))
            assert r.status_code == 403
            r = peter_api_session.get('/weights', mesos_node='master')
            assert r.status_code == 200
            assert len(r.json()) == 0

            r = superuser_api_session.put(
                '/weights', mesos_node='master', data=set_weight.replace('#WEIGHT#', '2.5'))
            assert r.status_code == 200
            r = superuser_api_session.get('/weights', mesos_node='master')
            assert r.status_code == 200

            found_weight = False
            for data in r.json():
                if data['role'] == 'test-weights-role':
                    found_weight = True
                    assert data['weight'] == 2.5
            assert found_weight
        finally:
            # Mesos does not provide a way to remove weights,
            # so we set it to the default value of 1.0 here.
            superuser_api_session.put(
                '/weights', mesos_node='master', data=set_weight.replace('#WEIGHT#', '1.0'))

    def test_mesos_reservation_volume_endpoints_authz(self, superuser_api_session, peter_api_session, superuser, peter):
        """Test that Mesos reservation and volume endpoints perform authorization
        correctly. A dynamic reservation is made for disk, a persistent volume is
        created with the reservation, and then both are destroyed"""
        def add_principal(string, principal):
            return copy.copy(string).replace('#PRINCIPAL#', principal)

        def check_authz(authorized, path, data):
            if authorized:
                assert superuser_api_session.post(path, data=data, mesos_node='master').status_code == 202
            else:
                assert peter_api_session.post(path, data=data, mesos_node='master').status_code == 403

        # Get a valid agent ID.
        r = superuser_api_session.get('/mesos/master/state')
        assert r.status_code == 200
        for agent in r.json()['slaves']:
            if 'slave_public' in agent['reserved_resources']:
                continue
            agent_id = agent['id']
            break
        assert agent_id, 'No private agents found!'

        # The `#PRINCIPAL#` will be substituted with the appropriate username.
        reservation_data = 'slaveId=' + agent_id + '&resources=' + '''
            [
                {
                    "name": "disk",
                    "type": "SCALAR",
                    "scalar": {"value": 4},
                    "role": "test-reservation-role",
                    "reservation": {"principal": "#PRINCIPAL#"}
                }
            ]'''
        volume_data = 'slaveId=' + agent_id + '&volumes=' + '''
            [
                {
                    "name": "disk",
                    "type": "SCALAR",
                    "scalar": {"value": 4},
                    "role": "test-reservation-role",
                    "reservation": {"principal": "#PRINCIPAL#"},
                    "disk": {
                        "persistence": {
                            "id": "test-volume-04",
                            "principal": "#PRINCIPAL#"
                        },
                        "volume": {
                            "mode": "RW",
                            "container_path": "volume-path"
                        }
                    }
                }
            ]'''
        check_authz(False, '/reserve', add_principal(reservation_data, peter.uid))
        check_authz(True, '/reserve', add_principal(reservation_data, superuser.uid))
        check_authz(False, '/create-volumes', add_principal(volume_data, peter.uid))
        check_authz(True, '/create-volumes', add_principal(volume_data, superuser.uid))
        check_authz(False, '/destroy-volumes', add_principal(volume_data, superuser.uid))
        check_authz(True, '/destroy-volumes', add_principal(volume_data, superuser.uid))
        check_authz(False, '/unreserve', add_principal(reservation_data, superuser.uid))
        check_authz(True, '/unreserve', add_principal(reservation_data, superuser.uid))

    @pytest.mark.parametrize('node_type', ['master', 'agent'])
    @pytest.mark.parametrize('path', [
        '/files/debug',
        '/files/read',
        '/files/download',
        '/files/browse'])
    def test_files_endpoints(self, superuser_api_session, peter_api_session, path, node_type):
        """Test that Mesos files endpoints perform authorization correctly"""
        query = get_query_path(path, node_type)
        assert superuser_api_session.get(path, query=query, mesos_node=node_type).status_code == 200
        assert peter_api_session.get(path, query=query, mesos_node=node_type).status_code == 403

    def test_mesos_quota_endpoint_authz(self, superuser_api_session, peter_api_session):
        """Test that Mesos master's '/quota' endpoint performs authorization correctly"""
        def found_quota(response):
            assert response.status_code == 200

            data = response.json()
            if 'infos' not in data:
                return False
            quota_found = False
            for info in data['infos']:
                if (info['role'] == test_role and info['guarantee'][0]['name'] == 'cpus' and
                        info['guarantee'][0]['scalar']['value'] == 1):
                    quota_found = True
            return quota_found

        test_role = 'test-quota-role'
        data = '''
            {
                "role": "''' + test_role + '''",
                "guarantee": [
                    {
                        "name": "cpus",
                        "type": "SCALAR",
                        "scalar": {"value": 1}
                    }
                ]
            }'''

        assert peter_api_session.post('/quota', data=data, mesos_node='master').status_code == 403
        assert superuser_api_session.post('/quota', data=data, mesos_node='master').status_code == 200

        assert not found_quota(peter_api_session.get('/quota', mesos_node='master'))
        assert found_quota(superuser_api_session.get('/quota', mesos_node='master'))

        assert peter_api_session.delete('/quota/' + test_role, mesos_node='master').status_code == 403
        assert superuser_api_session.delete('/quota/' + test_role, mesos_node='master').status_code == 200
