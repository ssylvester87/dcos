import collections
import copy
import json
import logging
import time
import uuid
from itertools import chain

import pytest

from dcos_test_utils.recordio import Decoder, Encoder
from ee_helpers import bootstrap_config, sleep_app_definition


log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.security,
    pytest.mark.usefixtures('iam_verify_and_reset')
]

Endpoint = collections.namedtuple('Endpoint', 'path, is_authenticated')


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


def reset_mesos_acls_cache():
    # At the moment there's no API to reset the cache, so we just wait for the
    # cache to be invalidated.
    time.sleep(6)


def grant_permissions(superuser, user_id, permissions):
    """
    Requests bouncer through superuser to grant the permissions set to the
    user 'user'. 'superuser' should be a DcosApiSession object instance while
    permissions is an array of dictionaries like in the example:
    [
      {
        'rid': 'dcos:mesos:master:role:foo',
        'actions: ['read', 'update']
      },
      {
        'rid': 'dcos:mesos:master:role:bar',
        'actions: ['full']
      }
    ]
    """
    for permission in permissions:
        if permission['rid'] not in superuser.initial_resource_ids:
            superuser.iam.create_acl(permission['rid'], 'ACL for rid "{}"'.format(permission['rid']))
        for action in permission['actions']:
            superuser.iam.grant_user_permission(user_id, action, permission['rid'])


@pytest.mark.xfail(
    bootstrap_config['security'] in {'disabled', 'permissive'},
    reason='Mesos authZ is currently enabled only in strict mode.',
    strict=False)
class TestMesosAuthz:
    @pytest.mark.parametrize(('path', 'targets', 'rid_template'), [
        ('/logging/toggle', ['master', 'agent'], 'dcos:mesos:{}:endpoint:path:{}'),
        ('/metrics/snapshot', ['master', 'agent'], 'dcos:mesos:{}:endpoint:path:{}'),
        ('/files/read', ['master', 'agent'], 'dcos:mesos:{}:log'),
        ('/containers', ['agent'], 'dcos:mesos:{}:endpoint:path:{}'),
        ('/monitor/statistics', ['agent'], 'dcos:mesos:{}:endpoint:path:{}')])
    def test_endpoint(self, superuser_api_session, peter_api_session, peter, path, targets,
                      rid_template):
        for node_type in targets:
            query = get_query_path(path, node_type)
            r = peter_api_session.get(path, query=query, mesos_node=node_type)
            assert r.status_code == 403
            r = superuser_api_session.get(path, query=query, mesos_node=node_type)
            assert r.status_code == 200

            rid = rid_template.format(node_type, path)
            if rid not in superuser_api_session.initial_resource_ids:
                superuser_api_session.iam.create_acl(rid, 'ACL for rid "{}"'.format(rid))
            superuser_api_session.iam.grant_user_permission(peter.uid, 'read', rid)
            reset_mesos_acls_cache()
            r = peter_api_session.get(path, query=query, mesos_node=node_type)
            assert r.status_code == 200, r.text

    def test_state_filtering(self, superuser_api_session, peter_api_session, peter):
        for node_type in ['agent', 'master']:
            assert is_unfiltered(superuser_api_session.get('/state', mesos_node=node_type), 'flags')
            assert not is_unfiltered(peter_api_session.get('/state', mesos_node=node_type), 'flags')

            rid = 'dcos:mesos:{}:flags'.format(node_type)

            if rid not in superuser_api_session.initial_resource_ids:
                superuser_api_session.iam.create_acl(rid, 'ACL for rid "{}"'.format(rid))
            superuser_api_session.iam.grant_user_permission(peter.uid, 'read', rid)

            reset_mesos_acls_cache()
            assert is_unfiltered(peter_api_session.get('/state', mesos_node=node_type), 'flags')

    def test_task_filtering(self, superuser_api_session, peter_api_session, peter):
        sleep_app_id = 'mesos-authz-{}'.format(str(uuid.uuid4()))
        sleep_app = sleep_app_definition(sleep_app_id)
        with superuser_api_session.marathon.deploy_and_cleanup(sleep_app, check_health=False):
            assert is_unfiltered(superuser_api_session.get('/tasks', mesos_node='master'), 'tasks')
            assert not is_unfiltered(peter_api_session.get('/tasks', mesos_node='master'), 'tasks')

            grant_permissions(
                superuser_api_session,
                peter.uid,
                [
                    {
                        'rid': 'dcos:mesos:master:task:app_id:/integration-test-sleep-app-{}'.format(sleep_app_id),
                        'actions': ['read']
                    },
                    {
                        'rid': 'dcos:mesos:master:framework:role:slave_public',
                        'actions': ['read']
                    }
                ])
            reset_mesos_acls_cache()
            r = peter_api_session.get('/tasks', mesos_node='master')
            assert is_unfiltered(r, 'tasks')

    def test_mesos_weights_endpoint_authz(self, superuser_api_session, peter_api_session, peter):
        """Test that Mesos weights-related endpoints perform authorization correctly"""

        def find_weight(weight_name, json):
            return next((data['weight'] for data in json if data['role'] == weight_name), None)

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
            assert find_weight('test-weights-role', r.json()) == 2.5

            r = superuser_api_session.put(
                '/weights', mesos_node='master', data=set_weight.replace('#WEIGHT#', '3.0'))
            assert r.status_code == 200
            r = superuser_api_session.get('/weights', mesos_node='master')
            assert r.status_code == 200
            assert find_weight('test-weights-role', r.json()) == 3.0

            rid = 'dcos:mesos:master:weight:role:test-weights-role'
            if rid not in superuser_api_session.initial_resource_ids:
                superuser_api_session.iam.create_acl(rid, 'ACL for rid "{}"'.format(rid))
            superuser_api_session.iam.grant_user_permission(peter.uid, 'read', rid)
            superuser_api_session.iam.grant_user_permission(peter.uid, 'update', rid)
            reset_mesos_acls_cache()
            r = peter_api_session.put('/weights', mesos_node='master', data=set_weight.replace('#WEIGHT#', '2.5'))
            assert r.status_code == 200
            r = peter_api_session.get('/weights', mesos_node='master')
            assert r.status_code == 200

            assert find_weight('test-weights-role', r.json()) == 2.5
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

        assert peter_api_session.post('/reserve',
                                      data=add_principal(reservation_data, peter.uid),
                                      mesos_node='master').status_code == 403
        assert superuser_api_session.post('/reserve',
                                          data=add_principal(reservation_data, superuser.uid),
                                          mesos_node='master').status_code == 202
        assert peter_api_session.post('/create-volumes',
                                      data=add_principal(volume_data, peter.uid),
                                      mesos_node='master').status_code == 403
        assert superuser_api_session.post('/create-volumes',
                                          data=add_principal(volume_data, superuser.uid),
                                          mesos_node='master').status_code == 202
        assert peter_api_session.post('/destroy-volumes',
                                      data=add_principal(volume_data, superuser.uid),
                                      mesos_node='master').status_code == 403
        assert superuser_api_session.post('/destroy-volumes',
                                          data=add_principal(volume_data, superuser.uid),
                                          mesos_node='master').status_code == 202
        assert peter_api_session.post('/unreserve',
                                      data=add_principal(reservation_data, superuser.uid),
                                      mesos_node='master').status_code == 403
        assert superuser_api_session.post('/unreserve',
                                          data=add_principal(reservation_data, superuser.uid),
                                          mesos_node='master').status_code == 202

        grant_permissions(
            superuser_api_session,
            peter.uid,
            [
                {
                    'rid': 'dcos:mesos:master:reservation:role:test-reservation-role',
                    'actions': ['create']
                },
                {
                    'rid': 'dcos:mesos:master:reservation:principal:{}'.format(peter.uid),
                    'actions': ['delete']
                },
                {
                    'rid': 'dcos:mesos:master:volume:role:test-reservation-role',
                    'actions': ['create']
                },
                {
                    'rid': 'dcos:mesos:master:volume:principal:{}'.format(peter.uid),
                    'actions': ['delete']
                }
            ])
        reset_mesos_acls_cache()
        assert peter_api_session.post('/reserve',
                                      data=add_principal(reservation_data, peter.uid),
                                      mesos_node='master').status_code == 202
        assert peter_api_session.post('/create-volumes',
                                      data=add_principal(volume_data, peter.uid),
                                      mesos_node='master').status_code == 202
        assert peter_api_session.post('/destroy-volumes',
                                      data=add_principal(volume_data, peter.uid),
                                      mesos_node='master').status_code == 202
        assert peter_api_session.post('/unreserve',
                                      data=add_principal(reservation_data, peter.uid),
                                      mesos_node='master').status_code == 202

    @pytest.mark.parametrize('node_type', ['master', 'agent'])
    @pytest.mark.parametrize('path', [
        '/files/debug',
        '/files/read',
        '/files/download',
        '/files/browse'])
    def test_files_endpoints(self, superuser_api_session, peter_api_session, peter, path, node_type):
        """Test that Mesos files endpoints perform authorization correctly"""
        query = get_query_path(path, node_type)
        assert superuser_api_session.get(path, query=query, mesos_node=node_type).status_code == 200
        assert peter_api_session.get(path, query=query, mesos_node=node_type).status_code == 403

        for rid in [t.format(node_type) for t in ['dcos:mesos:{}:log', 'dcos:mesos:{}:endpoint:path:/files/debug']]:
            if rid not in superuser_api_session.initial_resource_ids:
                superuser_api_session.iam.create_acl(rid, 'ACL for rid "{}"'.format(rid))
            superuser_api_session.iam.grant_user_permission(peter.uid, 'read', rid)
        reset_mesos_acls_cache()
        assert peter_api_session.get(path, query=query, mesos_node=node_type).status_code == 200

    def test_mesos_quota_endpoint_authz(self, superuser_api_session, peter_api_session, peter):
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

        rid = 'dcos:mesos:master:quota:role:{}'.format(test_role)
        if rid not in superuser_api_session.initial_resource_ids:
            superuser_api_session.iam.create_acl(rid, 'ACL for rid "{}"'.format(rid))
        superuser_api_session.iam.grant_user_permission(peter.uid, 'update', rid)
        superuser_api_session.iam.grant_user_permission(peter.uid, 'read', rid)
        reset_mesos_acls_cache()

        assert peter_api_session.post('/quota', data=data, mesos_node='master').status_code == 200
        assert found_quota(peter_api_session.get('/quota', mesos_node='master'))
        assert peter_api_session.delete('/quota/' + test_role, mesos_node='master').status_code == 200

    @pytest.mark.parametrize(('data', 'peter_expected', 'rid', 'action'), [
        ({'type': 'GET_HEALTH'}, 200, None, None),
        ({'type': 'GET_FLAGS'}, 403, 'dcos:mesos:agent:flags', 'read'),
        ({'type': 'GET_VERSION'}, 200, None, None),
        ({'type': 'GET_METRICS', 'get_metrics': {}}, 200, None, None),
        ({'type': 'GET_LOGGING_LEVEL'}, 200, None, None),
        ({'type': 'SET_LOGGING_LEVEL', 'set_logging_level': {'level': 0, 'duration': {'nanoseconds': 7}}}, 403,
         'dcos:mesos:agent:log_level', 'update'),
        ({'type': 'LIST_FILES', 'list_files': {'path': '/slave/log'}}, 403,
         'dcos:mesos:agent:log', 'read'),
        ({'type': 'READ_FILE', 'read_file': {'path': '/slave/log', 'offset': 0}}, 403,
         'dcos:mesos:agent:log', 'read')
    ])
    def test_mesos_v1_agent_operator_endpoint_authz(self, superuser_api_session, peter_api_session, peter,
                                                    data, peter_expected, rid, action):
        reset_mesos_acls_cache()
        assert superuser_api_session.post('/api/v1', json=data, mesos_node='agent').status_code == 200
        assert peter_api_session.post('/api/v1', json=data, mesos_node='agent').status_code == peter_expected
        if peter_expected != 200:
            if rid not in superuser_api_session.initial_resource_ids:
                superuser_api_session.iam.create_acl(rid, 'ACL for rid "{}"'.format(rid))
            superuser_api_session.iam.grant_user_permission(peter.uid, action, rid)
            reset_mesos_acls_cache()
            assert peter_api_session.post('/api/v1', json=data, mesos_node='agent').status_code == 200

    @pytest.mark.parametrize(('action', 'field'), [
        ('GET_STATE', 'get_tasks'),
        ('GET_CONTAINERS', 'get_containers'),
        ('GET_FRAMEWORKS', 'get_frameworks'),
        ('GET_EXECUTORS', 'get_executors'),
        ('GET_TASKS', 'get_tasks')
    ])
    def test_mesos_v1_agent_endpoint_authz_filtering(self, superuser_api_session, peter_api_session, peter, action,
                                                     field):

        def extract_executing_agent(state, app_id):
            tasks = chain.from_iterable(framework['tasks'] for framework in state['frameworks'])
            agent_id = next((t['slave_id'] for t in tasks if app_id in t['id']), None)
            if agent_id is None:
                return None
            return next((a['hostname'] for a in state['slaves'] if a['id'] == agent_id), None)

        def is_unfiltered(data):
            return field in data and data[field]

        def extract_data(response):
            return response.json() if action != 'GET_STATE' else response.json()['get_state']

        sleep_app_id = 'mesos-authz-{}'.format(str(uuid.uuid4()))
        sleep_app = sleep_app_definition(sleep_app_id)
        with superuser_api_session.marathon.deploy_and_cleanup(sleep_app, check_health=False):
            agent = extract_executing_agent(
                superuser_api_session.get('/state', mesos_node='master').json(),
                sleep_app_id)
            assert agent is not None

            response = superuser_api_session.api_request('POST',
                                                         '/api/v1',
                                                         host=agent,
                                                         port=5051,
                                                         json={'type': action},
                                                         headers={'Accept': 'application/json'})
            assert response.status_code == 200
            data = extract_data(response)
            assert is_unfiltered(data)

            reset_mesos_acls_cache()
            response = peter_api_session.api_request('POST',
                                                     '/api/v1',
                                                     host=agent,
                                                     port=5051,
                                                     json={'type': action},
                                                     headers={'Accept': 'application/json'})
            assert response.status_code == 200
            data = extract_data(response)
            assert not is_unfiltered(data)

            app_id = '/integration-test-sleep-app-{}'.format(sleep_app_id)
            grant_permissions(
                superuser_api_session,
                peter.uid,
                [
                    {
                        'rid': 'dcos:mesos:agent:task:app_id:{}'.format(app_id),
                        'actions': ['read']
                    },
                    {
                        'rid': 'dcos:mesos:agent:container:app_id:{}'.format(app_id),
                        'actions': ['read']
                    },
                    {
                        'rid': 'dcos:mesos:agent:executor:app_id:{}'.format(app_id),
                        'actions': ['read']
                    },
                    {
                        'rid': 'dcos:mesos:agent:framework:role:slave_public',
                        'actions': ['read']
                    },
                    {
                        'rid': 'dcos:mesos:agent:framework:role:*',
                        'actions': ['read']
                    }
                ])
            reset_mesos_acls_cache()

            response = peter_api_session.api_request('POST',
                                                     '/api/v1',
                                                     host=agent,
                                                     port=5051,
                                                     json={'type': action},
                                                     headers={'Accept': 'application/json'})
            assert response.status_code == 200
            data = extract_data(response)
            assert is_unfiltered(data)

    def test_mesos_v1_agent_operator_containers_api_authz(self, superuser_api_session, peter_api_session):

        def extract_container_agent(state, app_id):
            container_id = None
            agent_id = None
            for framework in state['frameworks']:
                for task in framework['tasks']:
                    if app_id in task['id']:
                        container_id = task['statuses'][0]['container_status']['container_id']['value']
                        agent_id = task['slave_id']
                        break
            if container_id is None or agent_id is None:
                return (None, None)

            agent_location = next((a['hostname'] for a in state['slaves'] if a['id'] == agent_id), None)
            if agent_location is None:
                return (None, None)
            return (container_id, agent_location)

        app_id = 'mesos-authz-{}'.format(str(uuid.uuid4()))
        sleep_app = sleep_app_definition(app_id)
        with superuser_api_session.marathon.deploy_and_cleanup(sleep_app, check_health=False):
            container_id, agent_address = extract_container_agent(
                superuser_api_session.get('/state', mesos_node='master').json(), app_id)
            assert container_id is not None
            assert agent_address is not None

            nested_container_id = {'value': 'pod-{}'.format(uuid.uuid4()), 'parent': {'value': container_id}}

            # Attempt to launch a nested container.
            launch_nested_container_kwargs = {
                'host': agent_address,
                'port': 5051,
                'json': {
                    'type': 'LAUNCH_NESTED_CONTAINER',
                    'launch_nested_container': {
                        'container_id': nested_container_id,
                        'command': {
                            'value': 'echo echo'
                        }
                    }
                }
            }
            response = peter_api_session.api_request('POST', '/api/v1', **launch_nested_container_kwargs)
            assert response.status_code == 403, response.text
            response = superuser_api_session.api_request('POST', '/api/v1', **launch_nested_container_kwargs)
            assert response.status_code == 200, response.text

            # Wait for the container to exit.
            wait_nested_container_kwargs = {
                'host': agent_address,
                'port': 5051,
                'json': {
                    'type': 'WAIT_NESTED_CONTAINER',
                    'wait_nested_container': {
                        'container_id': nested_container_id
                    }
                }
            }
            response = peter_api_session.api_request('POST', '/api/v1', **wait_nested_container_kwargs)
            assert response.status_code == 403, response.text
            response = superuser_api_session.api_request('POST', '/api/v1', **wait_nested_container_kwargs)
            assert response.status_code == 200, response.text

            # Launch a long-running nested container and kill it.
            nested_container_id = {'value': 'pod-{}'.format(uuid.uuid4()), 'parent': {'value': container_id}}
            launch_nested_container_kwargs['json']['launch_nested_container']['container_id'] = nested_container_id
            launch_nested_container_kwargs['json']['launch_nested_container']['command']['value'] = 'cat'
            response = superuser_api_session.api_request('POST', '/api/v1', **launch_nested_container_kwargs)
            assert response.status_code == 200, response.text

            kill_nested_container_kwargs = {
                'host': agent_address,
                'port': 5051,
                'json': {
                    'type': 'KILL_NESTED_CONTAINER',
                    'kill_nested_container': {
                        'container_id': nested_container_id
                    }
                }
            }
            response = peter_api_session.api_request('POST', '/api/v1', **kill_nested_container_kwargs)
            assert response.status_code == 403, response.text
            response = superuser_api_session.api_request('POST', '/api/v1', **kill_nested_container_kwargs)
            assert response.status_code == 200, response.text

            # Launch nested container session.
            nested_container_id = {'value': 'debug-{}'.format(uuid.uuid4()), 'parent': {'value': container_id}}
            launch_nested_container_session_kwargs = {
                'host': agent_address,
                'port': 5051,
                'json': {
                    'type': 'LAUNCH_NESTED_CONTAINER_SESSION',
                    'launch_nested_container_session': {
                        'container_id': nested_container_id,
                        'command': {
                            'value': 'cat'
                        }
                    }
                },
                'headers': {
                    'Content-Type': 'application/json',
                    'Accept': 'application/recordio',
                    'Message-Accept': 'application/json',
                    'Connection': 'keep-alive'
                },
                'stream': True
            }
            response = peter_api_session.api_request('POST', '/api/v1', **launch_nested_container_session_kwargs)
            assert response.status_code == 403, response.text
            session = superuser_api_session.api_request('POST', '/api/v1', **launch_nested_container_session_kwargs)
            assert session.status_code == 200, session.text

            encoder = Encoder(lambda s: bytes(json.dumps(s, ensure_ascii=False), "UTF-8"))
            attach_output_kwargs = {
                'host': agent_address,
                'port': 5051,
                'json': {
                    'type': 'ATTACH_CONTAINER_OUTPUT',
                    'attach_container_output': {
                        'container_id': nested_container_id
                    }
                },
                'headers': {
                    'Content-Type': 'application/json',
                    'Accept': 'application/recordio',
                    'Message-Accept': 'application/json',
                    'Connection': 'keep-alive'
                },
                'stream': True
            }
            response = peter_api_session.api_request('POST', '/api/v1', **attach_output_kwargs)
            assert response.status_code == 403, response.text
            attached_output = superuser_api_session.api_request('POST', '/api/v1', **attach_output_kwargs)
            assert attached_output.status_code == 200, attached_output.text

            def input_streamer():
                message = {
                    'type': 'ATTACH_CONTAINER_INPUT',
                    'attach_container_input': {
                        'type': 'CONTAINER_ID',
                        'container_id': nested_container_id
                    }
                }
                yield encoder.encode(message)
                message['attach_container_input'] = {
                    'type': 'PROCESS_IO',
                    'process_io': {
                        'type': 'DATA',
                        'data': {
                            'type': 'STDIN',
                            'data': 'meow'
                        }
                    }
                }
                yield encoder.encode(message)
                # Place an empty string to indicate EOF to the server and push
                # 'None' to our queue to indicate that we are done processing input.
                message['attach_container_input']['process_io']['data']['data'] = ''
                yield encoder.encode(message)

            attach_input_kwargs = {
                'host': agent_address,
                'port': 5051,
                'data': '',
                'headers': {
                    'Content-Type': 'application/recordio',
                    'Message-Content-Type': 'application/json',
                    'Accept': 'application/recordio',
                    'Message-Accept': 'application/json',
                    'Connection': 'keep-alive',
                    'Transfer-Encoding': 'chunked'
                }
            }
            attach_input_kwargs['data'] = input_streamer()
            response = peter_api_session.api_request('POST', '/api/v1', **attach_input_kwargs)
            assert response.status_code == 403, response.text
            attach_input_kwargs['data'] = input_streamer()
            response = superuser_api_session.api_request('POST', '/api/v1', **attach_input_kwargs)
            assert response.status_code == 200, response.text

            # Verify the streamed output from the launch session
            decoder = Decoder(lambda s: json.loads(s.decode("UTF-8")))
            for chunk in session.iter_content():
                for decoded in decoder.decode(chunk):
                    if decoded['type'] == 'DATA':
                        assert decoded['data']['data'] == 'meow', 'Output did not match expected'

            # Verify the streamed output from the attached output.
            for chunk in attached_output.iter_content():
                for decoded in decoder.decode(chunk):
                    if decoded['type'] == 'DATA':
                        assert decoded['data']['data'] == 'meow', 'Output did not match expected'

    def test_mesos_v1_agent_operator_containers_api_authz_known_user(self, superuser_api_session, peter_api_session,
                                                                     peter):

        def extract_container_agent(state, app_id):
            container_id = None
            agent_id = None
            for framework in state['frameworks']:
                for task in framework['tasks']:
                    if app_id in task['id']:
                        container_id = task['statuses'][0]['container_status']['container_id']['value']
                        agent_id = task['slave_id']
                        break
            if container_id is None or agent_id is None:
                return (None, None)

            agent_location = next((a['hostname'] for a in state['slaves'] if a['id'] == agent_id), None)
            if agent_location is None:
                return (None, None)
            return (container_id, agent_location)

        app_uid = 'mesos-authz-{}'.format(str(uuid.uuid4()))
        sleep_app = sleep_app_definition(app_uid)
        app_id = sleep_app['id']
        grant_permissions(
            superuser_api_session,
            peter.uid,
            [
                {
                    'rid': 'dcos:mesos:master:task:user:{}'.format(peter_api_session.default_os_user),
                    'actions': ['create']
                },
                {
                    'rid': 'dcos:service:marathon:marathon:services:/',
                    'actions': ['full']
                },
                {
                    'rid': 'dcos:adminrouter:service:marathon',
                    'actions': ['full']
                },
                {
                    'rid': 'dcos:mesos:master:task:app_id:{}'.format(app_id),
                    'actions': ['read']
                },
                {
                    'rid': 'dcos:mesos:master:framework:role:*',
                    'actions': ['read']
                },
                {
                    'rid': 'dcos:mesos:master:framework:role:slave_public',
                    'actions': ['read']
                }
            ])
        reset_mesos_acls_cache()
        with peter_api_session.marathon.deploy_and_cleanup(sleep_app, check_health=False):
            r = peter_api_session.get('/state', mesos_node='master')
            log.info(r.text)
            container_id, agent_address = extract_container_agent(r.json(), app_uid)
            assert container_id is not None
            assert agent_address is not None

            grant_permissions(
                superuser_api_session,
                peter.uid,
                [
                    {
                        'rid': 'dcos:mesos:agent:nested_container:app_id:{}'.format(app_id),
                        'actions': ['full']
                    },
                    {
                        'rid': 'dcos:mesos:agent:nested_container:role:slave_public',
                        'actions': ['full']
                    },
                    {
                        'rid': 'dcos:mesos:agent:nested_container:user:{}'.format(
                            peter_api_session.default_os_user),
                        'actions': ['full']
                    }
                ])
            nested_container_id = {'value': 'pod-{}'.format(uuid.uuid4()), 'parent': {'value': container_id}}

            # Attempt to launch a nested container.
            launch_nested_container_kwargs = {
                'host': agent_address,
                'port': 5051,
                'json': {
                    'type': 'LAUNCH_NESTED_CONTAINER',
                    'launch_nested_container': {
                        'container_id': nested_container_id,
                        'command': {
                            'value': 'echo echo'
                        }
                    }
                }
            }
            reset_mesos_acls_cache()
            response = peter_api_session.api_request('POST', '/api/v1', **launch_nested_container_kwargs)
            assert response.status_code == 200, response.text

            # Wait for the container to exit.
            wait_nested_container_kwargs = {
                'host': agent_address,
                'port': 5051,
                'json': {
                    'type': 'WAIT_NESTED_CONTAINER',
                    'wait_nested_container': {
                        'container_id': nested_container_id
                    }
                }
            }
            response = peter_api_session.api_request('POST', '/api/v1', **wait_nested_container_kwargs)
            assert response.status_code == 200, response.text

            # Launch a long-running nested container and kill it.
            nested_container_id = {'value': 'pod-{}'.format(uuid.uuid4()), 'parent': {'value': container_id}}
            launch_nested_container_kwargs['json']['launch_nested_container']['container_id'] = nested_container_id
            launch_nested_container_kwargs['json']['launch_nested_container']['command']['value'] = 'cat'
            response = peter_api_session.api_request('POST', '/api/v1', **launch_nested_container_kwargs)
            assert response.status_code == 200, response.text

            kill_nested_container_kwargs = {
                'host': agent_address,
                'port': 5051,
                'json': {
                    'type': 'KILL_NESTED_CONTAINER',
                    'kill_nested_container': {
                        'container_id': nested_container_id
                    }
                }
            }
            response = peter_api_session.api_request('POST', '/api/v1', **kill_nested_container_kwargs)
            assert response.status_code == 200, response.text

            grant_permissions(
                superuser_api_session,
                peter.uid,
                [
                    {
                        'rid': 'dcos:mesos:agent:nested_container_session:app_id:{}'.format(app_id),
                        'actions': ['full']
                    },
                    {
                        'rid': 'dcos:mesos:agent:nested_container_session:role:slave_public',
                        'actions': ['full']
                    },
                    {
                        'rid': 'dcos:mesos:agent:nested_container_session:user:{}'.format(
                            peter_api_session.default_os_user),
                        'actions': ['full']
                    },
                    {
                        'rid': 'dcos:mesos:agent:container:app_id:{}'.format(app_id),
                        'actions': ['read', 'update']
                    },
                    {
                        'rid': 'dcos:mesos:agent:container:role:slave_public',
                        'actions': ['read', 'update']
                    }
                ])
            reset_mesos_acls_cache()
            # Launch nested container session.
            nested_container_id = {'value': 'debug-{}'.format(uuid.uuid4()), 'parent': {'value': container_id}}
            launch_nested_container_session_kwargs = {
                'host': agent_address,
                'port': 5051,
                'json': {
                    'type': 'LAUNCH_NESTED_CONTAINER_SESSION',
                    'launch_nested_container_session': {
                        'container_id': nested_container_id,
                        'command': {
                            'value': 'cat'
                        }
                    }
                },
                'headers': {
                    'Content-Type': 'application/json',
                    'Accept': 'application/recordio',
                    'Message-Accept': 'application/json',
                    'Connection': 'keep-alive'
                },
                'stream': True
            }
            session = peter_api_session.api_request('POST', '/api/v1', **launch_nested_container_session_kwargs)
            assert session.status_code == 200, session.text

            encoder = Encoder(lambda s: bytes(json.dumps(s, ensure_ascii=False), "UTF-8"))
            attach_output_kwargs = {
                'host': agent_address,
                'port': 5051,
                'json': {
                    'type': 'ATTACH_CONTAINER_OUTPUT',
                    'attach_container_output': {
                        'container_id': nested_container_id
                    }
                },
                'headers': {
                    'Content-Type': 'application/json',
                    'Accept': 'application/recordio',
                    'Message-Accept': 'application/json',
                    'Connection': 'keep-alive'
                },
                'stream': True
            }
            attached_output = peter_api_session.api_request('POST', '/api/v1', **attach_output_kwargs)
            assert attached_output.status_code == 200, attached_output.text

            def input_streamer():
                message = {
                    'type': 'ATTACH_CONTAINER_INPUT',
                    'attach_container_input': {
                        'type': 'CONTAINER_ID',
                        'container_id': nested_container_id
                    }
                }
                yield encoder.encode(message)
                message['attach_container_input'] = {
                    'type': 'PROCESS_IO',
                    'process_io': {
                        'type': 'DATA',
                        'data': {
                            'type': 'STDIN',
                            'data': 'meow'
                        }
                    }
                }
                yield encoder.encode(message)
                # Place an empty string to indicate EOF to the server and push
                # 'None' to our queue to indicate that we are done processing input.
                message['attach_container_input']['process_io']['data']['data'] = ''
                yield encoder.encode(message)

            attach_input_kwargs = {
                'host': agent_address,
                'port': 5051,
                'data': '',
                'headers': {
                    'Content-Type': 'application/recordio',
                    'Message-Content-Type': 'application/json',
                    'Accept': 'application/recordio',
                    'Message-Accept': 'application/json',
                    'Connection': 'keep-alive',
                    'Transfer-Encoding': 'chunked'
                }
            }
            attach_input_kwargs['data'] = input_streamer()
            response = peter_api_session.api_request('POST', '/api/v1', **attach_input_kwargs)
            assert response.status_code == 200, response.text

            # Verify the streamed output from the launch session
            decoder = Decoder(lambda s: json.loads(s.decode("UTF-8")))
            for chunk in session.iter_content():
                for decoded in decoder.decode(chunk):
                    if decoded['type'] == 'DATA':
                        assert decoded['data']['data'] == 'meow', 'Output did not match expected'

            # Verify the streamed output from the attached output.
            for chunk in attached_output.iter_content():
                for decoded in decoder.decode(chunk):
                    if decoded['type'] == 'DATA':
                        assert decoded['data']['data'] == 'meow', 'Output did not match expected'
