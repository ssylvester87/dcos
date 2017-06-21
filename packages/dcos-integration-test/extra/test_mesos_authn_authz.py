import collections
import copy
import json
import logging
import uuid

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

    def test_task_filtering(self, superuser_api_session, peter_api_session):
        sleep_app = sleep_app_definition('mesos-authz-{}'.format(str(uuid.uuid4())))
        with superuser_api_session.marathon.deploy_and_cleanup(sleep_app, check_health=False):
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

    @pytest.mark.parametrize(('data', 'peter_expected'), [
        ({'type': 'GET_HEALTH'}, 200),
        ({'type': 'GET_FLAGS'}, 403),
        ({'type': 'GET_VERSION'}, 200),
        ({'type': 'GET_METRICS', 'get_metrics': {}}, 200),
        ({'type': 'GET_LOGGING_LEVEL'}, 200),
        ({'type': 'SET_LOGGING_LEVEL', 'set_logging_level': {'level': 0, 'duration': {'nanoseconds': 7}}}, 403),
        ({'type': 'LIST_FILES', 'list_files': {'path': '/slave/log'}}, 403),
        ({'type': 'READ_FILE', 'read_file': {'path': '/slave/log', 'offset': 0}}, 403)
    ])
    def test_mesos_v1_agent_operator_endpoint_authz(self, superuser_api_session, peter_api_session, data,
                                                    peter_expected):
        assert superuser_api_session.post('/api/v1', json=data, mesos_node='agent').status_code == 200
        assert peter_api_session.post('/api/v1', json=data, mesos_node='agent').status_code == peter_expected

    @pytest.mark.parametrize(('action', 'field'), [
        ('GET_STATE', 'get_tasks'),
        ('GET_CONTAINERS', 'get_containers'),
        ('GET_FRAMEWORKS', 'get_frameworks'),
        ('GET_EXECUTORS', 'get_executors'),
        ('GET_TASKS', 'get_tasks')
    ])
    def test_mesos_v1_agent_endpoint_authz_filtering(self, superuser_api_session, peter_api_session, action, field):

        def extract_executing_agent(state, app_id):
            agent_id = None
            for framework in state['frameworks']:
                for task in framework['tasks']:
                    if app_id in task['id']:
                        agent_id = task['slave_id']
                        break
            if agent_id is None:
                return None

            for agent in state['slaves']:
                if agent['id'] == agent_id:
                    return agent['hostname']
            return None

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

            response = peter_api_session.api_request('POST',
                                                     '/api/v1',
                                                     host=agent,
                                                     port=5051,
                                                     json={'type': action},
                                                     headers={'Accept': 'application/json'})
            assert response.status_code == 200
            data = extract_data(response)
            assert not is_unfiltered(data)

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

            agent_location = None
            for agent in state['slaves']:
                if agent['id'] == agent_id:
                    agent_location = agent['hostname']
                    break
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
