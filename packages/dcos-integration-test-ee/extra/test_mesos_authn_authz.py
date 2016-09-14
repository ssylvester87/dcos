import copy
import logging

import pytest
import requests

from dcostests import dcos, Url
from dcostests.marathon import MarathonApp, sleep_app_definition


log = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.security,
    pytest.mark.usefixtures("iam_verify_and_reset")
]


def get_mesos_endpoints(mesos_url):
    assert not mesos_url.endswith('/')
    data = requests.get(mesos_url + '/help?format=json').json()

    needle = ('\n### AUTHENTICATION ###\n'
              'This endpoint requires authentication')

    endpoints = []
    for top_level in data['processes']:
        for endpoint in top_level['endpoints']:
            is_authenticated = needle in endpoint['text']
            path = mesos_url + '/' + top_level['id'] + endpoint['name']
            endpoints.append({
                'path': path,
                'authenticated': is_authenticated
                })

    return endpoints


def run_task(superuser):
    app = MarathonApp(sleep_app_definition)
    app.deploy(headers=superuser.authheader)
    app.wait(check_health=False, headers=superuser.authheader)


@pytest.mark.xfail(
    dcos.config['security'] == 'disabled',
    reason='Mesos authN is disabled in security-disabled mode and is expected to fail.',
    strict=True
)
def test_mesos_endpoint_authn(superuser):
    """Test that Mesos endpoints behave as expected with respect to authentication"""

    def get_unauthenticated(url):
        ''' Performs an unauthenticated `GET` of `path` '''
        return requests.get(url)

    def get_authenticated(url):
        ''' Performs a Bouncer-authenticated `GET` of `path` '''
        return requests.get(url, headers=superuser.authheader)

    def request(url, do_authed, master):
        _get = get_authenticated if do_authed else get_unauthenticated

        # Handle special case that expects query parameters, and inject dummy
        # that we know to exist, depending on master/slave state.
        if 'files/browse' in url:
            if master:
                url = url + '?path=/master/log'
            else:
                url = url + '?path=/slave/log'

        if 'api/v1' in url:
            # These are not expected to be locked down.
            return

        r = _get(url)

        log.debug(
            'Got %s with %s request for endpoint %s. Response: \n%s',
            r.status_code,
            'authenticated' if do_authed else 'unauthenticated',
            endpoint,
            r.text
            )

        if endpoint['authenticated']:
            if do_authed:
                assert r.status_code != 401, \
                    'authenticated endpoint {} does not accept authentication' \
                    .format(endpoint['path'])
            else:
                if 'disabled' in r.text:
                    assert r.status_code == 403, \
                        'disabled endpoint {} did not return 403 as expected' \
                        .format(endpoint['path'])
                else:
                    assert r.status_code == 401, \
                        'authenticated endpoint {} incorrectly allows unauthenticated requests' \
                        .format(endpoint['path'])
        else:
            assert r.status_code != 401, \
                'unauthenticated endpoint {} rejected request due to missing authentication' \
                .format(endpoint['path'])

    master_url = str(Url('', host=dcos.masters[0], port=5050))
    agent_url = str(Url('', host=dcos.agents[0], port=5051))

    for endpoint in get_mesos_endpoints(master_url):
        log.info('Test Mesos master endpoint: %s', endpoint)
        for do_authed in [False, True]:
            request(url=(endpoint['path']), do_authed=do_authed, master=True)

    for endpoint in get_mesos_endpoints(agent_url):
        log.info('Test Mesos agent endpoint: %s', endpoint)
        for do_authed in [False, True]:
            request(url=(endpoint['path']), do_authed=do_authed, master=False)


@pytest.mark.xfail(
    dcos.config['security'] != 'strict',
    reason='Mesos authZ is currently only enabled in strict mode.',
    strict=False
)
class TestMesosAuthz:
    @pytest.mark.parametrize(("path", "endpoint_info"), [
        ("/logging/toggle", {"target": ["master", "agent"]}),
        ("/metrics/snapshot", {"target": ["master", "agent"]}),
        ("/files/read?path=/master/log", {"target": ["master"]}),
        ("/files/read?path=/slave/log", {"target": ["agent"]}),
        ("/containers", {"target": ["agent"]}),
        ("/monitor/statistics", {"target": ["agent"]})
    ])
    def test_mesos_endpoint_authz(self, superuser, peter, path, endpoint_info):
        """Test that Mesos endpoints behave as expected with respect to
        authorization"""

        def request(url, authorized):
            if authorized:
                r = requests.get(url, headers=superuser.authheader)
            else:
                r = requests.get(url, headers=peter.authheader)

            log.debug(
                'Got %s with %s request for endpoint %s. Response: \n%s',
                r.status_code,
                'authorized' if authorized else 'unauthorized',
                url,
                r.text
            )

            if authorized:
                assert r.status_code == 200
            else:
                assert r.status_code == 403

        urls = {
            'master': str(Url('', host=dcos.masters[0], port=5050)),
            'agent': str(Url('', host=dcos.agents[0], port=5051))
        }

        for target in endpoint_info['target']:
            log.info('Test Mesos %s endpoint: %s', target, path)
            for authorized in [False, True]:
                request(urls[target] + path, authorized)

    @pytest.mark.parametrize(("path", "endpoint_info"), [
        ('/state', {
            'filtered_field': 'flags',
            'targets': ['master', 'agent']
        }),
        ('/tasks', {
            'filtered_field': 'tasks',
            'bootstrap_function': run_task,
            'targets': ['master']
        })
    ])
    def test_mesos_endpoint_authz_filtering(self, superuser, peter, path, endpoint_info):
        """Test that Mesos endpoints which perform authorization-based filtering
        behave as expected with respect to authorization"""

        def request(url, authorized, filtered_field):
            if authorized:
                r = requests.get(url, headers=superuser.authheader)
            else:
                r = requests.get(url, headers=peter.authheader)

            log.debug(
                'Got %s with %s request for endpoint %s. Response: \n%s',
                r.status_code,
                'authorized' if authorized else 'unauthorized',
                url,
                r.text
            )

            assert r.status_code == 200

            data = r.json()
            filtered_field_is_nonempty = filtered_field in data and data[filtered_field]

            if authorized:
                assert filtered_field_is_nonempty
            else:
                assert not filtered_field_is_nonempty

        urls = {}
        urls['master'] = str(Url('', host=dcos.masters[0], port=5050))
        urls['agent'] = str(Url('', host=dcos.agents[0], port=5051))

        for target in endpoint_info['targets']:
            log.info('Test Mesos %s endpoint: %s', target, path)
            for authorized in [False, True]:
                if 'bootstrap_function' in endpoint_info:
                    endpoint_info['bootstrap_function'](superuser)

                request(urls[target] + path,
                        authorized=authorized,
                        filtered_field=endpoint_info['filtered_field'])

    def test_mesos_weights_endpoint_authz(self, superuser, peter):
        """Test that Mesos weights-related endpoints perform authorization
        correctly"""

        def set_weight(weight, authorized):
            url = str(Url('', host=dcos.masters[0], port=5050))
            headers = superuser.authheader if authorized else peter.authheader
            data = '[{"role": "test-weights-role", "weight": ' + str(weight) + '}]'
            r = requests.put(url + '/weights', headers=headers, data=data)

            log.debug(
                'Got %s with %s PUT request for endpoint ' + url + '/weights. Response: \n%s',
                r.status_code,
                'authorized' if authorized else 'unauthorized',
                url,
                r.text
            )

            if authorized:
                assert r.status_code == 200
            else:
                assert r.status_code == 403

        def check_weight(weight, authorized):
            url = str(Url('', host=dcos.masters[0], port=5050))
            headers = superuser.authheader if authorized else peter.authheader
            r = requests.get(url + '/weights', headers=headers)

            log.debug(
                'Got %s with %s GET request for endpoint ' + url + '/weights. Response: \n%s',
                r.status_code,
                'authorized' if authorized else 'unauthorized',
                url,
                r.text
            )

            assert r.status_code == 200

            data = r.json()

            if authorized:
                for weight_json in data:
                    if weight_json['role'] == 'test-weights-role':
                        weight_found = True
                        assert weight_json['weight'] == weight
                assert weight_found
            else:
                assert len(data) == 0

        # First, verify that setting the weight when unauthorized will fail. Then,
        # set the weight successfully.
        set_weight(2.5, authorized=False)
        set_weight(2.5, authorized=True)

        # Check that unauthorized GET requests fail, then check that weight was set.
        check_weight(2.5, authorized=False)
        check_weight(2.5, authorized=True)

        # Mesos does not provide a way to remove weights, so we set it to the
        # default value of 1.0 here.
        set_weight(1.0, authorized=True)
        check_weight(1.0, authorized=True)

    def test_mesos_reservation_volume_endpoints_authz(self, superuser, peter):
        """Test that Mesos reservation and volume endpoints perform authorization
        correctly. A dynamic reservation is made for disk, a persistent volume is
        created with the reservation, and then both are destroyed"""

        # Get a valid agent ID.
        r = requests.get(
            Url('/mesos/master/state'),
            headers=superuser.authheader
        )
        assert r.status_code == 200

        # Find a private agent with unreserved resources.
        agent_id = None
        for agent in r.json()['slaves']:
            if 'slave_public' in agent['reserved_resources']:
                continue
            agent_id = agent['id']
            break

        assert agent_id

        def post(path, authorized, data, principal):
            url = str(Url('', host=dcos.masters[0], port=5050))
            if authorized:
                headers = superuser.authheader
            else:
                headers = peter.authheader

            prepped_data = copy.copy(data).replace('#PRINCIPAL#', principal)
            r = requests.post(url + path, headers=headers, data=prepped_data)

            log.debug(
                'Got %s with %s POST request for endpoint ' + url + path + '. Response: \n%s',
                r.status_code,
                'authorized' if authorized else 'unauthorized',
                url,
                r.text
            )

            if authorized:
                assert r.status_code == 202
            else:
                assert r.status_code == 403

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

        post('/reserve', False, reservation_data, peter.uid)
        post('/reserve', True, reservation_data, superuser.uid)

        post('/create-volumes', False, volume_data, peter.uid)
        post('/create-volumes', True, volume_data, superuser.uid)

        # Once the volume has been created we use the superuser's principal, since
        # this is the principal that's been associated with the created volume.
        post('/destroy-volumes', False, volume_data, superuser.uid)
        post('/destroy-volumes', True, volume_data, superuser.uid)

        post('/unreserve', False, reservation_data, superuser.uid)
        post('/unreserve', True, reservation_data, superuser.uid)

    @pytest.mark.parametrize(("target", "url"), [
        ('master', str(Url('', host=dcos.masters[0], port=5050))),
        ('slave', str(Url('', host=dcos.agents[0], port=5051)))
    ])
    @pytest.mark.parametrize("path", [
        '/files/debug',
        '/files/read?path=/#TARGET#/log',
        '/files/download?path=/#TARGET#/log',
        '/files/browse?path=/#TARGET#/log'
    ])
    def test_mesos_files_endpoints_authz(self, superuser, peter, target, url, path):
        """Test that Mesos files endpoints perform authorization correctly"""

        def get(path, authorized, target, url):
            if authorized:
                headers = superuser.authheader
            else:
                headers = peter.authheader

            r = requests.get(url + path.replace('#TARGET#', target), headers=headers)

            log.debug(
                'Got %s with %s GET request for endpoint ' + url + path + '. Response: \n%s',
                r.status_code,
                'authorized' if authorized else 'unauthorized',
                url,
                r.text
            )

            if authorized:
                assert r.status_code == 200
            else:
                assert r.status_code == 403

        for authorized in [True, False]:
            get(path, authorized, target, url)

    def test_mesos_quota_endpoint_authz(self, superuser, peter):
        """Test that Mesos master's '/quota' endpoint performs authorization correctly"""

        master_host = str(Url('', host=dcos.masters[0], port=5050))
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

        # A POST request to the quota endpoint sets quota for a particular role.
        def post(authorized, headers):
            url = master_host + '/quota'

            r = requests.post(url, headers=headers, data=data)
            print(r.text)
            log.debug(
                'Got %s with %s POST request for endpoint ' + url + '. Response: \n%s',
                r.status_code,
                'authorized' if authorized else 'unauthorized',
                url,
                r.text
            )

            if authorized:
                assert r.status_code == 200
            else:
                assert r.status_code == 403

        # A GET request to the quota endpoint gets a list of all set quotas.
        def get(authorized, headers):
            url = master_host + '/quota'
            r = requests.get(url, headers=headers)

            log.debug(
                'Got %s with %s GET request for endpoint ' + url + '. Response: \n%s',
                r.status_code,
                'authorized' if authorized else 'unauthorized',
                url,
                r.text
            )

            assert r.status_code == 200

            quotas = r.json()
            quota_found = False
            if 'infos' in quotas:
                for info in quotas['infos']:
                    if (info['role'] == test_role and
                            info['guarantee'][0]['name'] == 'cpus' and
                            info['guarantee'][0]['scalar']['value'] == 1):
                        quota_found = True

            if authorized:
                assert quota_found
            else:
                assert not quota_found

        # A DELETE request to the quota endpoint removes any quota that was set
        # for a particular role.
        def delete(authorized, headers):
            url = master_host + '/quota/' + test_role
            r = requests.delete(url, headers=headers)

            log.debug(
                'Got %s with %s DELETE request for endpoint ' + url + '. Response: \n%s',
                r.status_code,
                'authorized' if authorized else 'unauthorized',
                url,
                r.text
            )

            if authorized:
                assert r.status_code == 200
            else:
                assert r.status_code == 403

        # Set, get, and remove quota; first unauthorized and then authorized.
        for request_function in (post, get, delete):
            for authorized in (False, True):
                if authorized:
                    headers = superuser.authheader
                else:
                    headers = peter.authheader

                request_function(authorized, headers)
