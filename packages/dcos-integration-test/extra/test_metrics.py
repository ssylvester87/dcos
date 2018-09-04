import pytest
import retrying

__maintainer__ = 'mnaboka'
__contact__ = 'dcos-cluster-ops@mesosphere.io'


LATENCY = 60


def test_metrics_agents_ping(dcos_api_session):
    """ Test that the metrics service is up on masters.
    """
    for agent in dcos_api_session.slaves:
        response = dcos_api_session.metrics.get('/ping', node=agent)
        assert response.status_code == 200, 'Status code: {}, Content {}'.format(response.status_code, response.content)
        assert response.json()['ok'], 'Status code: {}, Content {}'.format(response.status_code, response.content)
        'agent.'

    for agent in dcos_api_session.public_slaves:
        response = dcos_api_session.metrics.get('/ping', node=agent)
        assert response.status_code == 200, 'Status code: {}, Content {}'.format(response.status_code, response.content)
        assert response.json()['ok'], 'Status code: {}, Content {}'.format(response.status_code, response.content)


@pytest.mark.supportedwindows
def test_metrics_masters_ping(dcos_api_session):
    for master in dcos_api_session.masters:
        response = dcos_api_session.metrics.get('/ping', node=master)
        assert response.status_code == 200, 'Status code: {}, Content {}'.format(response.status_code, response.content)
        assert response.json()['ok'], 'Status code: {}, Content {}'.format(response.status_code, response.content)


@pytest.mark.parametrize("prometheus_port", [61091, 61092])
def test_metrics_agents_prom(dcos_api_session, prometheus_port):
    for agent in dcos_api_session.slaves:
        response = dcos_api_session.session.request('GET', 'http://' + agent + ':{}/metrics'.format(prometheus_port))
        assert response.status_code == 200, 'Status code: {}'.format(response.status_code)


@pytest.mark.parametrize("prometheus_port", [61091, 61092])
def test_metrics_masters_prom(dcos_api_session, prometheus_port):
    for master in dcos_api_session.masters:
        response = dcos_api_session.session.request('GET', 'http://' + master + ':{}/metrics'.format(prometheus_port))
        assert response.status_code == 200, 'Status code: {}'.format(response.status_code)


def test_metrics_node(dcos_api_session):
    """Test that the '/system/v1/metrics/v0/node' endpoint returns the expected
    metrics and metric metadata.
    """
    def expected_datapoint_response(response):
        """Enure that the "node" endpoint returns a "datapoints" dict.
        """
        assert 'datapoints' in response, '"datapoints" dictionary not found'
        'in response, got {}'.format(response)

        for dp in response['datapoints']:
            assert 'name' in dp, '"name" parameter should not be empty, got {}'.format(dp)
            if 'filesystem' in dp['name']:
                assert 'tags' in dp, '"tags" key not found, got {}'.format(dp)

                assert 'path' in dp['tags'], ('"path" tag not found for filesystem metric, '
                                              'got {}'.format(dp))

                assert len(dp['tags']['path']) > 0, ('"path" tag should not be empty for '
                                                     'filesystem metrics, got {}'.format(dp))

        return True

    def expected_dimension_response(response):
        """Ensure that the "node" endpoint returns a dimensions dict that
        contains a non-empty string for cluster_id.
        """
        assert 'dimensions' in response, '"dimensions" object not found in'
        'response, got {}'.format(response)

        assert 'cluster_id' in response['dimensions'], '"cluster_id" key not'
        'found in dimensions, got {}'.format(response)

        assert response['dimensions']['cluster_id'] != "", 'expected cluster to contain a value'

        return True

    # private agents
    for agent in dcos_api_session.slaves:
        response = dcos_api_session.metrics.get('/node', node=agent)

        assert response.status_code == 200, 'Status code: {}, Content {}'.format(
            response.status_code, response.content)
        assert expected_datapoint_response(response.json())
        assert expected_dimension_response(response.json())

    # public agents
    for agent in dcos_api_session.public_slaves:
        response = dcos_api_session.metrics.get('/node', node=agent)

        assert response.status_code == 200, 'Status code: {}, Content {}'.format(
            response.status_code, response.content)
        assert expected_datapoint_response(response.json())
        assert expected_dimension_response(response.json())

    # masters
    for master in dcos_api_session.masters:
        response = dcos_api_session.metrics.get('/node', node=master)

        assert response.status_code == 200, 'Status code: {}, Content {}'.format(
            response.status_code, response.content)
        assert expected_datapoint_response(response.json())
        assert expected_dimension_response(response.json())


def test_metrics_containers(dcos_api_session):
    """If there's a deployed container on the slave, iterate through them to check for
    the statsd-emitter executor. When found, query it's /app endpoint to test that
    it's sending the statsd metrics as expected.
    """
    # Helper func to check for non-unique CID's in a given /containers/id endpoint
    def check_cid(registry):
        if len(registry) <= 1:
            return True

        cid1 = registry[len(registry) - 1]
        cid2 = registry[len(registry) - 2]
        if cid1 != cid2:
            raise ValueError('{} != {}'.format(cid1, cid2))

        return True

    def check_tags(tags: dict, expected_tag_names: set):
        """Assert that tags contains only expected keys with nonempty values."""
        assert set(tags.keys()) == expected_tag_names
        for tag_name, tag_val in tags.items():
            assert tag_val != '', 'Value for tag "%s" must not be empty'.format(tag_name)

    @retrying.retry(wait_fixed=2000, stop_max_delay=LATENCY * 1000)
    def test_containers(app_endpoints):

        debug_task_name = []

        for agent in app_endpoints:

            # Retry for two and a half minutes since the collector collects
            # state every 2 minutes to propogate containers to the API
            @retrying.retry(wait_fixed=2000, stop_max_delay=150000)
            def wait_for_container_propogation():
                response = dcos_api_session.metrics.get('/containers', node=agent.host)
                assert response.status_code == 200
                assert len(response.json()) > 0, 'must have at least 1 container'

            wait_for_container_propogation()

            response = dcos_api_session.metrics.get('/containers', node=agent.host)
            for c in response.json():
                # Test that /containers/<id> responds with expected data
                container_id_path = '/containers/{}'.format(c)
                container_response = dcos_api_session.metrics.get(container_id_path, node=agent.host)

                # /containers/<container_id> should always respond succesfully
                assert container_response.status_code == 200

                assert 'datapoints' in container_response.json(), 'got {}'.format(container_response.json())

                cid_registry = []
                for dp in container_response.json()['datapoints']:
                    # Verify expected tags are present.
                    assert 'tags' in dp, 'got {}'.format(dp)
                    expected_tag_names = {
                        'container_id',
                    }
                    if 'executor_name' in dp['tags']:
                        # if present we want to make sure it has a valid value.
                        expected_tag_names.add('executor_name')
                    if dp['name'].startswith('blkio.'):
                        # blkio stats have 'blkio_device' tags.
                        expected_tag_names.add('blkio_device')
                    check_tags(dp['tags'], expected_tag_names)

                    # Ensure all container ID's in the container/<id> endpoint are
                    # the same.
                    cid_registry.append(dp['tags']['container_id'])
                    assert(check_cid(cid_registry))

                assert 'dimensions' in container_response.json(), 'got {}'.format(container_response.json())
                assert 'task_name' in container_response.json()['dimensions'], 'got {}'.format(
                    container_response.json()['dimensions'])

                debug_task_name.append(container_response.json()['dimensions']['task_name'])

                # looking for "statsd-emitter"
                if 'statsd-emitter' == container_response.json()['dimensions']['task_name']:
                    # Test that /app response is responding with expected data
                    app_response = dcos_api_session.metrics.get('/containers/{}/app'.format(c), node=agent.host)
                    assert app_response.status_code == 200
                    'got {}'.format(app_response.status_code)

                    # Ensure all /container/<id>/app data is correct
                    assert 'datapoints' in app_response.json(), 'got {}'.format(app_response.json())

                    # We expect three datapoints, could be in any order
                    uptime_dp = None
                    for dp in app_response.json()['datapoints']:
                        if dp['name'] == 'statsd_tester_time_uptime':
                            uptime_dp = dp
                            break

                    # If this metric is missing, statsd-emitter's metrics were not received
                    assert uptime_dp is not None, 'got {}'.format(app_response.json())

                    datapoint_keys = ['name', 'value', 'unit', 'timestamp', 'tags']
                    for k in datapoint_keys:
                        assert k in uptime_dp, 'got {}'.format(uptime_dp)

                    expected_tag_names = {
                        'dcos_cluster_id',
                        'test_tag_key',
                        'dcos_cluster_name',
                        'host'
                    }
                    check_tags(uptime_dp['tags'], expected_tag_names)
                    assert uptime_dp['tags']['test_tag_key'] == 'test_tag_value', 'got {}'.format(uptime_dp)

                    assert 'dimensions' in app_response.json(), 'got {}'.format(app_response.json())

                    return True

        assert False, 'Did not find statsd-emitter container, executor IDs found: {}'.format(debug_task_name)

    marathon_config = {
        "id": "/statsd-emitter",
        "cmd": "/opt/mesosphere/bin/./statsd-emitter -debug",
        "cpus": 0.5,
        "mem": 128.0,
        "instances": 1
    }
    with dcos_api_session.marathon.deploy_and_cleanup(marathon_config, check_health=False):
        endpoints = dcos_api_session.marathon.get_app_service_endpoints(marathon_config['id'])
        assert len(endpoints) == 1, 'The marathon app should have been deployed exactly once.'
        test_containers(endpoints)
