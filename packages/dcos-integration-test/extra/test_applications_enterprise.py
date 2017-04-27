import uuid


def test_enterprise_if_marathon_pods_can_be_deployed_with_mesos_containerizer(superuser_api_session):
    """Marathon pods deployment integration test using the Mesos Containerizer

    This test verifies that a Marathon pod can be deployed.
    """
    test_uuid = uuid.uuid4().hex

    pod_definition = {
        'id': '/integration-test-pods-{}'.format(test_uuid),
        'scaling': {'kind': 'fixed', 'instances': 1},
        'environment': {'PING': 'PONG'},
        'containers': [
            {
                'name': 'ct1',
                'resources': {'cpus': 0.1, 'mem': 32},
                'image': {'kind': 'DOCKER', 'id': 'debian:jessie'},
                'exec': {'command': {'shell': 'touch foo'}},
                'healthcheck': {'command': {'shell': 'test -f foo'}}
            },
            {
                'name': 'ct2',
                'resources': {'cpus': 0.1, 'mem': 32},
                'exec': {'command': {'shell': 'echo $PING > foo; while true; do sleep 1; done'}},
                'healthcheck': {'command': {'shell': 'test $PING = `cat foo`'}}
            }
        ],
        'networks': [{'mode': 'host'}]
    }

    with superuser_api_session.marathon.deploy_pod_and_cleanup(pod_definition):
        # Trivial app if it deploys, there is nothing else to check
        pass
