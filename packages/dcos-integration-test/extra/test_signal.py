"""
Test Enterprise DC/OS Signal Service
TODO: this test only differs from upstream in the services that it checks for, rather
    find a method such that we do not need to duplicate so much code
"""
import json
import os
import subprocess

from ee_helpers import dcos_config

from pkgpanda.util import load_json, load_string


def test_ee_signal_service(superuser_api_session):
    """
    signal-service runs on an hourly timer, this test runs it as a one-off
    and pushes the results to the test_server app for easy retrieval
    """
    dcos_version = os.getenv("DCOS_VERSION", "")

    signal_config = load_json('/opt/mesosphere/etc/dcos-signal-config.json')
    signal_config.update(load_json('/opt/mesosphere/etc/dcos-signal-extra.json'))

    customer_key = signal_config.get('customer_key', 'CUSTOMER KEY NOT SET')
    cluster_id = load_string('/var/lib/dcos/cluster-id').strip()

    # sudo is required to read /run/dcos/etc/signal-service/service_account.json
    env = os.environ.copy()
    signal_cmd = ["sudo", "-E", "/opt/mesosphere/bin/dcos-signal", "-test"]
    # universal_newlines means utf-8
    with subprocess.Popen(signal_cmd, stdout=subprocess.PIPE, universal_newlines=True, env=env) as p:
        signal_results = p.stdout.read()

    r_data = json.loads(signal_results)

    exp_data = {
        'diagnostics': {
            'event': 'health',
            'userId': customer_key,
            'anonymousId': cluster_id,
            'properties': {}
        },
        'cosmos': {
            'event': 'package_list',
            'anonymousId': cluster_id,
            'properties': {}
        },
        'mesos': {
            'event': 'mesos_track',
            'anonymousId': cluster_id,
            'properties': {}
        }
    }

    # Generic properties which are the same between all tracks
    generic_properties = {
        'platform': dcos_config['platform'],
        'provider': dcos_config['provider'],
        'source': 'cluster',
        'clusterId': cluster_id,
        'customerKey': customer_key,
        'environmentVersion': dcos_version,
        'variant': 'enterprise'
    }

    # Insert the generic property data which is the same between all signal tracks
    exp_data['diagnostics']['properties'].update(generic_properties)
    exp_data['cosmos']['properties'].update(generic_properties)
    exp_data['mesos']['properties'].update(generic_properties)

    # Insert all the diagnostics data programmatically
    master_units = [
        'adminrouter-service',
        'backup-master-service',
        'backup-master-socket',
        'bouncer-service',
        'bouncer-legacy-service',
        'ca-service',
        'cosmos-service',
        'cockroach-service',
        'log-master-service',
        'log-master-socket',
        'exhibitor-service',
        'history-service',
        'logrotate-master-service',
        'logrotate-master-timer',
        'marathon-service',
        'mesos-dns-service',
        'metrics-master-service',
        'metrics-master-socket',
        'mesos-master-service',
        'metronome-service',
        'networking_api-service',
        'secrets-service',
        'secrets-socket',
        'signal-service',
        'vault-service']
    all_node_units = [
        'diagnostics-service',
        'diagnostics-socket',
        'epmd-service',
        'gen-resolvconf-service',
        'gen-resolvconf-timer',
        'navstar-service',
        'pkgpanda-api-service',
        'signal-timer',
        'spartan-service',
        'spartan-watchdog-service',
        'spartan-watchdog-timer']
    slave_units = [
        'mesos-slave-service']
    public_slave_units = [
        'mesos-slave-public-service']
    all_slave_units = [
        'adminrouter-agent-service',
        'docker-gc-service',
        'docker-gc-timer',
        'log-agent-service',
        'log-agent-socket',
        'logrotate-agent-service',
        'logrotate-agent-timer',
        'metrics-agent-service',
        'metrics-agent-socket',
        'rexray-service']

    for unit in master_units:
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-total".format(unit)] = \
            len(superuser_api_session.masters)
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-unhealthy".format(unit)] = 0
    for unit in all_node_units:
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-total".format(unit)] = \
            len(superuser_api_session.all_slaves + superuser_api_session.masters)
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-unhealthy".format(unit)] = 0
    for unit in slave_units:
        total_key = "health-unit-dcos-{}-total".format(unit)
        exp_data['diagnostics']['properties'][total_key] = len(superuser_api_session.slaves)
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-unhealthy".format(unit)] = 0
    for unit in public_slave_units:
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-total".format(unit)] = \
            len(superuser_api_session.public_slaves)
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-unhealthy".format(unit)] = 0
    for unit in all_slave_units:
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-total".format(unit)] = \
            len(superuser_api_session.all_slaves)
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-unhealthy".format(unit)] = 0

    # Check the entire hash of diagnostics data
    assert r_data['diagnostics'] == exp_data['diagnostics']
    # Check a subset of things regarding Mesos that we can logically check for
    framework_names = [x['name'] for x in r_data['mesos']['properties']['frameworks']]
    assert 'marathon' in framework_names
    assert 'metronome' in framework_names
    # There are no packages installed by default on the integration test, ensure the key exists
    assert len(r_data['cosmos']['properties']['package_list']) == 0
