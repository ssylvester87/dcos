"""
Test Enterprise DC/OS Signal Service
"""
import json
import os
import pytest
import subprocess

from dcostests import dcos


# Add an adapter for legacy tests.
@pytest.fixture
def cluster():
    return dcos


def test_ee_signal_service(cluster):
    """
    signal-service runs on an hourly timer, this test runs it as a one-off
    and pushes the results to the test_server app for easy retrieval
    """
    dcos_version = os.getenv("DCOS_VERSION", "")
    signal_config = open('/opt/mesosphere/etc/dcos-signal-config.json', 'r')
    signal_config_data = json.loads(signal_config.read())
    customer_key = signal_config_data.get('customer_key', 'CUSTOMER KEY NOT SET')
    cluster_id_file = open('/var/lib/dcos/cluster-id')
    cluster_id = cluster_id_file.read().strip()

    print("Version: ", dcos_version)
    print("Customer Key: ", customer_key)
    print("Cluster ID: ", cluster_id)

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
        'provider': cluster.provider,
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
        'bouncer-service',
        'ca-service',
        'cosmos-service',
        'exhibitor-service',
        'history-service',
        'logrotate-master-service',
        'logrotate-master-timer',
        'marathon-service',
        'mesos-dns-service',
        'mesos-master-service',
        'metronome-service',
        'networking_api-service',
        'secrets-service',
        'signal-service',
        'vault-service']
    all_node_units = [
        'adminrouter-reload-service',
        'adminrouter-reload-timer',
        '3dt-service',
        '3dt-socket',
        'epmd-service',
        'gen-resolvconf-service',
        'gen-resolvconf-timer',
        'minuteman-service',
        'navstar-service',
        'signal-timer',
        'spartan-service',
        'spartan-watchdog-service',
        'spartan-watchdog-timer']
    slave_units = [
        'mesos-slave-service',
        'vol-discovery-priv-agent-service']
    public_slave_units = [
        'mesos-slave-public-service',
        'vol-discovery-pub-agent-service']
    all_slave_units = [
        'adminrouter-agent-service',
        'logrotate-agent-service',
        'logrotate-agent-timer',
        'rexray-service']

    for unit in master_units:
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-total".format(unit)] = len(cluster.masters)
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-unhealthy".format(unit)] = 0
    for unit in all_node_units:
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-total".format(unit)] = len(
            cluster.agents+cluster.masters)
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-unhealthy".format(unit)] = 0
    for unit in slave_units:
        total_key = "health-unit-dcos-{}-total".format(unit)
        exp_data['diagnostics']['properties'][total_key] = len(cluster.private_agents)
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-unhealthy".format(unit)] = 0
    for unit in public_slave_units:
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-total".format(unit)] = len(cluster.public_agents)
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-unhealthy".format(unit)] = 0
    for unit in all_slave_units:
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-total".format(unit)] = len(cluster.agents)
        exp_data['diagnostics']['properties']["health-unit-dcos-{}-unhealthy".format(unit)] = 0

    # Check the entire hash of diagnostics data
    assert r_data['diagnostics'] == exp_data['diagnostics']
    # Check a subset of things regarding Mesos that we can logically check for
    framework_names = [x['name'] for x in r_data['mesos']['properties']['frameworks']]
    assert 'marathon' in framework_names
    assert 'metronome' in framework_names
    # There are no packages installed by default on the integration test, ensure the key exists
    assert len(r_data['cosmos']['properties']['package_list']) == 0
