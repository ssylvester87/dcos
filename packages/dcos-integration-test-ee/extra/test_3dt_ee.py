import gzip
import json
import logging
import os
import tempfile
import zipfile

import pytest
import requests
import retrying

from dcostests import DDDTUrl, dcos


PORT_3DT_MASTER = 443
PORT_3DT_AGENT = 61002


# Add an adapter for legacy tests.
@pytest.fixture
def cluster():
    return dcos


class Node:
    def __init__(self, ip, role):
        self.ip = ip
        self.role = role
        self.port = PORT_3DT_MASTER
        if self.role in ['agent', 'public_agent']:
            self.port = PORT_3DT_AGENT


def make_nodes(hosts, role):
    assert isinstance(hosts, list)
    assert isinstance(role, str)
    return [Node(host, role) for host in hosts]


def make_3dt_request(host, endpoint, superuser):
    assert isinstance(host, Node)
    assert endpoint.startswith('/')

    url = DDDTUrl(endpoint, host=host.ip, port=host.port)
    response = requests.get(url, headers=superuser.authheader)

    assert response.ok
    json_response = response.json()
    assert len(json_response) > 0

    return json_response


def test_3dt_health(cluster, superuser):
    """
    test health endpoint /system/health/v1
    """
    required_fields = ['units', 'hostname', 'ip', 'dcos_version', 'node_role', 'mesos_id', '3dt_version', 'system']
    required_fields_unit = ['id', 'health', 'output', 'description', 'help', 'name']
    required_system_fields = ['memory', 'load_avarage', 'partitions', 'disk_usage']

    # Check all masters 3DT instances on base port since this is extra-cluster request (outside localhost)
    for host in make_nodes(cluster.masters, 'master'):
        response = make_3dt_request(host, '/', superuser)
        assert len(response) == len(required_fields), 'response must have the following fields: {}'.format(
            ', '.join(required_fields)
        )

        # validate units
        assert 'units' in response, 'units field not found'
        assert isinstance(response['units'], list), 'units field must be a list'
        assert len(response['units']) > 0, 'units field cannot be empty'
        for unit in response['units']:
            assert len(unit) == len(required_fields_unit), 'unit must have the following fields: {}'.format(
                ', '.join(required_fields_unit)
            )
            for required_field_unit in required_fields_unit:
                assert required_field_unit in unit, '{} must be in a unit repsonse'

            # id, health and description cannot be empty
            assert unit['id'], 'id field cannot be empty'
            assert unit['health'] in [0, 1], 'health field must be 0 or 1'
            assert unit['description'], 'description field cannot be empty'

        # check all required fields but units
        for required_field in required_fields[1:]:
            assert required_field in response, '{} field not found'.format(required_field)
            assert response[required_field], '{} cannot be empty'.format(required_field)

        # check system metrics
        assert len(response['system']) == len(required_system_fields), 'fields required: {}'.format(
            ', '.join(required_system_fields))

        for sys_field in required_system_fields:
            assert sys_field in response['system'], 'system metric {} is missing'.format(sys_field)
            assert response['system'][sys_field], 'system metric {} cannot be empty'.format(sys_field)

    for host in make_nodes(cluster.agents, 'agent'):
        response = make_3dt_request(host, '/', superuser)
        assert len(response) == len(required_fields), 'response must have the following fields: {}'.format(
            ', '.join(required_fields)
        )

        # validate units
        assert 'units' in response, 'units field not found'
        assert isinstance(response['units'], list), 'units field must be a list'
        assert len(response['units']) > 0, 'units field cannot be empty'
        for unit in response['units']:
            assert len(unit) == len(required_fields_unit), 'unit must have the following fields: {}'.format(
                ', '.join(required_fields_unit)
            )
            for required_field_unit in required_fields_unit:
                assert required_field_unit in unit, '{} must be in a unit repsonse'

            # id, health and description cannot be empty
            assert unit['id'], 'id field cannot be empty'
            assert unit['health'] in [0, 1], 'health field must be 0 or 1'
            assert unit['description'], 'description field cannot be empty'

        # check all required fields but units
        for required_field in required_fields[1:]:
            assert required_field in response, '{} field not found'.format(required_field)
            assert response[required_field], '{} cannot be empty'.format(required_field)

        # check system metrics
        assert len(response['system']) == len(required_system_fields), 'fields required: {}'.format(
            ', '.join(required_system_fields))

        for sys_field in required_system_fields:
            assert sys_field in response['system'], 'system metric {} is missing'.format(sys_field)
            assert response['system'][sys_field], 'system metric {} cannot be empty'.format(sys_field)


def validate_node(nodes):
    assert isinstance(nodes, list), 'input argument must be a list'
    assert len(nodes) > 0, 'input argument cannot be empty'
    required_fields = ['host_ip', 'health', 'role']

    for node in nodes:
        logging.info('check node reponse: {}'.format(node))
        assert len(node) == len(required_fields), 'node should have the following fields: {}'.format(
            ', '.join(required_fields)
        )
        for required_field in required_fields:
            assert required_field in node, '{} must be in node'.format(required_field)

        # host_ip, health, role fields cannot be empty
        assert node['health'] in [0, 1], 'health must be 0 or 1'
        assert node['host_ip'], 'host_ip cannot be empty'
        assert node['role'], 'role cannot be empty'


def test_3dt_nodes(cluster, superuser):
    """
    test a list of nodes with statuses endpoint /system/health/v1/nodes
    """
    for master in make_nodes(cluster.masters, 'master'):
        response = make_3dt_request(master, '/nodes', superuser)
        assert len(response) == 1, 'nodes response must have only one field: nodes'
        assert 'nodes' in response
        assert isinstance(response['nodes'], list)
        assert len(response['nodes']) == len(cluster.masters + cluster.agents), (
            'a number of nodes in response must be {}'.format(len(cluster.masters + cluster.agents)))

        # test nodes
        validate_node(response['nodes'])


def test_3dt_nodes_node(cluster, superuser):
    """
    test a specific node enpoint /system/health/v1/nodes/<node>
    """
    for master in make_nodes(cluster.masters, 'master'):
        # get a list of nodes
        response = make_3dt_request(master, '/nodes', superuser)
        nodes = list(map(lambda node: node['host_ip'], response['nodes']))
        logging.info('received the following nodes: {}'.format(nodes))

        for node in nodes:
            node_response = make_3dt_request(master, '/nodes/{}'.format(node), superuser)
            validate_node([node_response])


def validate_units(units):
    assert isinstance(units, list), 'input argument must be list'
    assert len(units) > 0, 'input argument cannot be empty'
    required_fields = ['id', 'name', 'health', 'description']

    for unit in units:
        logging.info('validating unit {}'.format(unit))
        assert len(unit) == len(required_fields), 'a unit must have the following fields: {}'.format(
            ', '.join(required_fields)
        )
        for required_field in required_fields:
            assert required_field in unit, 'unit response must have field: {}'.format(required_field)

        # a unit must have all 3 fields not empty
        assert unit['id'], 'id field cannot be empty'
        assert unit['name'], 'name field cannot be empty'
        assert unit['health'] in [0, 1], 'health must be 0 or 1'
        assert unit['description'], 'description field cannot be empty'


def validate_unit(unit):
    assert isinstance(unit, dict), 'input argument must be a dict'
    logging.info('validating unit: {}'.format(unit))

    required_fields = ['id', 'health', 'output', 'description', 'help', 'name']
    assert len(unit) == len(required_fields), 'unit must have the following fields: {}'.format(
        ', '.join(required_fields)
    )
    for required_field in required_fields:
        assert required_field in unit, '{} must be in a unit'.format(required_field)

    # id, name, health, description, help should not be empty
    assert unit['id'], 'id field cannot be empty'
    assert unit['name'], 'name field cannot be empty'
    assert unit['health'] in [0, 1], 'health must be 0 or 1'
    assert unit['description'], 'description field cannot be empty'
    assert unit['help'], 'help field cannot be empty'


def test_3dt_nodes_node_units(cluster, superuser):
    """
    test a list of units from a specific node, endpoint /system/health/v1/nodes/<node>/units
    """
    for master in make_nodes(cluster.masters, 'master'):
        # get a list of nodes
        response = make_3dt_request(master, '/nodes', superuser)
        nodes = list(map(lambda node: node['host_ip'], response['nodes']))
        logging.info('received the following nodes: {}'.format(nodes))

        for node in nodes:
            node_response = make_3dt_request(master, '/nodes/{}'.format(node), superuser)
            logging.info('node reponse: {}'.format(node_response))
            units_response = make_3dt_request(master, '/nodes/{}/units'.format(node), superuser)
            logging.info('units reponse: {}'.format(units_response))

            assert len(units_response) == 1, 'unit response should have only 1 field `units`'
            assert 'units' in units_response
            validate_units(units_response['units'])


def test_3dt_nodes_node_units_unit(cluster, superuser):
    """
    test a specific unit for a specific node, endpoint /system/health/v1/nodes/<node>/units/<unit>
    """
    for master in make_nodes(cluster.masters, 'master'):
        response = make_3dt_request(master, '/nodes', superuser)
        nodes = list(map(lambda node: node['host_ip'], response['nodes']))
        for node in nodes:
            units_response = make_3dt_request(master, '/nodes/{}/units'.format(node), superuser)
            unit_ids = list(map(lambda unit: unit['id'], units_response['units']))
            logging.info('unit ids: {}'.format(unit_ids))

            for unit_id in unit_ids:
                validate_unit(
                    make_3dt_request(master, '/nodes/{}/units/{}'.format(node, unit_id), superuser))


def test_3dt_units(cluster, superuser):
    """
    test a list of collected units, endpoint /system/health/v1/units
    """
    # get all unique unit names
    all_units = set()
    for master in make_nodes(cluster.masters, 'master'):
        node_response = make_3dt_request(master, '/', superuser)
        for unit in node_response['units']:
            all_units.add(unit['id'])

    for agent in make_nodes(cluster.agents, 'agent'):
        node_response = make_3dt_request(agent, '/', superuser)
        for unit in node_response['units']:
            all_units.add(unit['id'])

    logging.info('Master units: {}'.format(all_units))

    # test against masters
    for master in make_nodes(cluster.masters, 'master'):
        units_response = make_3dt_request(master, '/units', superuser)
        validate_units(units_response['units'])

        pulled_units = list(map(lambda unit: unit['id'], units_response['units']))
        logging.info('collected units: {}'.format(pulled_units))
        assert set(pulled_units) == all_units, 'not all units have been collected by 3dt puller, missing: {}'.format(
            set(pulled_units).symmetric_difference(all_units)
        )


def test_3dt_units_unit(cluster, superuser):
    """
    test a unit response in a right format, endpoint: /system/health/v1/units/<unit>
    """
    for master in make_nodes(cluster.masters, 'master'):
        units_response = make_3dt_request(master, '/units', superuser)
        pulled_units = list(map(lambda unit: unit['id'], units_response['units']))
        for unit in pulled_units:
            unit_response = make_3dt_request(master, '/units/{}'.format(unit), superuser)
            validate_units([unit_response])


def make_nodes_ip_map(cluster, superuser):
    """
    a helper function to make a map detected_ip -> external_ip
    """
    node_private_public_ip_map = {}
    for master in make_nodes(cluster.masters, 'master'):
        detected_ip = make_3dt_request(master, '/', superuser)['ip']
        node_private_public_ip_map[detected_ip] = master.ip

    for agent in make_nodes(cluster.agents, 'agent'):
        detected_ip = make_3dt_request(agent, '/', superuser)['ip']
        node_private_public_ip_map[detected_ip] = agent.ip

    logging.info('detected ips: {}'.format(node_private_public_ip_map))
    return node_private_public_ip_map


def test_3dt_units_unit_nodes(cluster, superuser):
    """
    test a list of nodes for a specific unit, endpoint /system/health/v1/units/<unit>/nodes
    """
    nodes_ip_map = make_nodes_ip_map(cluster, superuser)

    for master in make_nodes(cluster.masters, 'master'):
        units_response = make_3dt_request(master, '/units', superuser)
        pulled_units = list(map(lambda unit: unit['id'], units_response['units']))
        for unit in pulled_units:
            nodes_response = make_3dt_request(master, '/units/{}/nodes'.format(unit), superuser)
            validate_node(nodes_response['nodes'])

        # make sure dcos-mesos-master.service has master nodes and dcos-mesos-slave.service has agent nodes
        master_nodes_response = make_3dt_request(
            master, '/units/dcos-mesos-master.service/nodes', superuser)
        master_nodes = list(map(lambda node: nodes_ip_map.get(node['host_ip']), master_nodes_response['nodes']))
        logging.info('master_nodes: {}'.format(master_nodes))

        assert len(master_nodes) == len(cluster.masters), '{} != {}'.format(master_nodes, cluster.masters)
        assert set(master_nodes) == set(cluster.masters), 'a list of difference: {}'.format(
            set(master_nodes).symmetric_difference(set(cluster.masters))
        )

        agent_nodes_response = make_3dt_request(
            master, '/units/dcos-mesos-slave.service/nodes', superuser)
        agent_nodes = list(map(lambda node: nodes_ip_map.get(node['host_ip']), agent_nodes_response['nodes']))
        logging.info('aget_nodes: {}'.format(agent_nodes))
        assert len(agent_nodes) == len(cluster.private_agents), '{} != {}'.format(agent_nodes, cluster.private_agents)


def test_3dt_units_unit_nodes_node(cluster, superuser):
    """
    test a specific node for a specific unit, endpoint /system/health/v1/units/<unit>/nodes/<node>
    """
    required_node_fields = ['host_ip', 'health', 'role', 'output', 'help']

    for master in make_nodes(cluster.masters, 'master'):
        units_response = make_3dt_request(master, '/units', superuser)
        pulled_units = list(map(lambda unit: unit['id'], units_response['units']))
        logging.info('pulled units: {}'.format(pulled_units))
        for unit in pulled_units:
            nodes_response = make_3dt_request(master, '/units/{}/nodes'.format(unit), superuser)
            pulled_nodes = list(map(lambda node: node['host_ip'], nodes_response['nodes']))
            logging.info('pulled nodes: {}'.format(pulled_nodes))
            for node in pulled_nodes:
                node_response = make_3dt_request(
                    master, '/units/{}/nodes/{}'.format(unit, node), superuser)
                logging.info('node response: {}'.format(node_response))
                assert len(node_response) == len(required_node_fields), 'required fields: {}'.format(
                    ', '.format(required_node_fields)
                )

                for required_node_field in required_node_fields:
                    assert required_node_field in node_response, 'field {} must be set'.format(required_node_field)

                # host_ip, health, role, help cannot be empty
                assert node_response['host_ip'], 'host_ip field cannot be empty'
                assert node_response['health'] in [0, 1], 'health must be 0 or 1'
                assert node_response['role'], 'role field cannot be empty'
                assert node_response['help'], 'help field cannot be empty'


def test_3dt_selftest(cluster, superuser):
    """
    test invokes 3dt `self test` functionality
    """
    for master in make_nodes(cluster.masters, 'master'):
        response = make_3dt_request(master, '/selftest/info', superuser)
        for test_name, attrs in response.items():
            assert 'Success' in attrs, 'Field `Success` does not exist'
            assert 'ErrorMessage' in attrs, 'Field `ErrorMessage` does not exist'
            assert attrs['Success'], '{} failed, error message {}'.format(test_name, attrs['ErrorMessage'])


def test_3dt_report(cluster, superuser):
    """
    test 3dt report endpoint /system/health/v1/report
    """
    for master in make_nodes(cluster.masters, 'master'):
        report_response = make_3dt_request(master, '/report', superuser)
        assert 'Units' in report_response
        assert len(report_response['Units']) > 0

        assert 'Nodes' in report_response
        assert len(report_response['Nodes']) > 0


def _get_bundle_list(cluster, superuser):
    list_url = '/report/diagnostics/list/all'
    masters = make_nodes(cluster.masters, 'master')
    assert len(masters) > 0

    response = make_3dt_request(masters[0], list_url, superuser)
    logging.info('GET {}, response: {}'.format(list_url, response))

    bundles = []
    for _, bundle_list in response.items():
        if bundle_list is not None and isinstance(bundle_list, list) and len(bundle_list) > 0:
            # append bundles and get just the filename.
            bundles += map(lambda s: os.path.basename(s['file_name']), bundle_list)
    return bundles


def test_3dt_bundle_create(cluster, superuser):
    """
    test bundle create functionality
    """

    # start the diagnostics bundle job
    create_url = '/report/diagnostics/create'
    response = requests.post(DDDTUrl(create_url), data=json.dumps({"nodes": ["all"]}), headers=superuser.authheader)
    assert response.ok
    json_response = response.json()
    logging.info('POST {}, json_response: {}'.format(create_url, json_response))

    # make sure the job is done, timeout is 5 sec, wait between retying is 1 sec
    status_url = '/report/diagnostics/status/all'

    # TODO(mnaboka): fix delay bug
    # give 2 minutes for a job to finish
    @retrying.retry(stop_max_delay=1000 * 120, wait_fixed=1000)
    def wait_for_job():
        response = requests.get(DDDTUrl(status_url), headers=superuser.authheader)
        assert response.ok
        json_response = response.json()
        logging.info('GET {}, json_response: {}'.format(status_url, json_response))

        # check `is_running` attribute for each host. All of them must be False
        for _, attributes in json_response.items():
            assert not attributes['is_running']

        # sometimes it may take extra seconds to list bundles after the job is finished.
        # the job should finish within 5 seconds and listing should be available after 3 seconds.
        assert _get_bundle_list(cluster, superuser), 'get a list of bundles timeout'

    wait_for_job()

    # the job should be complete at this point.
    # check the listing for a zip file
    bundles = _get_bundle_list(cluster, superuser)
    assert len(bundles) == 1, 'bundle file not found'
    assert bundles[0] == json_response['extra']['bundle_name']


def verify_unit_response(zip_ext_file):
    assert isinstance(zip_ext_file, zipfile.ZipExtFile)
    unit_output = gzip.decompress(zip_ext_file.read())

    # TODO: This seems like a really fragile string to be searching for. This might need to be changed for
    # different localizations.
    assert 'Hint: You are currently not seeing messages from other users and the system' not in str(unit_output), (
        '3dt does not have permission to run `journalctl`')


def test_3dt_bundle_download_and_extract(cluster, superuser):
    """
    test bundle download and validate zip file
    """

    bundles = _get_bundle_list(cluster, superuser)
    assert bundles

    expected_common_files = ['dmesg-0.output.gz', 'opt/mesosphere/active.buildinfo.full.json.gz', '3dt-health.json']

    # these files are expected to be in archive for a master host
    expected_master_files = ['dcos-mesos-master.service.gz'] + expected_common_files

    # for agent host
    expected_agent_files = ['dcos-mesos-slave.service.gz'] + expected_common_files

    # for public agent host
    expected_public_agent_files = ['dcos-mesos-slave-public.service.gz'] + expected_common_files

    with tempfile.TemporaryDirectory() as tmp_dir:
        download_base_url = '/report/diagnostics/serve'
        for bundle in bundles:
            bundle_full_location = os.path.join(tmp_dir, bundle)
            with open(bundle_full_location, 'wb') as f:
                r = requests.get(DDDTUrl(os.path.join(download_base_url, bundle)), stream=True,
                                 headers=superuser.authheader)
                for chunk in r.iter_content(1024):
                    f.write(chunk)

            # validate bundle zip file.
            assert zipfile.is_zipfile(bundle_full_location)
            z = zipfile.ZipFile(bundle_full_location)

            # get a list of all files in a zip archive.
            archived_items = z.namelist()

            # make sure all required log files for master node are in place.
            for master_ip in cluster.masters:
                master_folder = master_ip + '_master/'

                # try to load 3dt health report and validate the report is for this host
                health_report = json.loads(z.read(master_folder + '3dt-health.json').decode())
                assert 'ip' in health_report
                assert health_report['ip'] == master_ip

                # make sure systemd unit output is correct and does not contain error message
                gzipped_unit_output = z.open(master_folder + 'dcos-mesos-master.service.gz')
                verify_unit_response(gzipped_unit_output)

                for expected_master_file in expected_master_files:
                    expected_file = master_folder + expected_master_file
                    assert expected_file in archived_items, 'expecting {} in {}'.format(expected_file, archived_items)

            # make sure all required log files for agent node are in place.
            for agent_ip in cluster.private_agents:
                agent_folder = agent_ip + '_agent/'

                # try to load 3dt health report and validate the report is for this host
                health_report = json.loads(z.read(agent_folder + '3dt-health.json').decode())
                assert 'ip' in health_report
                assert health_report['ip'] == agent_ip

                # make sure systemd unit output is correct and does not contain error message
                gzipped_unit_output = z.open(agent_folder + 'dcos-mesos-slave.service.gz')
                verify_unit_response(gzipped_unit_output)

                for expected_agent_file in expected_agent_files:
                    expected_file = agent_folder + expected_agent_file
                    assert expected_file in archived_items, 'expecting {} in {}'.format(expected_file, archived_items)

            # make sure all required log files for public agent node are in place.
            for public_agent_ip in cluster.public_agents:
                agent_public_folder = public_agent_ip + '_agent_public/'

                # try to load 3dt health report and validate the report is for this host
                health_report = json.loads(z.read(agent_public_folder + '3dt-health.json').decode())
                assert 'ip' in health_report
                assert health_report['ip'] == public_agent_ip

                # make sure systemd unit output is correct and does not contain error message
                gzipped_unit_output = z.open(agent_public_folder + 'dcos-mesos-slave-public.service.gz')
                verify_unit_response(gzipped_unit_output)

                for expected_public_agent_file in expected_public_agent_files:
                    expected_file = agent_public_folder + expected_public_agent_file
                    assert expected_file in archived_items, ('expecting {} in {}'.format(expected_file, archived_items))


def test_bundle_delete(cluster, superuser):
    bundles = _get_bundle_list(cluster, superuser)
    assert bundles, 'no bundles found'
    delete_base_url = '/report/diagnostics/delete'
    for bundle in bundles:
        requests.post(DDDTUrl(os.path.join(delete_base_url, bundle)), headers=superuser.authheader)

    bundles = _get_bundle_list(cluster, superuser)
    assert len(bundles) == 0, 'Could not remove bundles {}'.format(bundles)


def test_diagnostics_bundle_status(cluster, superuser):
    # validate diagnostics job status response
    diagnostics_bundle_status_response = requests.get(DDDTUrl('/report/diagnostics/status/all'),
                                                      headers=superuser.authheader)
    assert diagnostics_bundle_status_response.ok
    diagnostics_bundle_status = diagnostics_bundle_status_response.json()
    required_status_fields = ['is_running', 'status', 'errors', 'last_bundle_dir', 'job_started', 'job_ended',
                              'job_duration', 'diagnostics_bundle_dir', 'diagnostics_job_timeout_min',
                              'journald_logs_since_hours', 'diagnostics_job_get_since_url_timeout_min',
                              'command_exec_timeout_sec', 'diagnostics_partition_disk_usage_percent']

    for _, properties in diagnostics_bundle_status.items():
        assert len(properties) == len(required_status_fields), 'response must have the following fields: {}'.format(
            required_status_fields
        )
        for required_status_field in required_status_fields:
            assert required_status_field in properties, 'property {} not found'.format(required_status_field)
