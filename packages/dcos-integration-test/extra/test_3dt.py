# -*- coding: utf-8 -*-
# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
Test 3DT.
"""


import logging

import pytest
import requests

from dcostests import DDDTUrl, dcos


log = logging.getLogger(__name__)


PORT_3DT = 1050
BASE_ENDPOINT_3DT = '/system/health/v1'


# Note(JP): skip these tests for now, seem not to be adjusted to current
# enterprise DC/OS.
pytestmark = [pytest.mark.skip]


# Add an adapter for legacy tests.
@pytest.fixture
def cluster():
    return dcos


def make_3dt_request(host, endpoint, port=None):
    if port is None:
        assert endpoint.startswith('/'), \
            'endpoint {} must start with /'.format(endpoint)
        json_response = requests.get(path=endpoint).json()
        return json_response

    url = DDDTUrl(endpoint, host=host, port=port)

    request = requests.get(url, timeout=10.0)
    assert request.ok

    json_response = request.json()
    assert len(json_response) > 0
    return json_response


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


def test_3dt_health(cluster):
    """
    test health endpoint /system/health/v1
    """
    required_fields = ['units', 'hostname', 'ip', 'dcos_version', 'node_role', 'mesos_id', '3dt_version']
    required_fields_unit = ['id', 'health', 'output', 'description', 'help', 'name']

    for host in cluster.masters + cluster.slaves:
        response = make_3dt_request(host, '/', port=PORT_3DT)
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


def test_3dt_nodes_node_units(cluster):
    """
    test a list of units from a specific node, endpoint /system/health/v1/nodes/<node>/units
    """
    for master in cluster.masters:
        # get a list of nodes
        response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/nodes', cluster)
        nodes = list(map(lambda node: node['host_ip'], response['nodes']))
        logging.info('received the following nodes: {}'.format(nodes))

        for node in nodes:
            node_response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/nodes/{}'.format(node), cluster)
            logging.info('node reponse: {}'.format(node_response))
            units_response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/nodes/{}/units'.format(node), cluster)
            logging.info('units reponse: {}'.format(units_response))

            assert len(units_response) == 1, 'unit response should have only 1 field `units`'
            assert 'units' in units_response
            validate_units(units_response['units'])


def test_3dt_nodes_node_units_unit(cluster):
    """
    test a specific unit for a specific node, endpoint /system/health/v1/nodes/<node>/units/<unit>
    """
    for master in cluster.masters:
        response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/nodes', cluster)
        nodes = list(map(lambda node: node['host_ip'], response['nodes']))
        for node in nodes:
            units_response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/nodes/{}/units'.format(node), cluster)
            unit_ids = list(map(lambda unit: unit['id'], units_response['units']))
            logging.info('unit ids: {}'.format(unit_ids))

            for unit_id in unit_ids:
                validate_unit(
                    make_3dt_request(master, BASE_ENDPOINT_3DT + '/nodes/{}/units/{}'.format(node, unit_id), cluster))


def test_3dt_units(cluster):
    """
    test a list of collected units, endpoint /system/health/v1/units
    """
    # get all unique unit names
    all_units = set()
    for node in cluster.masters + cluster.slaves:
        node_response = make_3dt_request(node, BASE_ENDPOINT_3DT, cluster, port=PORT_3DT)
        for unit in node_response['units']:
            all_units.add(unit['id'])
    logging.info('all units: {}'.format(all_units))

    # test agaist masters
    for master in cluster.masters:
        units_response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/units', cluster)
        validate_units(units_response['units'])

        pulled_units = list(map(lambda unit: unit['id'], units_response['units']))
        logging.info('collected units: {}'.format(pulled_units))
        assert set(pulled_units) == all_units, 'not all units have been collected by 3dt puller, missing: {}'.format(
            set(pulled_units).symmetric_difference(all_units)
        )


def test_3dt_units_unit(cluster):
    """
    test a unit response in a right format, endpoint: /system/health/v1/units/<unit>
    """
    for master in cluster.masters:
        units_response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/units', cluster)
        pulled_units = list(map(lambda unit: unit['id'], units_response['units']))
        for unit in pulled_units:
            unit_response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/units/{}'.format(unit), cluster)
            validate_units([unit_response])


def make_nodes_ip_map(cluster):
    """
    a helper function to make a map detected_ip -> external_ip
    """
    node_private_public_ip_map = {}
    for node in cluster.masters + cluster.slaves:
        detected_ip = make_3dt_request(node, BASE_ENDPOINT_3DT, cluster, port=PORT_3DT)['ip']
        node_private_public_ip_map[detected_ip] = node

    logging.info('detected ips: {}'.format(node_private_public_ip_map))
    return node_private_public_ip_map


def test_3dt_units_unit_nodes(cluster):
    """
    test a list of nodes for a specific unit, endpoint /system/health/v1/units/<unit>/nodes
    """
    nodes_ip_map = make_nodes_ip_map(cluster)

    for master in cluster.masters:
        units_response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/units', cluster)
        pulled_units = list(map(lambda unit: unit['id'], units_response['units']))
        for unit in pulled_units:
            nodes_response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/units/{}/nodes'.format(unit), cluster)
            validate_node(nodes_response['nodes'])

        # make sure dcos-mesos-master.service has master nodes and dcos-mesos-slave.service has agent nodes
        master_nodes_response = make_3dt_request(
            master, BASE_ENDPOINT_3DT + '/units/dcos-mesos-master.service/nodes', cluster)
        master_nodes = list(map(lambda node: nodes_ip_map.get(node['host_ip']), master_nodes_response['nodes']))
        logging.info('master_nodes: {}'.format(master_nodes))

        assert len(master_nodes) == len(cluster.masters), '{} != {}'.format(master_nodes, cluster.masters)
        assert set(master_nodes) == set(cluster.masters), 'a list of difference: {}'.format(
            set(master_nodes).symmetric_difference(set(cluster.masters))
        )

        agent_nodes_response = make_3dt_request(
            master, BASE_ENDPOINT_3DT + '/units/dcos-mesos-slave.service/nodes', cluster)
        agent_nodes = list(map(lambda node: nodes_ip_map.get(node['host_ip']), agent_nodes_response['nodes']))
        logging.info('aget_nodes: {}'.format(agent_nodes))
        assert len(agent_nodes) == len(cluster.slaves), '{} != {}'.format(agent_nodes, cluster.slaves)


def test_3dt_units_unit_nodes_node(cluster):
    """
    test a specific node for a specific unit, endpoint /system/health/v1/units/<unit>/nodes/<node>
    """
    required_node_fields = ['host_ip', 'health', 'role', 'output', 'help']

    for master in cluster.masters:
        units_response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/units', cluster)
        pulled_units = list(map(lambda unit: unit['id'], units_response['units']))
        logging.info('pulled units: {}'.format(pulled_units))
        for unit in pulled_units:
            nodes_response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/units/{}/nodes'.format(unit), cluster)
            pulled_nodes = list(map(lambda node: node['host_ip'], nodes_response['nodes']))
            logging.info('pulled nodes: {}'.format(pulled_nodes))
            for node in pulled_nodes:
                node_response = make_3dt_request(
                    master, BASE_ENDPOINT_3DT + '/units/{}/nodes/{}'.format(unit, node), cluster)
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


def test_3dt_report(cluster):
    """
    test 3dt report endpoint /system/health/v1/report
    """
    for master in cluster.masters:
        report_response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/report', cluster)
        assert 'Units' in report_response
        assert len(report_response['Units']) > 0

        assert 'Nodes' in report_response
        assert len(report_response['Nodes']) > 0


def test_3dt_nodes(cluster):
    """
    test a list of nodes with statuses endpoint /system/health/v1/nodes
    """
    for master in cluster.masters:
        response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/nodes', cluster)
        assert len(response) == 1, 'nodes response must have only one field: nodes'
        assert 'nodes' in response
        assert isinstance(response['nodes'], list)
        assert len(response['nodes']) == len(cluster.masters + cluster.slaves), (
            'a number of nodes in response must be {}'.format(len(cluster.masters + cluster.slaves)))

        # test nodes
        validate_node(response['nodes'])


def test_3dt_nodes_node(cluster):
    """
    test a specific node enpoint /system/health/v1/nodes/<node>
    """
    for master in cluster.masters:
        # get a list of nodes
        response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/nodes', cluster)
        nodes = list(map(lambda node: node['host_ip'], response['nodes']))
        logging.info('received the following nodes: {}'.format(nodes))

        for node in nodes:
            node_response = make_3dt_request(master, BASE_ENDPOINT_3DT + '/nodes/{}'.format(node), cluster)
            validate_node([node_response])
