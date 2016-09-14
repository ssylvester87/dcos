"""
Tests that check if cluster state is sane.

Tests do not modify cluster state.
"""


import json

import kazoo.client
import requests

from dcostests import dcos, Url


def test_if_all_mesos_agents_have_registered(superuser):
    url = Url('/mesos/master/state')

    r = requests.get(url, headers=superuser.authheader)
    assert r.status_code == 200
    data = r.json()

    agent_ips = sorted(x['hostname'] for x in data['slaves'])
    assert agent_ips == dcos.agents


def test_if_all_mesos_masters_have_registered(superuser):
    zk = kazoo.client.KazooClient(hosts=dcos.zk_hostports, read_only=True)
    master_ips = []

    zk.start()
    for znode in zk.get_children("/mesos"):
        if not znode.startswith("json.info_"):
            continue
        master = json.loads(zk.get("/mesos/" + znode)[0].decode('utf-8'))
        master_ips.append(master['address']['ip'])
    zk.stop()

    assert sorted(master_ips) == dcos.masters


def test_if_zookeeper_cluster_is_up(superuser):
    r = requests.get(
        Url('/exhibitor/exhibitor/v1/cluster/status'),
        headers=superuser.authheader
        )
    assert r.status_code == 200

    data = r.json()
    serving_zks = sum(1 for x in data if x['code'] == 3)
    zks_ips = sorted(x['hostname'] for x in data)
    zks_leaders = sum(1 for x in data if x['isLeader'])

    assert zks_ips == dcos.masters
    assert serving_zks == len(dcos.masters)
    assert zks_leaders == 1


def test_if_all_exhibitors_are_in_sync(superuser):
    r = requests.get(
        Url('/exhibitor/exhibitor/v1/cluster/status'),
        headers=superuser.authheader
        )
    assert r.status_code == 200

    correct_data = sorted(r.json(), key=lambda k: k['hostname'])

    for zk_ip in dcos.public_masters:
        resp = requests.get(
            'http://{}:8181/exhibitor/v1/cluster/status'.format(zk_ip))
        assert resp.status_code == 200

        tested_data = sorted(resp.json(), key=lambda k: k['hostname'])
        assert correct_data == tested_data


def test_if_history_service_is_getting_data(superuser):
    r = requests.get(
        Url('/dcos-history-service/history/last'),
        headers=superuser.authheader
        )
    assert r.status_code == 200
    # Make sure some basic fields are present from state-summary which the DCOS
    # UI relies upon. Their exact content could vary so don't test the value.
    json = r.json()
    assert 'cluster' in json
    assert 'frameworks' in json
    assert 'slaves' in json
    assert 'hostname' in json
