import pytest
import time

from ee_helpers import bootstrap_config


@pytest.fixture()
def marathon_groups(cluster):
    # setup group
    r = cluster.marathon.post('/v2/groups', json={"id": "//example"})
    assert r.status_code == 201

    r = cluster.marathon.post('/v2/groups', json={"id": "//example-secure"})
    assert r.status_code == 201

    yield

    cluster.marathon.delete('/v2/groups/example')
    cluster.marathon.delete('/v2/groups/example-secure')


@pytest.fixture
def set_user_permission(cluster):
    def set_permission(rid, uid, action):
        rid = rid.replace('/', '%252F')
        # Create ACL if it does not yet exist.
        r = cluster.iam.put('/acls/{}'.format(rid), json={'description': 'jope'})
        assert r.status_code == 201 or r.status_code == 409
        # Set the permission triplet.
        r = cluster.iam.put('/acls/{}/users/{}/{}'.format(rid, uid, action))
        r.raise_for_status()
    return set_permission


skip_security_disabled = pytest.mark.skipif(bootstrap_config['security'] == 'disabled', reason="security is disabled")
pytestmark = [skip_security_disabled, pytest.mark.usefixtures("iam_verify_and_reset")]


def test_read_access_on_marathon_group(cluster, peter_cluster, set_user_permission, marathon_groups):

    # admin router
    set_user_permission(
        rid='dcos:adminrouter:service:marathon',
        uid=peter_cluster.web_auth_default_user.uid,
        action='full')
    # read example
    set_user_permission(
        rid='dcos:service:marathon:marathon:services:/example',
        uid=peter_cluster.web_auth_default_user.uid,
        action='read')
    # read example-secure
    set_user_permission(
        rid='dcos:service:marathon:marathon:services:/example-secure',
        uid=peter_cluster.web_auth_default_user.uid,
        action='read')

    # check access to group
    r = peter_cluster.marathon.get('/v2/groups')
    groups = r.json().get('groups')
    assert len(groups) == 2
    assert groups[0]['id'] == '/example'
    assert groups[1]['id'] == '/example-secure'


def test_delete_denied_on_marathon_group(cluster, peter_cluster, set_user_permission, marathon_groups):

    # admin router
    set_user_permission(
        rid='dcos:adminrouter:service:marathon',
        uid=peter_cluster.web_auth_default_user.uid,
        action='full')
    # read example
    set_user_permission(
        rid='dcos:service:marathon:marathon:services:/example',
        uid=peter_cluster.web_auth_default_user.uid,
        action='read')
    # read example-secure
    set_user_permission(
        rid='dcos:service:marathon:marathon:services:/example-secure',
        uid=peter_cluster.web_auth_default_user.uid,
        action='read')

    # check access to group
    r = peter_cluster.marathon.delete('/v2/groups/example')
    # forbidden
    assert r.status_code == 403


def test_read_access_denied_on_marathon_group_prefix(cluster, peter_cluster, set_user_permission, marathon_groups):
    # admin router
    set_user_permission(
        rid='dcos:adminrouter:service:marathon',
        uid=peter_cluster.web_auth_default_user.uid,
        action='full')
    # read example
    set_user_permission(
        rid='dcos:service:marathon:marathon:services:/example',
        uid=peter_cluster.web_auth_default_user.uid,
        action='read')
    # caching requires at least a 5 sec wait
    time.sleep(6)

    # check access to group
    r = peter_cluster.marathon.get('/v2/groups')
    groups = r.json().get('groups')
    # /example-secure should NOT be viewable
    assert len(groups) == 1
    assert groups[0]['id'] == '/example'
