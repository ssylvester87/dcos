import time

import pytest

from ee_helpers import bootstrap_config


@pytest.fixture()
def marathon_groups(superuser_api_session):
    # setup group
    r = superuser_api_session.marathon.post('/v2/groups', json={"id": "//example"})
    assert r.status_code == 201

    r = superuser_api_session.marathon.post('/v2/groups', json={"id": "//example-secure"})
    assert r.status_code == 201

    yield

    superuser_api_session.marathon.delete('/v2/groups/example')
    superuser_api_session.marathon.delete('/v2/groups/example-secure')


@pytest.fixture
def set_user_permission(superuser_api_session):
    def set_permission(rid, uid, action):
        rid = rid.replace('/', '%252F')
        # Create ACL if it does not yet exist.
        r = superuser_api_session.iam.put('/acls/{}'.format(rid), json={'description': 'jope'})
        assert r.status_code == 201 or r.status_code == 409
        # Set the permission triplet.
        r = superuser_api_session.iam.put('/acls/{}/users/{}/{}'.format(rid, uid, action))
        r.raise_for_status()
    return set_permission


@pytest.fixture
def remove_user_permission(superuser_api_session):
    def remove_permission(rid, uid, action):
        rid = rid.replace('/', '%252F')
        # Set the permission triplet.
        r = superuser_api_session.iam.delete('/acls/{}/users/{}/{}'.format(rid, uid, action))
        r.raise_for_status()
    return remove_permission


skip_security_disabled = pytest.mark.skipif(bootstrap_config['security'] == 'disabled', reason="security is disabled")
pytestmark = [skip_security_disabled, pytest.mark.usefixtures("iam_verify_and_reset")]


def test_read_access_on_marathon_group(peter_api_session, peter, set_user_permission, marathon_groups):

    # admin router
    set_user_permission(
        rid='dcos:adminrouter:service:marathon',
        uid=peter.uid,
        action='full')
    # read example
    set_user_permission(
        rid='dcos:service:marathon:marathon:services:/example',
        uid=peter.uid,
        action='read')
    # read example-secure
    set_user_permission(
        rid='dcos:service:marathon:marathon:services:/example-secure',
        uid=peter.uid,
        action='read')

    # check access to group
    r = peter_api_session.marathon.get('/v2/groups')
    groups = r.json().get('groups')
    assert len(groups) == 2
    assert groups[0]['id'] == '/example'
    assert groups[1]['id'] == '/example-secure'


def test_delete_denied_on_marathon_group(peter_api_session, peter, set_user_permission, marathon_groups):

    # admin router
    set_user_permission(
        rid='dcos:adminrouter:service:marathon',
        uid=peter.uid,
        action='full')
    # read example
    set_user_permission(
        rid='dcos:service:marathon:marathon:services:/example',
        uid=peter.uid,
        action='read')
    # read example-secure
    set_user_permission(
        rid='dcos:service:marathon:marathon:services:/example-secure',
        uid=peter.uid,
        action='read')

    # check access to group
    r = peter_api_session.marathon.delete('/v2/groups/example')
    # forbidden
    assert r.status_code == 403


def test_read_access_denied_on_marathon_group_prefix(peter_api_session, peter, set_user_permission, marathon_groups):
    # admin router
    set_user_permission(
        rid='dcos:adminrouter:service:marathon',
        uid=peter.uid,
        action='full')
    # read example
    set_user_permission(
        rid='dcos:service:marathon:marathon:services:/example',
        uid=peter.uid,
        action='read')
    # 5 sec expiration -> 5 sec expiration plus a second to account for potential latency
    time.sleep(5 + 1)

    # check access to group
    r = peter_api_session.marathon.get('/v2/groups')
    groups = r.json()['groups']

    # /example-secure should NOT be viewable
    assert len(groups) == 1
    assert groups[0]['id'] == '/example'


def test_cache_timeout_for_access_on_marathon_group_prefix(
        peter_api_session,
        set_user_permission,
        marathon_groups,
        remove_user_permission):
    peter_uid = peter_api_session.auth_user.uid
    marathon_example_group = 'dcos:service:marathon:marathon:services:/example'

    # admin router
    set_user_permission(
        rid='dcos:adminrouter:service:marathon',
        uid=peter_uid,
        action='full')
    # read example
    set_user_permission(
        rid=marathon_example_group,
        uid=peter_uid,
        action='read')
    # t1 successful access
    r = peter_api_session.marathon.get('/v2/groups')
    groups = r.json()['groups']

    assert len(groups) == 1
    assert groups[0]['id'] == '/example'

    # remove access
    remove_user_permission(
        rid=marathon_example_group,
        uid=peter_uid,
        action='read')
    # t2 successful access (even after remove based on cache)
    r = peter_api_session.marathon.get('/v2/groups')
    groups = r.json()['groups']

    # still in cache
    assert len(groups) == 1
    assert groups[0]['id'] == '/example'

    # t3 cache expires and access is denied
    time.sleep(6)
    r = peter_api_session.marathon.get('/v2/groups')
    groups = r.json().get('groups')
    # /example should NOT be viewable
    assert groups is None
