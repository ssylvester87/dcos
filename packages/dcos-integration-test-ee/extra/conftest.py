"""
Automatically loaded by py.test.

This is the place to define globally visible fixtures.
"""


import json
import logging
import os

import pytest
import requests
from jwt.utils import base64url_decode, base64url_encode

from dcostests import AuthedUser, dcos, IAMUrl, SuperUser, Url


log = logging.getLogger(__name__)


# These test for this option only exists upstream, but nested
# conftest.py's cannot instantiate options
def pytest_addoption(parser):
        parser.addoption('--resiliency', action='store_true')


@pytest.fixture(scope="session", autouse=True)
def https_enabled():
    """This fixture allows upstream integration tests
    to have CA bundle available
    """
    dcos_addr = os.environ['DCOS_DNS_ADDRESS']
    if dcos.config['ssl_enabled']:
        os.environ['DCOS_DNS_ADDRESS'] = dcos_addr.replace('http', 'https')
    return dcos


@pytest.fixture(scope="session")
def superuser():

    log.info('Fixture invoked')

    r = requests.post(
        IAMUrl('/auth/login'),
        json={'uid': dcos.su_uid, 'password': dcos.su_password}
        )
    r.raise_for_status()
    data = r.json()

    s = SuperUser()

    s.uid = dcos.su_uid
    s.authheader = {'Authorization': 'token=%s' % data['token']}
    s.authtoken = data['token']
    s.authcookie = r.cookies['dcos-acs-auth-cookie']

    return s


@pytest.yield_fixture(scope="session")
def peter(superuser):

    log.info('Fixture invoked')

    p = AuthedUser()
    p.uid = 'weakpeter'
    p.password = 'peterpan'
    p.description = 'An ordinarily weak Peter'

    url = IAMUrl('/users/%s' % p.uid)

    r = requests.put(
        url,
        json={'description': p.description, 'password': p.password},
        headers=superuser.authheader
        )

    # TODO(JP): Get rid of the 409 (detect missing test cleanuo).
    assert r.status_code in (201, 409)

    url = IAMUrl('/users/%s' % p.uid)

    # Obtain token and cookie for user.
    r = requests.post(
        IAMUrl('/auth/login'),
        json={'uid': p.uid, 'password': p.password}
        )
    r.raise_for_status()
    data = r.json()

    p.authheader = {'Authorization': 'token=%s' % data['token']}
    p.authtoken = data['token']
    p.authcookie = r.cookies['dcos-acs-auth-cookie']

    yield p
    log.info('Fixture teardown')

    log.info('Delete user `%s`', p.uid)
    r = requests.delete(url, headers=superuser.authheader)
    r.raise_for_status()


@pytest.fixture(scope="session")
def forged_superuser_authheader(peter, superuser):

    log.info('Fixture invoked')

    # Decode Peter's authentication token.
    t = peter.authtoken
    header_bytes, payload_bytes, signature_bytes = [
        base64url_decode(_.encode('ascii')) for _ in t.split(".")]
    payload_dict = json.loads(payload_bytes.decode('ascii'))
    assert 'exp' in payload_dict
    assert 'uid' in payload_dict
    assert payload_dict['uid'] == peter.uid

    # Rewrite uid and invert token decode procedure.
    forged_payload_dict = payload_dict.copy()
    forged_payload_dict['uid'] = superuser.uid
    forged_payload_bytes = json.dumps(forged_payload_dict).encode('utf-8')

    forged_token = '.'.join(
        base64url_encode(_).decode('ascii') for _ in (
            header_bytes, forged_payload_bytes, signature_bytes)
        )

    forged_authheader = {'Authorization': 'token=%s' % forged_token}
    return forged_authheader


@pytest.yield_fixture()
def with_peter_in_superuser_acl(superuser, peter):

    log.info('Fixture invoked')

    url = IAMUrl('/acls/dcos:superuser/users/%s/full' % peter.uid)

    # Add peter.
    r = requests.put(url, headers=superuser.authheader)
    r.raise_for_status()

    yield

    # Teardown code, remove peter, accept any 2xx status code.
    r = requests.delete(url, headers=superuser.authheader)
    r.raise_for_status()


@pytest.yield_fixture()
def with_peter_in_superuser_group(superuser, peter):

    log.info('Fixture invoked')

    url = IAMUrl('/groups/superusers/users/%s' % peter.uid)

    # Add peter to the group.
    r = requests.put(url, headers=superuser.authheader)
    assert r.status_code == 204

    yield

    # Teardown code, remove peter from the group, accept any 2xx status code.
    r = requests.delete(url, headers=superuser.authheader)
    r.raise_for_status()


def iam_reset_undecorated(superuser, peter):
    """
    1) Remove unexpected users.
    2) Remove unexpected groups.
    3) Remove ACLs that are not part of the initially seen ones.
    4) Remove Peter's direct permissions.
    5) Remove Peter's group memberships.
    """
    # Remove unexpected users.
    r = requests.get(IAMUrl('/users'), headers=superuser.authheader)
    for u in r.json()['array']:
        if u['uid'] in (peter.uid, superuser.uid):
            continue
        log.info("Delete user: %s", u['url'])
        r = requests.delete(Url(u['url']), headers=superuser.authheader)
        r.raise_for_status()

    # Remove unexpected groups.
    r = requests.get(IAMUrl('/groups'), headers=superuser.authheader)
    for g in r.json()['array']:
        if g['gid'] == 'superusers':
            continue
        log.info("Delete group: %s", g['url'])
        r = requests.delete(Url(g['url']), headers=superuser.authheader)
        r.raise_for_status()

    # Remove ACLs that are not part of the initially seen ones.
    r = requests.get(IAMUrl('/acls'), headers=superuser.authheader)
    for o in r.json()['array']:
        if o['rid'] in dcos.initial_resource_ids:
            continue
        log.info("Delete ACL: %s", o['url'])
        r = requests.delete(Url(o['url']), headers=superuser.authheader)
        r.raise_for_status()

    # Remove Peter's direct permissions (group permissions will be obliterated
    # by removing group memberships in the next step).
    permurl = IAMUrl('/users/%s/permissions' % peter.uid)
    groupsurl = IAMUrl('/users/%s/groups' % peter.uid)

    r = requests.get(permurl, headers=superuser.authheader)
    for o in r.json()['direct']:
        for a in o['actions']:
            log.info("Delete Peter's permission: %s", a['url'])
            r = requests.delete(Url(a['url']), headers=superuser.authheader)
            r.raise_for_status()

    # Remove Peter's group memberships.
    r = requests.get(groupsurl, headers=superuser.authheader)
    for o in r.json()['array']:
        log.info("Delete Peter's group membership: %s", o['membershipurl'])
        r = requests.delete(Url(o['membershipurl']), headers=superuser.authheader)
        r.raise_for_status()


def iam_verify_undecorated(superuser, peter):
    """
    1) Verify there are no other users except for superuser and Peter.
    2) Verify there are no groups other than 'superuser'.
    3) Verify Peter is not part of any group.
    4) Verify Peter has no permissions set.
    """
    # Verify there are no other users except for superuser and Peter.
    r = requests.get(IAMUrl('/users'), headers=superuser.authheader)
    uids = [_['uid'] for _ in r.json()['array']]
    assert set(uids) == set((superuser.uid, peter.uid))

    # Verify there are no groups other than 'superuser'.
    r = requests.get(IAMUrl('/groups'), headers=superuser.authheader)
    gids = [_['gid'] for _ in r.json()['array']]
    assert gids == ['superusers']

    # Verify Peter is not part of any group.
    groupsurl = IAMUrl('/users/%s/groups' % peter.uid)
    r = requests.get(groupsurl, headers=superuser.authheader)
    assert r.json()['array'] == []

    # Verify Peter has no permissions set.
    permurl = IAMUrl('/users/%s/permissions' % peter.uid)
    r = requests.get(permurl, headers=superuser.authheader)
    data = r.json()
    assert data['direct'] == []
    assert data['groups'] == []


@pytest.fixture()
def iam_reset_before(superuser, peter):
    log.info('Fixture invoked')
    iam_reset_undecorated(superuser, peter)


@pytest.yield_fixture()
def iam_reset_after(superuser, peter):
    log.info('Fixture invoked')
    yield
    log.info('Fixture teardown')
    iam_reset_undecorated(superuser, peter)


@pytest.yield_fixture()
def iam_verify_and_reset(superuser, peter):
    """
    Pre-test steps:

        1) Verify there are no other users except for superuser and Peter.
        2) Verify there are no groups other than 'superusers'.
        3) Verify Peter is not part of any group (could be in superusers
           otherwise).
        4) Verify Peter has no permissions set.

    Post-test steps:

        1) Remove unexpected users.
        2) Remove unexpected groups.
        3) Remove ACLs that are not part of the initially seen ones.
        4) Remove Peter's direct permissions.
        5) Remove Peter's group memberships.


    Only yield into test code if pre-test has succeeded. Perform post-test even
    if pre-test failed, i.e. always try to perform cleanup.
    """

    log.info('Fixture invoked')

    try:
        iam_verify_undecorated(superuser, peter)
    except Exception as e:
        log.error('Exception in iam_verify_undecorated(), reraise: %s', str(e))
        raise
    else:
        yield
    finally:
        log.info('Fixture teardown')
        iam_reset_undecorated(superuser, peter)
