"""
Automatically loaded by py.test.

This is the place to define globally visible fixtures.
"""
import atexit
import functools
import json
import logging
import os
import tempfile
from urllib.parse import urlparse

import pytest
import requests
from jwt.utils import base64url_decode, base64url_encode

from dcostests import AuthedUser, dcos, IAMUrl, SuperUser, Url
from test_util.cluster_api import ClusterApi
from test_util.helpers import DcosUser


log = logging.getLogger(__name__)

INITIAL_RESOURCE_IDS = [
    "dcos:adminrouter:ops:metadata",
    "dcos:adminrouter:ops:historyservice",
    "dcos:adminrouter:package",
    "dcos:adminrouter:acs",
    "dcos:adminrouter:ops:mesos",
    "dcos:adminrouter:service:marathon",
    "dcos:adminrouter:ops:mesos-dns",
    "dcos:adminrouter:ops:exhibitor",
    "dcos:adminrouter:ops:ca:ro",
    "dcos:adminrouter:ops:slave",
    "dcos:superuser",
    "dcos:adminrouter:ops:system-health",
    "dcos:adminrouter:ops:ca:rw",
    "dcos:adminrouter:ops:networking"
    ]


@pytest.fixture(scope='session')
def cluster_config():
    with open('/opt/mesosphere/etc/bootstrap-config.json', 'rb') as f:
        config = json.loads(f.read().decode('ascii'))
    return config


@pytest.fixture(scope="session", autouse=True)
def use_custom_ca(cluster_config):
    if not cluster_config['ssl_enabled']:
        return None

    # Override the given address with https
    dcos_addr = os.environ['DCOS_DNS_ADDRESS'].replace('http', 'https')
    os.environ['DCOS_DNS_ADDRESS'] = dcos_addr

    # Attempt to get CA bundle from cluster. Follow redirects (might
    # redirect to HTTPS), but do not attempt to verify cert.
    log.info('Attempt to get CA bundle via CA HTTP API')
    r = requests.post(
        '{}/ca/api/v2/info'.format(dcos_addr),
        json={'profile': ''},
        verify=False)

    assert r.status_code == 200
    data = r.json()
    crt = data['result']['certificate'].encode('ascii')

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(crt)
        ca_cert_path = f.name

    # Attempt to remove the file upon normal interpreter exit.
    atexit.register(functools.partial(remove_file, ca_cert_path))

    os.environ['DCOS_CA_CERT_PATH'] = ca_cert_path

    return ca_cert_path


@pytest.fixture(scope="session", autouse=True)
def apply_security_settings(cluster_config):
    """When strict mode is set, marathon will launch apps as 'nobody' instead 'root'
    """
    global INITIAL_RESOURCE_IDS
    security = cluster_config['security'] == 'strict'
    if security == 'permissive':
        INITIAL_RESOURCE_IDS.extend([
            'dcos:mesos:master:framework',
            'dcos:mesos:master:reservation',
            'dcos:mesos:master:volume',
            'dcos:mesos:master:task'])
    elif security == 'strict':
        os.environ['DCOS_DEFAULT_OS_USER'] = 'nobody'
        INITIAL_RESOURCE_IDS.extend([
            'dcos:mesos:master:framework:role:slave_public',
            'dcos:mesos:master:framework:role:*',
            'dcos:mesos:master:reservation:role:slave_public',
            'dcos:mesos:master:reservation:principal:dcos_marathon',
            'dcos:mesos:master:volume:role:slave_public',
            'dcos:mesos:master:volume:principal:dcos_marathon',
            'dcos:mesos:master:task:user:nobody',
            'dcos:mesos:master:task:app_id'])


@pytest.fixture(scope='session', autouse=True)
def pass_creds_to_upstream():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(json.dumps({'uid': os.environ['DCOS_LOGIN_UNAME'], 'password': os.environ['DCOS_LOGIN_PW']}).encode())
        auth_json_path = f.name

    os.environ['DCOS_AUTH_JSON_PATH'] = auth_json_path

    # Attempt to remove the file upon normal interpreter exit.
    atexit.register(functools.partial(remove_file, auth_json_path))


def path_only(url):
    return urlparse(url).path


def remove_file(path):
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture(scope='session')
def superuser():
    uid = os.environ['DCOS_LOGIN_UNAME']
    password = os.environ['DCOS_LOGIN_PW']
    auth_json = {
        'uid': uid,
        'password': password}

    # Pass the creds to the upstream tests
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(json.dumps(auth_json).encode())
        auth_json_path = f.name
    os.environ['DCOS_AUTH_JSON_PATH'] = auth_json_path

    def _remove_file():
        if os.path.exists(auth_json_path):
            os.remove(auth_json_path)

    # Attempt to remove the file upon normal interpreter exit.
    atexit.register(_remove_file)

    if 'DCOS_AUTH_JSON_PATH' in os.environ:
        with open(os.environ['DCOS_AUTH_JSON_PATH'], 'r') as auth_json_fh:
            auth_json = json.load(auth_json_fh)
    test_super_user = DcosUser(auth_json)
    test_super_user.uid = uid
    test_super_user.password = password
    return test_super_user


class EnterpriseClusterApi(ClusterApi):
    @property
    def iam(self):
        return self.get_client('/acs/api/v1')

    @property
    def secrets(self):
        return self.get_client('/secrets/v1/')

    @property
    def ca(self):
        return self.get_client('/ca/api/v2/')


@pytest.fixture(scope='session')
def cluster(superuser, use_custom_ca):
    assert 'DCOS_DNS_ADDRESS' in os.environ
    assert 'MASTER_HOSTS' in os.environ
    assert 'PUBLIC_MASTER_HOSTS' in os.environ
    assert 'SLAVE_HOSTS' in os.environ
    assert 'PUBLIC_SLAVE_HOSTS' in os.environ
    assert 'DNS_SEARCH' in os.environ
    assert 'DCOS_PROVIDER' in os.environ

    # dns_search must be true or false (prevents misspellings)
    assert os.environ['DNS_SEARCH'] in ['true', 'false']

    assert os.environ['DCOS_PROVIDER'] in ['onprem', 'aws', 'azure']

    logging.basicConfig(format='[%(asctime)s] %(levelname)s: %(message)s', level=logging.INFO)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)

    cluster_api = EnterpriseClusterApi(
        dcos_uri=os.environ['DCOS_DNS_ADDRESS'],
        masters=os.environ['MASTER_HOSTS'].split(','),
        public_masters=os.environ['PUBLIC_MASTER_HOSTS'].split(','),
        slaves=os.environ['SLAVE_HOSTS'].split(','),
        public_slaves=os.environ['PUBLIC_SLAVE_HOSTS'].split(','),
        dns_search_set=os.environ['DNS_SEARCH'],
        provider=os.environ['DCOS_PROVIDER'],
        auth_enabled=os.getenv('DCOS_AUTH_ENABLED', 'true') == 'true',
        default_os_user=os.getenv('DCOS_DEFAULT_OS_USER', 'root'),
        web_auth_default_user=superuser,
        ca_cert_path=use_custom_ca)
    cluster_api.wait_for_dcos()
    return cluster_api


@pytest.yield_fixture(scope="module")
def peter(cluster):
    """Provides a non-super user and deletes it after test
    """
    uid = 'weakestpeter'
    password = 'peterpan'
    p = DcosUser({'uid': uid, 'password': password})
    p.uid = uid
    p.password = password
    description = 'An ordinarily weak Peter'

    new_user_json = {'description': description, 'password': password}
    user_endpoint = '/users/{}'.format(uid)
    cluster.iam.put(user_endpoint, json=new_user_json)
    p.authenticate(cluster)

    yield p

    log.info('Delete user {}'.format(p.uid))
    r = cluster.iam.delete(user_endpoint)
    r.raise_for_status()


@pytest.yield_fixture()
def with_peter_in_superuser_acl(cluster, peter):
    """Grants peter user superuser priveleges
    """
    path = '/acls/dcos:superuser/users/{}/full'.format(peter.uid)
    # Add peter.
    r = cluster.iam.put(path)
    r.raise_for_status()

    yield

    # Teardown code, remove peter, accept any 2xx status code.
    r = cluster.iam.delete(path)
    r.raise_for_status()


@pytest.yield_fixture()
def with_peter_in_superuser_group(peter, cluster):
    path = '/groups/superusers/users/{}'.format(peter.uid)

    # Add peter to the group.
    r = cluster.iam.put(path)
    assert r.status_code == 204

    yield

    # Teardown code, remove peter from the group, accept any 2xx status code.
    r = cluster.iam.delete(path)
    r.raise_for_status()


def iam_reset_undecorated(cluster, superuser, peter):
    """
    1) Remove unexpected users.
    2) Remove unexpected groups.
    3) Remove ACLs that are not part of the initially seen ones.
    4) Remove Peter's direct permissions.
    5) Remove Peter's group memberships.
    """
    # Remove unexpected users.
    r = cluster.iam.get('/users')
    for u in r.json()['array']:
        if u['uid'] in (peter.uid, superuser.uid, 'dcos_marathon', 'dcos_metronome'):
            continue
        log.info("Delete user: %s", u['url'])
        r = cluster.delete(path_only(u['url']))
        r.raise_for_status()

    # Remove unexpected groups.
    r = cluster.iam.get('/groups')
    for g in r.json()['array']:
        if g['gid'] == 'superusers':
            continue
        log.info("Delete group: %s", g['url'])
        r = cluster.delete(path_only(g['url']))
        r.raise_for_status()

    # Remove ACLs that are not part of the initially seen ones.
    r = cluster.iam.get('/acls')
    for o in r.json()['array']:
        if o['rid'] in INITIAL_RESOURCE_IDS:
            continue
        log.info("Delete ACL: %s", o['url'])
        r = cluster.delete(path_only(o['url']))
        r.raise_for_status()

    # Remove Peter's direct permissions (group permissions will be obliterated
    # by removing group memberships in the next step).

    r = cluster.iam.get('/users/{}/permissions'.format(peter.uid))
    for o in r.json()['direct']:
        for a in o['actions']:
            log.info("Delete Peter's permission: %s", a['url'])
            r = cluster.delete(path_only(a['url']))
            r.raise_for_status()

    # Remove Peter's group memberships.
    r = cluster.iam.get('/users/{}/groups'.format(peter.uid))
    for o in r.json()['array']:
        log.info("Delete Peter's group membership: %s", o['membershipurl'])
        r = cluster.delete(path_only(o['membershipurl']))
        r.raise_for_status()


def iam_verify_undecorated(cluster, superuser, peter):
    """
    1) Verify there are no other users except for superuser and Peter.
    2) Verify there are no groups other than 'superuser'.
    3) Verify Peter is not part of any group.
    4) Verify Peter has no permissions set.
    """
    # Verify there are no other users except for superuser and Peter.
    r = cluster.iam.get('/users')
    uids = [_['uid'] for _ in r.json()['array']]
    assert set(uids) == set((superuser.uid, peter.uid))

    # Verify there are no groups other than 'superuser'.
    r = cluster.iam.get('/groups')
    gids = [_['gid'] for _ in r.json()['array']]
    assert gids == ['superusers']

    # Verify Peter is not part of any group.
    r = cluster.iam.get('/users/{}/groups'.format(peter.uid))
    assert r.json()['array'] == []

    # Verify Peter has no permissions set.
    r = cluster.iam.get('/users/{}/permissions'.format(peter.uid))
    data = r.json()
    assert data['direct'] == []
    assert data['groups'] == []


@pytest.yield_fixture()
def iam_verify_and_reset(cluster, superuser, peter):
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
    try:
        logging.info('Verifying superuser and peter are in original state')
        iam_verify_undecorated(cluster, superuser, peter)
    except Exception as e:
        log.error('Exception in iam_verify_undecorated(), reraise: %s', str(e))
        raise
    else:
        yield
    finally:
        logging.info('Returning superuser and peter to original state')
        iam_reset_undecorated(cluster, superuser, peter)
# ####################################################### #
# Below here are the DEPRECATED fixtures to be phased out #
# ####################################################### #


@pytest.fixture(scope="session")
def superuser_():

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


@pytest.yield_fixture(scope="module")
def peter_(superuser_):

    log.info('Fixture invoked')

    p = AuthedUser()
    p.uid = 'weakpeter'
    p.password = 'peterpan'
    p.description = 'An ordinarily weak Peter'

    url = IAMUrl('/users/%s' % p.uid)

    r = requests.put(
        url,
        json={'description': p.description, 'password': p.password},
        headers=superuser_.authheader
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
    r = requests.delete(url, headers=superuser_.authheader)
    r.raise_for_status()


@pytest.fixture(scope="module")
def forged_superuser_authheader(peter_, superuser_):

    log.info('Fixture invoked')

    # Decode Peter's authentication token.
    t = peter_.authtoken
    header_bytes, payload_bytes, signature_bytes = [
        base64url_decode(_.encode('ascii')) for _ in t.split(".")]
    payload_dict = json.loads(payload_bytes.decode('ascii'))
    assert 'exp' in payload_dict
    assert 'uid' in payload_dict
    assert payload_dict['uid'] == peter_.uid

    # Rewrite uid and invert token decode procedure.
    forged_payload_dict = payload_dict.copy()
    forged_payload_dict['uid'] = superuser_.uid
    forged_payload_bytes = json.dumps(forged_payload_dict).encode('utf-8')

    forged_token = '.'.join(
        base64url_encode(_).decode('ascii') for _ in (
            header_bytes, forged_payload_bytes, signature_bytes)
        )

    forged_authheader = {'Authorization': 'token=%s' % forged_token}
    return forged_authheader


def iam_reset_undecorated_(superuser_, peter_):
    """
    1) Remove unexpected users.
    2) Remove unexpected groups.
    3) Remove ACLs that are not part of the initially seen ones.
    4) Remove Peter's direct permissions.
    5) Remove Peter's group memberships.
    """
    # Remove unexpected users.
    r = requests.get(IAMUrl('/users'), headers=superuser_.authheader)
    for u in r.json()['array']:
        if u['uid'] in (peter_.uid, superuser_.uid, 'dcos_marathon', 'dcos_metronome'):
            continue
        log.info("Delete user: %s", u['url'])
        r = requests.delete(Url(u['url']), headers=superuser_.authheader)
        r.raise_for_status()

    # Remove unexpected groups.
    r = requests.get(IAMUrl('/groups'), headers=superuser_.authheader)
    for g in r.json()['array']:
        if g['gid'] == 'superusers':
            continue
        log.info("Delete group: %s", g['url'])
        r = requests.delete(Url(g['url']), headers=superuser_.authheader)
        r.raise_for_status()

    # Remove ACLs that are not part of the initially seen ones.
    r = requests.get(IAMUrl('/acls'), headers=superuser_.authheader)
    for o in r.json()['array']:
        if o['rid'] in dcos.initial_resource_ids:
            continue
        log.info("Delete ACL: %s", o['url'])
        r = requests.delete(Url(o['url']), headers=superuser_.authheader)
        r.raise_for_status()

    # Remove Peter's direct permissions (group permissions will be obliterated
    # by removing group memberships in the next step).
    permurl = IAMUrl('/users/%s/permissions' % peter_.uid)
    groupsurl = IAMUrl('/users/%s/groups' % peter_.uid)

    r = requests.get(permurl, headers=superuser_.authheader)
    for o in r.json()['direct']:
        for a in o['actions']:
            log.info("Delete Peter's permission: %s", a['url'])
            r = requests.delete(Url(a['url']), headers=superuser_.authheader)
            r.raise_for_status()

    # Remove Peter's group memberships.
    r = requests.get(groupsurl, headers=superuser_.authheader)
    for o in r.json()['array']:
        log.info("Delete Peter's group membership: %s", o['membershipurl'])
        r = requests.delete(Url(o['membershipurl']), headers=superuser_.authheader)
        r.raise_for_status()


def iam_verify_undecorated_(superuser_, peter_):
    """
    1) Verify there are no other users except for superuser and Peter.
    2) Verify there are no groups other than 'superuser'.
    3) Verify Peter is not part of any group.
    4) Verify Peter has no permissions set.
    """
    # Verify there are no other users except for superuser and Peter.
    r = requests.get(IAMUrl('/users'), headers=superuser_.authheader)
    uids = [_['uid'] for _ in r.json()['array']]
    assert set(uids) == set((superuser_.uid, peter_.uid))

    # Verify there are no groups other than 'superuser'.
    r = requests.get(IAMUrl('/groups'), headers=superuser_.authheader)
    gids = [_['gid'] for _ in r.json()['array']]
    assert gids == ['superusers']

    # Verify Peter is not part of any group.
    groupsurl = IAMUrl('/users/%s/groups' % peter_.uid)
    r = requests.get(groupsurl, headers=superuser_.authheader)
    assert r.json()['array'] == []

    # Verify Peter has no permissions set.
    permurl = IAMUrl('/users/%s/permissions' % peter_.uid)
    r = requests.get(permurl, headers=superuser_.authheader)
    data = r.json()
    assert data['direct'] == []
    assert data['groups'] == []


@pytest.yield_fixture()
def iam_verify_and_reset_(superuser_, peter_):
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
        iam_verify_undecorated_(superuser_, peter_)
    except Exception as e:
        log.error('Exception in iam_verify_undecorated(), reraise: %s', str(e))
        raise
    else:
        yield
    finally:
        log.info('Fixture teardown')
        iam_reset_undecorated_(superuser_, peter_)
