"""
Test IAM/Bouncer functionality through Admin Router.
"""
import base64
import json
import logging
import os
import time
import uuid

import jwt
import pexpect
import pytest
from ee_helpers import generate_RSA_keypair
from jwt.utils import base64url_decode

pytestmark = [pytest.mark.security]

# Pre-generate keypair for performance reasons.
# TODO: move this into a session scoped fixture
default_rsa_privkey, default_rsa_pubkey = generate_RSA_keypair()


class TestIAM404s:

    def test_acs(self, noauth_api_session):
        assert noauth_api_session.get('/acs').status_code == 404

    def test_acs_api(self, noauth_api_session):
        assert noauth_api_session.get('/acs/api').status_code == 404


class TestIAMPublicEndpointReachability:

    def test_jwks(self, noauth_api_session):
        assert noauth_api_session.iam.get('/auth/jwks').status_code == 200

    def test_login(self, noauth_api_session):
        r = noauth_api_session.iam.get('/auth/login')
        assert r.status_code == 400
        assert r.json()  # just check that some json is provided

    def test_logout(self, noauth_api_session):
        assert noauth_api_session.iam.get('/auth/logout').status_code == 200

    def test_saml_providers(self, noauth_api_session):
        assert noauth_api_session.iam.get('/auth/saml/providers').status_code == 200

    def test_oidc_providers(self, noauth_api_session):
        assert noauth_api_session.iam.get('/auth/oidc/providers').status_code == 200

    def test_oidc_callback_url(self, noauth_api_session):
        r = noauth_api_session.iam.get('/auth/oidc/callback')
        assert r.status_code == 401
        data = r.json()
        assert 'dcos-iam-oidc-state cookie missing' in data['description']

    def test_saml_callback_url(self, noauth_api_session):
        r = noauth_api_session.iam.post('/auth/saml/providers/unknown/acs-callback', json={})
        data = r.json()
        assert 'SAML provider `unknown` not known' in data['description']


class TestIAMLoginEndpointBehavior:

    login_path = '/auth/login'

    def test_accessible_wo_auth(self, noauth_api_session):
        r = noauth_api_session.iam.get(self.login_path)
        assert r.status_code == 400
        d = r.json()
        assert 'ERR_MISSING_QUERY_PARAMETERS' == d['code']

    def test_missing_content_type(self, noauth_api_session):
        # requests does not always set a content-type, use this here.
        r = noauth_api_session.iam.post(self.login_path, data="rofl")
        assert r.status_code == 400
        d = r.json()
        assert "Missing Content-Type header" in d['description']

    def test_post_wrong_content_type(self, noauth_api_session):
        r = noauth_api_session.iam.post(
            self.login_path,
            data="MyVariableOne=ValueOne&MyVariableTwo=ValueTwo",
            headers={'Content-Type': 'application/x-www-form-urlencoded'})
        assert r.status_code == 400
        d = r.json()
        assert "Request has bad Content-Type or lacks JSON" in d['description']

    def test_post_invalid_credentials(self, noauth_api_session):
        r = noauth_api_session.iam.post(
            self.login_path,
            json={'uid': 'unknown', 'password': 'not-the-right-one'})
        assert r.status_code == 401
        assert r.json()['code'] == "ERR_INVALID_CREDENTIALS"
        assert r.headers['WWW-Authenticate'] == 'acsjwt'

    def test_authtoken_anatomy(self, noauth_api_session, superuser):
        r = noauth_api_session.iam.post(
            self.login_path,
            json={'uid': superuser.uid, 'password': superuser.password})
        token = r.json()['token']
        header_bytes, payload_bytes, signature_bytes = [
            base64url_decode(_.encode('ascii')) for _ in token.split(".")]

        assert b'typ' in header_bytes

        header_dict = json.loads(header_bytes.decode('ascii'))
        assert header_dict['alg'] == "RS256"
        assert header_dict['typ'] == "JWT"

        payload_dict = json.loads(payload_bytes.decode('ascii'))
        assert 'exp' in payload_dict
        assert 'uid' in payload_dict
        assert payload_dict['uid'] == superuser.uid

    def test_cookies_anatomy(self, noauth_api_session, superuser):
        r = noauth_api_session.iam.post(
            self.login_path,
            json={'uid': superuser.uid, 'password': superuser.password})
        assert r.status_code == 200
        token = r.json()['token']
        assert 'dcos-acs-auth-cookie' in r.cookies
        assert 'dcos-acs-info-cookie' in r.cookies

        # Valide auth cookie content.
        assert r.cookies['dcos-acs-auth-cookie'] == token

        info_json = base64.b64decode(
            r.cookies['dcos-acs-info-cookie']).decode('utf-8')
        info = json.loads(info_json)
        assert 'description' in info
        assert info['uid'] == superuser.uid
        assert not info['is_remote']

        cookies = r.headers['set-cookie'].split(',')
        assert len(cookies) == 2
        for c in cookies:
            c = c.lower()
            if 'dcos-acs-auth-cookie' in c:
                assert 'httponly' in c
                assert 'path=/' in c
                assert 'domain' not in c
                assert 'secure' not in c
            if 'dcos-acs-info-cookie' in c:
                assert 'httponly' not in c
                assert 'domain' not in c
                assert 'secure' not in c
                assert 'path=/' in c


@pytest.mark.parametrize('headers', [
    None,
    {'Authorization': 'foo'},
    {'Authorization': 'token='},
    {'Authorization': 'token=X'}])
def test_invalid_auth_header(noauth_api_session, headers):
    r = noauth_api_session.iam.get('/', headers=headers)
    assert r.status_code == 401
    assert r.headers['WWW-Authenticate'] == 'acsjwt'


@pytest.mark.usefixtures('iam_verify_and_reset')
class TestIAMUserGroupCRUD:

    @pytest.fixture()
    def service_account_uid(self, superuser_api_session) -> str:
        """Return the UID of a service user account."""
        uid = str(uuid.uuid4())
        superuser_api_session.iam.create_service(
            uid=uid,
            pubkey=default_rsa_pubkey,
            description=str(uuid.uuid4()),
        )
        return uid

    def test_create_user_account_log_in_delete(self, superuser_api_session, noauth_api_session):

        # Specify user details.
        uid = 'test-user-1'
        description = 'a test user'
        password = 'Woot-secret-woot'

        # Create user.
        user_path = '/users/' + uid
        r = superuser_api_session.iam.put(user_path, json={'description': description, 'password': password})
        assert r.status_code == 201

        # Log in.
        login_obj = {'uid': uid, 'password': password}
        r = noauth_api_session.iam.post('/auth/login', json=login_obj)
        assert r.status_code == 200
        d = r.json()
        assert 'token' in d

        # Verify that user appears in collection.
        r = superuser_api_session.iam.get('/users')
        uids = [o['uid'] for o in r.json()['array']]
        assert uid in uids

        # Delete user.
        r = superuser_api_session.iam.delete(user_path)
        assert r.status_code == 204

        # Verify that user does not appear in collection anymore.
        r = superuser_api_session.iam.get('/users')
        uids = [o['uid'] for o in r.json()['array']]
        assert uid not in uids

    def test_create_service_account_log_in_delete(self, superuser_api_session, noauth_api_session):

        # Specify service details.
        uid = 'test-service-1'
        description = 'a test service'

        # Create service.
        service_path = '/users/' + uid
        r = superuser_api_session.iam.put(
            service_path,
            json={
                'description': description,
                'public_key': default_rsa_pubkey
                }
            )
        assert r.status_code == 201

        # Log in.
        login_obj = {
            'uid': uid,
            'token': jwt.encode(
                {
                    'exp': int(time.time() + 5 * 60),
                    'uid': uid
                },
                default_rsa_privkey,
                algorithm='RS256')
            .decode('ascii')
            }
        r = noauth_api_session.iam.post('/auth/login', json=login_obj)
        assert r.status_code == 200
        d = r.json()
        assert 'token' in d

        # Verify that service appears in collection.
        r = superuser_api_session.iam.get('/users', query='type=service')
        uids = [o['uid'] for o in r.json()['array']]
        assert uid in uids

        # Delete service.
        r = superuser_api_session.iam.delete(service_path)
        assert r.status_code == 204

        # Verify that service does not appear in collection anymore.
        r = superuser_api_session.iam.get('/users', query='type=service')
        uids = [o['uid'] for o in r.json()['array']]
        assert uid not in uids

    def test_delete_service_user_in_superusers_group(self,
                                                     superuser_api_session,
                                                     service_account_uid):
        """
        A service user which has been granted superuser privileges by being
        added to the `superusers` group can be deleted.
        """
        resp = superuser_api_session.iam.put(
            '/groups/superusers/users/{uid}'.format(uid=service_account_uid))
        assert resp.status_code == 204

        superuser_api_session.iam.delete_service(uid=service_account_uid)

    def test_delete_service_user_assigned_superuser(self,
                                                    superuser_api_session,
                                                    service_account_uid):
        """
        A service user which has been granted superuser privileges by being
        assigned to the `dcos:superuser` ACL can be deleted.
        """
        superuser_api_session.iam.grant_user_permission(
            uid=service_account_uid,
            action='full',
            rid='dcos:superuser',
            )

        superuser_api_session.iam.delete_service(uid=service_account_uid)

    def test_group_membership(self, superuser_api_session, peter):
        # Create group.
        gid = 'test-group-1'
        description = 'Group A'
        group_path = '/groups/' + gid
        r = superuser_api_session.iam.put(group_path, json={'description': description})
        assert r.status_code == 201

        # Verify that group appears in collection.
        r = superuser_api_session.iam.get('groups')
        gids = [o['gid'] for o in r.json()['array']]
        assert gid in gids

        # Put peter into group.
        r = superuser_api_session.iam.put('/groups/{}/users/{}'.format(gid, peter.uid))
        assert r.status_code == 204

        # Confirm membership.
        r = superuser_api_session.iam.get('/users/{}/groups'.format(peter.uid))
        assert r.status_code == 200
        l = r.json()['array']
        assert l[0]['group']['gid'] == gid

        # Delete group.
        r = superuser_api_session.iam.delete(group_path)
        assert r.status_code == 204

        # Verify that group does not appear in collection anymore.
        r = superuser_api_session.iam.get('groups')
        gids = [o['gid'] for o in r.json()['array']]
        assert gid not in gids


def reset_superuser_run(uid, password):
    """
    Runs the `reset-superuser` script for given user and set provided
    password and resets credentials and privileges for uid.

    Args:
        uid (str): User UID to be resetted.
        password (str): New password.

    Raises:
        Exception if script exits with other return code than 0.
    """
    path = '/opt/mesosphere/active/bouncer/bouncer/bin/reset-superuser'
    process = pexpect.spawn(path, [uid])

    # Although password prompt shouldn't be delayed add a safe `timeout`
    # 3 seconds to avoid potential flakyness.
    process.expect('Type superuser password: ', timeout=3)
    process.sendline(password)
    process.expect('Retype superuser password: ', timeout=3)
    process.sendline(password)

    # Make sure that process ended with result code 0
    return_code = process.wait()
    if return_code != 0:
        raise Exception(
            '`reset-superuser` script failed with '
            'return code: `{return_code}`'.format(
                return_code=return_code
                )
            )


@pytest.fixture()
def reset_superuser_password():
    """
    Use bouncer `reset-superuser` script to reset the test super user password.

    Running this script adds considerable time to execution so its not used
    to reset superuser credentials as part of `iam_verify_and_reset`.
    """
    # Run this fixture after tests
    yield

    logging.info(
        'reset-superuser: `{uid}` user password back to `{password}` with '
        'admin priviledges'.format(
            uid=os.environ['DCOS_LOGIN_UNAME'],
            password=os.environ['DCOS_LOGIN_PW'],
            )
        )

    reset_superuser_run(
        os.environ['DCOS_LOGIN_UNAME'], os.environ['DCOS_LOGIN_PW'])


@pytest.mark.usefixtures('iam_verify_and_reset')
class TestIAMResetSuperuser:

    @pytest.mark.usefixtures('reset_superuser_password')
    def test_reset_admin_superuser(
            self, superuser_api_session, noauth_api_session):
        """
        Attempting to reset the password of an existing superuser.
        """
        uid = superuser_api_session.auth_user.uid
        new_password = str(uuid.uuid4())

        reset_superuser_run(uid, new_password)

        # Superuser can no longer login with original password
        r = noauth_api_session.iam.post(
            '/auth/login',
            json={'uid': uid, 'password': os.environ['DCOS_LOGIN_PW']}
            )
        r.status_code == 401

        r = noauth_api_session.iam.post(
            '/auth/login',
            json={'uid': uid, 'password': new_password}
            )
        r.raise_for_status()
        # Assert that bouncer responded with auth token
        assert 'token' in r.json()

    def test_reset_nonexisting_user(
            self, superuser_api_session, noauth_api_session):
        """
        Attempting to reset the password of a user which does not exist creates
        new user with superuser privileges.
        """
        uid = 'new_uid'
        new_password = str(uuid.uuid4())

        # Check that user doesn't exists
        r = superuser_api_session.iam.get('/user/{}'.format(uid))
        assert r.status_code == 404

        reset_superuser_run(uid, new_password)

        r = noauth_api_session.iam.post(
            '/auth/login',
            json={'uid': uid, 'password': new_password}
            )
        r.raise_for_status()
        # Assert that bouncer responded with auth token
        assert 'token' in r.json()

        # Make sure that newly created user is in superusers group
        r = superuser_api_session.iam.get('/groups/superusers/users')
        r.raise_for_status()

        uids = set([u['user']['uid'] for u in r.json()['array']])
        assert uid in uids
