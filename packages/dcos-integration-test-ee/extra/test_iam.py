"""
Test IAM/Bouncer functionality through Admin Router.
"""


import base64
import json
import logging
import time

import jwt
import pytest
import requests
from jwt.utils import base64url_decode

from dcostests import dcos, IAMUrl, Url


log = logging.getLogger(__name__)


pytestmark = [pytest.mark.security]


class TestIAM404s:

    def test_acs(self):
        r = requests.get(Url('/acs'))
        assert r.status_code == 404

    def test_acs_api(self):
        r = requests.get(Url('/acs/api'))
        assert r.status_code == 404


class TestIAMPublicEndpointReachability:

    def test_jwks(self):
        r = requests.get(IAMUrl('/auth/jwks'))
        assert r.status_code == 200

    def test_login(self):
        r = requests.get(IAMUrl('/auth/login'))
        assert r.status_code == 400
        d = r.json()
        _ = d  # noqa

    def test_logout(self):
        r = requests.get(IAMUrl('/auth/logout'))
        assert r.status_code == 200

    def test_saml_providers(self):
        r = requests.get(IAMUrl('/auth/saml/providers'))
        assert r.status_code == 200

    def test_oidc_providers(self):
        r = requests.get(IAMUrl('/auth/oidc/providers'))
        assert r.status_code == 200

    def test_oidc_callback_url(self):
        r = requests.get(IAMUrl('/auth/oidc/callback'))
        assert r.status_code == 401
        data = r.json()
        assert 'dcos-iam-oidc-state cookie missing' in data['description']

    def test_saml_callback_url(self):
        r = requests.post(
            IAMUrl('/auth/saml/providers/unknown/acs-callback'),
            json={}
            )
        data = r.json()
        assert 'SAML provider `unknown` not known' in data['description']


class TestIAMLoginEndpointBehavior:

    login_url = IAMUrl('/auth/login')

    def test_accessible_wo_auth(self):
        r = requests.get(self.login_url)
        assert r.status_code == 400
        d = r.json()
        assert 'ERR_MISSING_QUERY_PARAMETERS' == d['code']

    def test_missing_content_type(self):
        # requests does not always set a content-type, use this here.
        r = requests.post(self.login_url, data="rofl")
        assert r.status_code == 400
        d = r.json()
        assert "Missing Content-Type header" in d['description']

    def test_post_wrong_content_type(self):
        r = requests.post(
            self.login_url,
            data="MyVariableOne=ValueOne&MyVariableTwo=ValueTwo",
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
        assert r.status_code == 400
        d = r.json()
        assert "Request has bad Content-Type or lacks JSON" in d['description']

    def test_post_invalid_credentials(self):
        r = requests.post(
            self.login_url,
            json={'uid': 'unknown', 'password': 'not-the-right-one'}
            )
        assert r.status_code == 401
        assert r.json()['code'] == "ERR_INVALID_CREDENTIALS"
        assert r.headers['WWW-Authenticate'] == 'acsjwt'

    def test_post_superuser_credentials_verify_token_cookies_in_resp(self):
        r = requests.post(
            self.login_url,
            json={'uid': dcos.su_uid, 'password': dcos.su_password}
            )
        assert r.status_code == 200
        assert 'token' in r.json()
        assert 'dcos-acs-auth-cookie' in r.cookies
        assert 'dcos-acs-info-cookie' in r.cookies

    def test_authtoken_anatomy(self):
        r = requests.post(
            self.login_url,
            json={'uid': dcos.su_uid, 'password': dcos.su_password}
            )
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
        assert payload_dict['uid'] == dcos.su_uid

    def test_cookies_anatomy(self):
        r = requests.post(
            self.login_url,
            json={'uid': dcos.su_uid, 'password': dcos.su_password}
            )
        token = r.json()['token']

        assert 'dcos-acs-auth-cookie' in r.cookies
        assert 'dcos-acs-info-cookie' in r.cookies

        # Valide auth cookie content.
        assert r.cookies['dcos-acs-auth-cookie'] == token

        info_json = base64.b64decode(
            r.cookies['dcos-acs-info-cookie']).decode('utf-8')
        info = json.loads(info_json)
        assert 'description' in info
        assert info['uid'] == dcos.su_uid
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


class TestIAMLogoutEndpointBehavior:

    def test_logout_simple(self):
        """Test bouncer's logout endpoint. It's a soft logout, instructing
        the user agent to delete the authentication cookie, i.e. this test
        does not have side effects on other tests.
        """
        r = requests.get(IAMUrl('/auth/logout'))
        cookieheader = r.headers['set-cookie']
        assert 'dcos-acs-auth-cookie=;' in cookieheader
        assert 'expires' in cookieheader.lower()


class TestIAMInvalidAuthHeader:

    def test_auth_required(self):
        r = requests.get(IAMUrl('/'))
        assert r.status_code == 401
        assert r.headers['WWW-Authenticate'] == 'acsjwt'

    def test_invalid_auth_header(self):
        r = requests.get(IAMUrl('/'), headers={'Authorization': 'foo'})
        assert r.status_code == 401
        assert r.headers['WWW-Authenticate'] == 'acsjwt'

    def test_invalid_auth_header2(self):
        r = requests.get(IAMUrl('/'), headers={'Authorization': 'token='})
        assert r.status_code == 401
        assert r.headers['WWW-Authenticate'] == 'acsjwt'

    def test_invalid_auth_header3(self):
        r = requests.get(IAMUrl('/'), headers={'Authorization': 'token=X'})
        assert r.status_code == 401
        assert r.headers['WWW-Authenticate'] == 'acsjwt'


@pytest.mark.usefixtures("iam_verify_and_reset")
class TestIAMUserGroupCRUD:

    def test_create_user_account_log_in_delete(self, superuser):

        # Specify user details.
        uid = 'test-user-1'
        description = 'a test user'
        password = 'Woot-secret-woot'

        # Create user.
        user_url = IAMUrl('/users/%s' % uid)
        r = requests.put(
            user_url,
            json={'description': description, 'password': password},
            headers=superuser.authheader
            )
        assert r.status_code == 201

        # Log in.
        login_obj = {'uid': uid, 'password': password}
        r = requests.post(IAMUrl('/auth/login'), json=login_obj)
        assert r.status_code == 200
        d = r.json()
        assert 'token' in d

        # Verify that user appears in collection.
        r = requests.get(IAMUrl('/users'), headers=superuser.authheader)
        uids = [o['uid'] for o in r.json()['array']]
        assert uid in uids

        # Delete user.
        r = requests.delete(user_url, headers=superuser.authheader)
        assert r.status_code == 204

        # Verify that user does not appear in collection anymore.
        r = requests.get(IAMUrl('/users'), headers=superuser.authheader)
        uids = [o['uid'] for o in r.json()['array']]
        assert uid not in uids

    def test_create_service_account_log_in_delete(self, superuser):

        # Specify service details.
        uid = 'test-service-1'
        description = 'a test service'
        sharedsecret = 'Woot-secret-woot'

        # Create service.
        service_url = IAMUrl('/users/%s' % uid)
        r = requests.put(
            service_url,
            json={'description': description, 'secret': sharedsecret},
            headers=superuser.authheader
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
                sharedsecret,
                algorithm='HS256')
            .decode('ascii')
            }
        r = requests.post(IAMUrl('/auth/login'), json=login_obj)
        assert r.status_code == 200
        d = r.json()
        assert 'token' in d

        # Verify that service appears in collection.
        r = requests.get(
            IAMUrl('/users?type=service'),
            headers=superuser.authheader
            )
        uids = [o['uid'] for o in r.json()['array']]
        assert uid in uids

        # Delete service.
        r = requests.delete(service_url, headers=superuser.authheader)
        assert r.status_code == 204

        # Verify that service does not appear in collection anymore.
        r = requests.get(
            IAMUrl('/users?type=service'),
            headers=superuser.authheader
            )
        uids = [o['uid'] for o in r.json()['array']]
        assert uid not in uids

    def test_group_membership(self, superuser, peter):
        # Create group.
        gid = 'test-group-1'
        description = 'Group A'
        group_url = IAMUrl('/groups/%s' % gid)
        r = requests.put(
            group_url,
            json={'description': description},
            headers=superuser.authheader
            )
        assert r.status_code == 201

        # Verify that group appears in collection.
        r = requests.get(
            IAMUrl('/groups'),
            headers=superuser.authheader
            )
        gids = [o['gid'] for o in r.json()['array']]
        assert gid in gids

        # Put peter into group.
        r = requests.put(
            IAMUrl('/groups/%s/users/%s' % (gid, peter.uid)),
            headers=superuser.authheader
            )
        assert r.status_code == 204

        # Confirm membership.
        r = requests.get(
            IAMUrl('/users/%s/groups' % peter.uid),
            headers=superuser.authheader
            )
        assert r.status_code == 200
        l = r.json()['array']
        assert l[0]['group']['gid'] == gid

        # Delete group.
        r = requests.delete(group_url, headers=superuser.authheader)
        assert r.status_code == 204

        # Verify that group does not appear in collection anymore.
        r = requests.get(IAMUrl('/groups'), headers=superuser.authheader)
        gids = [o['gid'] for o in r.json()['array']]
        assert gid not in gids
