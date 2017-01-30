"""
Test Admin Router's authentication and authorization behavior.

These tests intend to cover large parts of Admin Router's auth.lua module.
"""
import pytest

from ee_helpers import OPS_ENDPOINTS

pytestmark = [pytest.mark.security]


@pytest.mark.usefixtures("iam_verify_and_reset")
class TestAccessControlMarathon:

    def test_anonymous_access(self, noauth_api_session):
        r = noauth_api_session.get('/service/marathon')
        assert r.status_code == 401
        assert r.headers['WWW-Authenticate'] == 'acsjwt'

    def test_peteraccess(self, peter_api_session):
        assert peter_api_session.get('/service/marathon').status_code == 403

    def test_su_access(self, superuser_api_session):
        assert superuser_api_session.get('/service/marathon').status_code == 200

    def test_wu_access_service_marathon_with_perm(self, superuser_api_session, peter_api_session, peter):
        # Verify that Peter cannot access.
        assert peter_api_session.get('/service/marathon').status_code == 403

        # Add peter to ACL, with action full.
        assert superuser_api_session.iam.put(
            '/acls/dcos:adminrouter:service:marathon/users/{}/full'.format(peter.uid)).status_code == 204

        # Attempt to access again.
        assert peter_api_session.get('/service/marathon/').status_code == 200


class TestErrorPages:

    def test_nonauth_html_body(self, noauth_api_session):
        r = noauth_api_session.iam.get('/users')
        assert r.status_code == 401
        assert '<html>' in r.text
        assert '</html>' in r.text
        # Make sure that this is UI's error page body, including some
        # JavaScript.
        assert 'window.location' in r.text
        assert r.headers['content-type'] == 'text/html; charset=UTF-8'
        assert r.headers['WWW-Authenticate'] == 'acsjwt'

    def test_permdenied_html_body(self, peter_api_session):
        r = peter_api_session.iam.get('/users')
        assert r.status_code == 403
        assert '<html>' in r.text
        assert '</html>' in r.text
        # Make sure that this is the UI's error page body, including some
        # JavaScript.
        assert 'window.location' in r.text
        assert r.headers['content-type'] == 'text/html; charset=UTF-8'


class TestCookieAuth:
    """Test authentication with cookie.

    The majority of tests use the Authorization header as auth mechanism,
    whereas the typical interaction between a browser and DC/OS requires
    cookie-based authentication to work.
    """

    def test_access_with_auth_cookie(self, noauth_api_session, superuser, peter):
        wucookie = {'dcos-acs-auth-cookie': peter.auth_cookie}
        sucookie = {'dcos-acs-auth-cookie': superuser.auth_cookie}

        # Super user has access.
        assert noauth_api_session.iam.get('/users', cookies=sucookie).status_code == 200

        # Weak user does not have access.
        assert noauth_api_session.iam.get('/users', cookies=wucookie).status_code == 403

    def test_access_with_both_cookie_and_auth_header(self, noauth_api_session, superuser, peter):
        """Existence of Authorization header overrides auth cookie."""

        sucookie = {'dcos-acs-auth-cookie': superuser.auth_cookie}
        invalidauthheader = {'Authorization': 'token=wrong-token'}

        # Set valid auth header and invalid cookie: must succeed.
        r = noauth_api_session.iam.get(
            '/users',
            cookies=sucookie,
            headers=superuser.auth_header)
        assert r.status_code == 200

        # Set invalid auth header and valid cookie: must fail.
        r = noauth_api_session.iam.get(
            '/users',
            cookies=sucookie,
            headers=invalidauthheader)
        assert r.status_code == 401
        assert r.headers['WWW-Authenticate'] == 'acsjwt'

        # Set valid auth header (wu) and valid cookie (su): perm denied.
        r = noauth_api_session.iam.get(
            '/users',
            cookies=sucookie,
            headers=peter.auth_header)
        assert r.status_code == 403


@pytest.mark.parametrize("endpoint", OPS_ENDPOINTS)
def test_with_forged_header(endpoint, forged_superuser_session):
    assert forged_superuser_session.get(endpoint).status_code == 401
