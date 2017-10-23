"""
Test authentication behavior of various components.
"""
import pytest

import requests

from ee_helpers import bootstrap_config

pytestmark = [
    pytest.mark.security,
    pytest.mark.skipif(
        bootstrap_config['security'] in {'disabled', 'permissive'},
        reason=("Authentication tests skipped: currently adjusted to only run in strict security mode")
    )
]


ENDPOINT_PARAMS = [
    ('get', '/acs/api/v1/users', None, None),
    ('get', '/v2/apps', 'master', 8443),
    ('get', '/v1/jobs', 'master', 9443),
    ('post', '/teardown', 'master', 5050),
    ('get', '/containers', 'agent', 5051),
    ('get', '/system/health/v1', 'agent', 61002)]


def make_request(api_session, method, path, host, port):
    if host == 'master':
        host = api_session.masters[0]
    elif host == 'agent':
        host = api_session.slaves[0]
    elif host is not None:
        raise AssertionError('Bad host parameter: {}. Use master or agent'.format(host))
    return getattr(api_session, method)(path, host=host, port=port)


@pytest.mark.parametrize('method, path, host, port', ENDPOINT_PARAMS)
def test_component_auth_direct_no_auth(
        noauth_api_session, method, path, host, port):
    r = make_request(noauth_api_session, method, path, host, port)
    assert r.status_code == 401
    # We must adjust the expectation for Mesos agent API endpoints (currently
    # just '/containers') because the agent loads two authenticators in strict
    # mode, so its 'WWW-Authenticate' header will contain two challenges.
    if path == '/containers':
        challenges = r.headers['WWW-Authenticate'].split(',')
        assert 'Bearer' in challenges
        assert 'acsjwt' in challenges
    else:
        assert r.headers['WWW-Authenticate'] == 'acsjwt'


@pytest.mark.parametrize('method, path, host, port', ENDPOINT_PARAMS)
def test_component_auth_direct_forged_token(
        forged_superuser_session, method, path, host, port):
    r = make_request(forged_superuser_session, method, path, host, port)
    assert r.status_code == 401
    # We must adjust the expectation for Mesos agent API endpoints (currently
    # just '/containers') because the agent loads two authenticators in strict
    # mode, so its 'WWW-Authenticate' header will contain two challenges.
    if path == '/containers':
        challenges = r.headers['WWW-Authenticate'].split(',')
        assert 'Bearer' in challenges
        assert 'acsjwt' in challenges
    else:
        assert r.headers['WWW-Authenticate'] == 'acsjwt'


@pytest.mark.parametrize('method, path, host, port', ENDPOINT_PARAMS)
def test_component_auth_direct_peter(
        peter_api_session, method, path, host, port):
    r = make_request(peter_api_session, method, path, host, port)
    # Expect success or forbidden.
    try:
        r.raise_for_status()
    except requests.HTTPError:
        if r.request.url is not None and 'teardown' in r.request.url:
            assert r.status_code == 400
        else:
            assert r.status_code == 403
