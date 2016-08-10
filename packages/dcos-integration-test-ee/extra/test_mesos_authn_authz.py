import logging

import pytest
import requests

from dcostests import dcos, Url


log = logging.getLogger(__name__)


def get_mesos_endpoints(mesos_url):
    assert not mesos_url.endswith('/')
    data = requests.get(mesos_url + '/help?format=json').json()

    needle = ('\n### AUTHENTICATION ###\n'
              'This endpoint requires authentication')

    endpoints = []
    for top_level in data['processes']:
        for endpoint in top_level['endpoints']:
            is_authenticated = needle in endpoint['text']
            path = mesos_url + '/' + top_level['id'] + endpoint['name']
            endpoints.append({
                'path': path,
                'authenticated': is_authenticated
                })

    return endpoints


@pytest.mark.security
@pytest.mark.xfail(
    dcos.config['security'] == 'disabled',
    reason='Mesos authN is disabled in security-disabled mode and is expected to fail.',
    strict=True
    )
def test_mesos_endpoint_authn(superuser):
    """Test that Mesos endpoints behave as expected with respect to authentication"""

    def get_unauthenticated(url):
        ''' Performs an unauthenticated `GET` of `path` '''
        return requests.get(url)

    def get_authenticated(url):
        ''' Performs a Bouncer-authenticated `GET` of `path` '''
        return requests.get(url, headers=superuser.authheader)

    def request(url, do_authed, master):
        _get = get_authenticated if do_authed else get_unauthenticated

        # Handle special case that expects query parameters, and inject dummy
        # that we know to exist, depending on master/slave state.
        if 'files/browse' in url:
            if master:
                url = url + '?path=/master/log'
            else:
                url = url + '?path=/slave/log'

        if 'api/v1' in url:
            # These are not expected to be locked down.
            return

        r = _get(url)

        log.debug(
            'Got %s with %s request for endpoint %s. Response: \n%s',
            r.status_code,
            'authenticated' if do_authed else 'unauthenticated',
            endpoint,
            r.text
            )

        if endpoint['authenticated']:
            if do_authed:
                assert r.status_code != 401, \
                    'authenticated endpoint {} does not accept authentication' \
                    .format(endpoint['path'])
            else:
                assert r.status_code == 401, \
                    'authenticated endpoint {} incorrectly allows unauthenticated requests' \
                    .format(endpoint['path'])
        else:
            assert r.status_code != 401, \
                'unauthenticated endpoint {} rejected request due to missing authentication' \
                .format(endpoint['path'])

    master_url = str(Url('', host=dcos.masters[0], port=5050))
    agent_url = str(Url('', host=dcos.agents[0], port=5051))

    for endpoint in get_mesos_endpoints(master_url):
        for do_authed in [False, True]:
            request(url=(endpoint['path']), do_authed=do_authed, master=True)

    for endpoint in get_mesos_endpoints(agent_url):
        for do_authed in [False, True]:
            request(url=(endpoint['path']), do_authed=do_authed, master=False)
