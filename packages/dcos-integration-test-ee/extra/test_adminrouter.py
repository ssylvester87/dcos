"""
Test if nginx endpoints are serving, either static or dynamic.

Test subtle details of nginx configuration.

Tests should not modify cluster state.
"""


import logging

import pytest
import requests
import retrying

from dcostests import dcos, Url


log = logging.getLogger(__name__)


@pytest.mark.security
class TestHttpHttpsConfig:

    @pytest.mark.xfail(
        dcos.config['security'] != 'disabled',
        reason='AR must not serve / over HTTP except in security-disabled mode.',
        strict=True
    )
    def test_root_path_http(self):
        r = requests.get(Url('/', scheme='http'), allow_redirects=False)
        assert r.status_code == 200

    @pytest.mark.xfail(
        dcos.config['security'] == 'disabled',
        reason='AR is not expected to redirect from HTTP to HTTPS in disabled mode.',
        strict=True
    )
    def test_root_path_http_https_redirect(self):
        r = requests.get(Url('/', scheme='http'), allow_redirects=False)
        assert r.status_code == 307
        assert r.headers['location'].startswith('https')

        r = requests.get(Url('/', scheme='http'))
        assert r.status_code == 200
        assert '<html' in r.text

    @pytest.mark.xfail(
        dcos.config['security'] == 'strict',
        reason='AR must not serve /mesos/ over HTTP in strict-security mode.',
        strict=True
    )
    def test_mesos_path_http(self, superuser):
        r = requests.get(
            Url('/mesos/', scheme='http'),
            headers=superuser.authheader,
            allow_redirects=False
            )
        assert r.status_code == 200
        assert '<html' in r.text

    @pytest.mark.xfail(
        dcos.config['security'] != 'strict',
        reason='AR is only expected to redirect non-root paths from HTTP to HTTPS in strict mode.',
        strict=True
    )
    def test_mesos_path_http_https_redirect(self, superuser):
        r = requests.get(
            Url('/mesos/', scheme='http'),
            headers=superuser.authheader,
            allow_redirects=False
            )
        assert r.status_code == 307
        assert r.headers['location'].startswith('https')

        r = requests.get(
            Url('/mesos/', scheme='http'),
            headers=superuser.authheader
            )
        assert r.status_code == 200
        assert '<html' in r.text

    @pytest.mark.xfail(
        dcos.config['security'] == 'disabled',
        reason='AR does not support HTTPS with security disabled',
        strict=True
    )
    def test_root_path_https_cert_verification(self):
        r = requests.get(Url('/', scheme='https'))
        assert r.status_code == 200


class TestResourceAvailability:

    def test_dcos_ui(self):
        r = requests.get(Url('/'))
        assert r.status_code == 200
        assert len(r.text) > 100
        assert '<html' in r.text
        assert '<script' in r.text
        assert 'DC/OS' in r.text

    def test_dcos_version_anonymous(self):
        r = requests.get(Url('/dcos-metadata/dcos-version.json'))
        assert r.status_code == 200

    def test_ui_config(self, superuser):
        r = requests.get(
            Url('/dcos-metadata/ui-config.json'),
            headers=superuser.authheader
            )
        assert r.status_code == 200
        assert 'uiConfiguration' in r.json()

    def test_dcos_history_service_api(self, superuser):
        r = requests.get(
            Url('/dcos-history-service/ping'),
            headers=superuser.authheader
            )
        assert r.status_code == 200
        assert 'pong' == r.text

    def test_marathon_ui(self, superuser):
        r = requests.get(
            Url('/service/marathon/ui/'),
            headers=superuser.authheader
            )
        assert r.status_code == 200
        assert len(r.text) > 100
        assert '<title>Marathon</title>' in r.text

    def test_legacy_marathon_endpoint(self, superuser):
        r = requests.get(
            Url('/marathon/ui/'),
            headers=superuser.authheader
            )
        assert r.status_code == 200
        assert len(r.text) > 100
        assert '<title>Marathon</title>' in r.text

    def test_mesos_ui(self, superuser):
        r = requests.get(Url('/mesos'), headers=superuser.authheader)
        assert r.status_code == 200
        assert len(r.text) > 100
        assert '<title>Mesos</title>' in r.text

    def test_mesos_dns_api(self, superuser):
        r = requests.get(
            Url('/mesos_dns/v1/version'),
            headers=superuser.authheader
            )
        assert r.status_code == 200
        data = r.json()
        assert data["Service"] == 'Mesos-DNS'

    def test_pkgpanda_metadata(self, superuser):
        r = requests.get(
            Url('/pkgpanda/active.buildinfo.full.json'),
            headers=superuser.authheader
            )
        assert r.status_code == 200
        data = r.json()
        assert 'mesos' in data
        assert len(data) > 5  # (prozlach) We can try to put minimal number of pacakages required

    def test_exhibitor_api(self, superuser):
        r = requests.get(
            Url('/exhibitor/exhibitor/v1/cluster/list'),
            headers=superuser.authheader
            )
        assert r.status_code == 200
        data = r.json()
        assert data["port"] > 0

    def test_exhibitor_ui(self, superuser):
        r = requests.get(
            Url('/exhibitor'),
            headers=superuser.authheader
            )
        assert r.status_code == 200
        assert '<html' in r.text
        assert 'Exhibitor for ZooKeeper' in r.text

    def test_ca_cert_retrieval(self):
        # Expect CA cert to be accessible w/o authentication.
        r = requests.get(Url('/ca/dcos-ca.crt'))
        assert r.status_code == 200
        assert 'BEGIN CERTIFICATE' in r.text
        assert r.headers['Content-Type'] == 'application/x-x509-ca-cert'

    def test_jks_ca_cert_retrieval(self):
        # No authentication required.
        r = requests.get(Url('/ca/cacerts.jks'))
        assert r.status_code == 200
        assert r.headers['Content-Type'] == 'application/x-java-keystore'


def test_agents_endpoint_unknown_agent():

    r = requests.get(Url('/slave/foo/bar'))
    assert r.status_code == 404

    r = requests.get(Url('/agent/foo/bar'))
    assert r.status_code == 404


# Retry if returncode is False, do not retry on exceptions.
@retrying.retry(wait_fixed=2000,
                retry_on_result=lambda r: r is False,
                retry_on_exception=lambda _: False)
def test_agents_endpoint_all_agents(superuser):

    # Get currently known agents. This request is served through Admin Router
    # straight from Mesos (no AdminRouter-based caching is involved).

    r = requests.get(
        Url('/mesos/master/state'),
        headers=superuser.authheader
        )
    assert r.status_code == 200
    agent_ids = sorted(x['id'] for x in r.json()['slaves'])
    log.info('Obtained these agent IDs: %s', agent_ids)

    for agent_id in agent_ids:
        # Admin Router's agent endpoint internally uses cached Mesos
        # state data. That is, agent IDs of just recently joined
        # agents can be unknown here. For those, this endpoint
        # returns a 404. Retry in this case, until this endpoint
        # is confirmed to work for all known agents.

        # Test both, /slave and /agent Admin Router endpoints.
        paths = (
            '/slave/{}/slave%281%29/state.json'.format(agent_id),
            '/agent/{}/slave%281%29/state.json'.format(agent_id)
            )

        for p in paths:
            r = requests.get(Url(p), headers=superuser.authheader)

            # Retry in that case.
            if r.status_code == 404:
                return False

            assert r.status_code == 200
            data = r.json()
            assert "id" in data
            assert data["id"] == agent_id


class TestServiceEndpoint:
    # Test the more subtle details of the service endpoint, such as slash
    # behavior test /service/marathon and /service/marathon/
    pass
