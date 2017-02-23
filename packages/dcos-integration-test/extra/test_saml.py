"""
Test Bouncer's SAML integration with Shibboleth
"""

import io
import os
import subprocess
import tempfile
from collections import namedtuple

import pytest

import test_ldap
from ee_helpers import bootstrap_config

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

pytestmark = [pytest.mark.security]

SamlUser = namedtuple("SamlUser", ["username", "password", "email"])

# Service Provider base URL configured in Shibboleth IdP
SP_BASE_URL = "https://master.mesos"

# Shibboleth IdP Metadata
IDP_METADATA = """<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:shibmd="urn:mace:shibboleth:metadata:1.0"
    xmlns:xml="http://www.w3.org/XML/1998/namespace"
    xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
    entityID="https://shibboleth.marathon.l4lb.thisdcos.directory/idp/shibboleth">
    <IDPSSODescriptor
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol
        urn:oasis:names:tc:SAML:1.1:protocol
        urn:mace:shibboleth:1.0">
        <Extensions>
            <shibmd:Scope
                regexp="false">shibboleth.marathon.l4lb.thisdcos.directory</shibmd:Scope>
        </Extensions>

        <KeyDescriptor>
            <ds:KeyInfo>
                    <ds:X509Data>
                        <ds:X509Certificate>
MIIDFDCCAfygAwIBAgIVAN3vv+b7KN5Se9m1RZsCllp/B/hdMA0GCSqGSIb3DQEB
CwUAMBUxEzARBgNVBAMMCmlkcHRlc3RiZWQwHhcNMTUxMjExMDIyMDE0WhcNMzUx
MjExMDIyMDE0WjAVMRMwEQYDVQQDDAppZHB0ZXN0YmVkMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAh91caeY0Q85uhaUyqFwP2bMjwMFxMzRlAoqBHd7g
u6eo4duaeLz1BaoR2XTBpNNvFR5oHH+TkKahVDGeH5+kcnIpxI8JPdsZml1srvf2
Z6dzJsulJZUdpqnngycTkGtZgEoC1vmYVky2BSAIIifmdh6s0epbHnMGLsHzMKfJ
Cb/Q6dYzRWTCPtzE2VMuQqqWgeyMr7u14x/Vqr9RPEFsgY8GIu5jzB6AyUIwrLg+
MNkv6aIdcHwxYTGL7ijfy6rSWrgBflQoYRYNEnseK0ZHgJahz4ovCag6wZAoPpBs
uYlY7lEr89Ucb6NHx3uqGMsXlDFdE4QwfDLLhCYHPvJ0uwIDAQABo1swWTAdBgNV
HQ4EFgQUAkOgED3iYdmvQEOMm6u/JmD/UTQwOAYDVR0RBDEwL4IKaWRwdGVzdGJl
ZIYhaHR0cHM6Ly9pZHB0ZXN0YmVkL2lkcC9zaGliYm9sZXRoMA0GCSqGSIb3DQEB
CwUAA4IBAQBIdd4YWlnvJjql8+zKKgmWgIY7U8DA8e6QcbAf8f8cdE33RSnjI63X
sv/y9GfmbAVAD6RIAXPFFeRYJ08GOxGI9axfNaKdlsklJ9bk4ducHqgCSWYVer3s
RQBjxyOfSTvk9YCJvdJVQRJLcCvxwKakFCsOSnV3t9OvN86Ak+fKPVB5j2fM/0fZ
Kqjn3iqgdNPTLXPsuJLJO5lITRiBa4onmVelAiCstI9PQiaEck+oAHnMTnC9JE/B
DHv3e4rwq3LznlqPw0GSd7xqNTdMDwNOWjkuOr3sGpWS8ms/ZHHXV1Vd22uPe70i
s00xrv14zLifcc8oj5DYzOhYRifRXgHX
                        </ds:X509Certificate>
                    </ds:X509Data>
            </ds:KeyInfo>
        </KeyDescriptor>

        <NameIDFormat>urn:mace:shibboleth:1.0:nameIdentifier</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>

        <SingleSignOnService
            Binding="urn:mace:shibboleth:1.0:profiles:AuthnRequest"
            Location="https://shibboleth.marathon.l4lb.thisdcos.directory:4443/idp/profile/Shibboleth/SSO"/>
        <SingleSignOnService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="https://shibboleth.marathon.l4lb.thisdcos.directory:4443/idp/profile/SAML2/POST/SSO"/>
        <SingleSignOnService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"
            Location="https://shibboleth.marathon.l4lb.thisdcos.directory:4443/idp/profile/SAML2/POST-SimpleSign/SSO"/>
        <SingleSignOnService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="https://shibboleth.marathon.l4lb.thisdcos.directory:4443/idp/profile/SAML2/Redirect/SSO"/>
    </IDPSSODescriptor>
</EntityDescriptor>"""


@pytest.fixture(scope="module")
def dcoscli_enterprise(dcoscli):
    dcoscli.setup_enterprise()
    yield dcoscli


@pytest.fixture()
def browser():
    driver = webdriver.PhantomJS(
        service_log_path='/tmp/ghostdriver.log',
        service_args=['--ignore-ssl-errors=true', '--ssl-protocol=any'])
    driver.set_window_size(1024, 968)
    yield driver
    driver.close()


@pytest.fixture()
def ipd_metadata_file():
    """ This fixture writes contents of the IDP_METADATA variable to a file so
    it can be used as an argument where CLI expects path to metadat file

    IdP Metadata contains information about SAML Identity provider Service"""
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, 'w') as file:
        file.write(IDP_METADATA)
    yield path
    os.remove(path)


@pytest.fixture(scope="module")
def freeipa_app(superuser_api_session):
    """
    The freeipa_app fixture starts and populates a freeIPA container
    running on marathon in the DC/OS cluster under test. It destroys
    the application when the tests have finished.
    """

    freeipa_marathon = test_ldap._freeipa_marathon_definition()
    # Expose also port 389 ldap that is not used by test_ldap but shibboleth
    # uses it for FreeIPA connection.
    freeipa_marathon['container']['docker']['portMappings'].append({
        "containerPort": 389,
        "protocol": "tcp",
        "name": "ldap",
        "servicePort": 389,
        "labels": {
            "VIP_3": "/freeipa:389"
        }
    })

    # start the freeIPA application on marathon
    # and clean it up once the tests complete
    with superuser_api_session.marathon.deploy_and_cleanup(freeipa_marathon, timeout=1200):
        # connect to freeIPA using a requests wrapper
        client = test_ldap.FreeIPAClient(
            "freeipa.marathon.l4lb.thisdcos.directory",
            username='admin',
            password='Secret123'
        )

        # create users and groups for tests
        client.add_user("manager", "Secret123")
        client.add_user("employee", "Secret123")
        client.add_group("employees")
        client.add_group_members("employees", ["manager", "employee"])

        yield client


@pytest.fixture(scope="module")
def shibboleth_app(freeipa_app, superuser_api_session):
    """
    The shibboleth_app fixture starts and populates a freeIPA container
    running on marathon in the DC/OS cluster under test. It destroys
    the application when the tests have finished.
    """
    # start the freeIPA application on marathon
    # and clean it up once the tests complete
    with superuser_api_session.marathon.deploy_and_cleanup(
            _shibboleth_marathon_definition(),
            timeout=1200):
        yield


def _shibboleth_marathon_definition():
    """
    Returns the appropriate marathon app definition as a dictionary
    ready to be marshalled to JSON.
    """
    shibboleth_url = "https://shibboleth.marathon.l4lb.thisdcos.directory:4443/idp/shibboleth"
    curl_cmd = "curl -fk -s {url}".format(url=shibboleth_url)
    return {
        "id": "/shibboleth",
        "env": {
            "JETTY_BROWSER_SSL_KEYSTORE_PASSWORD": "password",
            "JETTY_BACKCHANNEL_SSL_KEYSTORE_PASSWORD": "password"
        },
        "instances": 1,
        "cpus": 1,
        "mem": 2048,
        "maxLaunchDelaySeconds": 3600,
        "container": {
            "type": "DOCKER",
            "docker": {
                # TODO(mhrabovcin): Move container to mesosphere/shibboleth-idp:[VERSION]
                "image": "mhrabovcin/shibboleth-idp:latest",
                "privileged": True,
                "parameters": [
                    {
                        "key": "hostname",
                        "value": "shibboleth.marathon.l4lb.thisdcos.directory"
                    }
                ],
                "portMappings": [
                    {
                        "containerPort": 4443,
                        "protocol": "tcp",
                        "name": "http",
                        "servicePort": 4443,
                        "labels": {
                            "VIP_0": "/shibboleth:4443"
                        }
                    }
                ],
                "network": "USER"
            }
        },
        "healthChecks": [
            {
                "protocol": "COMMAND",
                "command": {
                    "value": curl_cmd
                },
                "gracePeriodSeconds": 120,
                "intervalSeconds": 10,
                "timeoutSeconds": 10,
                "maxConsecutiveFailures": 1
            }
        ],
        "ipAddress": {
            "networkName": "dcos"
        }
    }


@pytest.fixture()
def shibboleth_idp(shibboleth_app, superuser_api_session):
    """
    The shibboleth_idp fixture uses shibboleth_app and configures bouncer
    to support shibboleth_app as a SAML identity provider.
    """
    # Its important to keep this provider ID as it's also defined in the
    # idp-metadata.xml file
    provider_id = 'shib-integration-test'
    r = superuser_api_session.iam.put(
        '/auth/saml/providers/{}'.format(provider_id),
        json={
            "description": "shibboleth_idp",
            "sp_base_url": SP_BASE_URL,
            "idp_metadata": IDP_METADATA,
            }
        )
    assert r.status_code == 201

    yield provider_id

    r = superuser_api_session.iam.delete(
        '/auth/saml/providers/{}'.format(provider_id))
    assert r.status_code == 204


@pytest.mark.usefixtures("iam_verify_and_reset")
class TestShibbolethSAML:

    # This user is created in freeipa_app fixture
    SAML_USER = SamlUser(
        'employee',
        'Secret123',
        'employee@freeipa.marathon.l4lb.thisdcos.directory'
        )

    def test_add_and_delete_valid_idp_provider(self, superuser_api_session):
        """
        Test adding and removing a valid SAML provider
        """
        provider_id = 'shib-integration-test'
        r = superuser_api_session.iam.put(
            '/auth/saml/providers/{}'.format(provider_id),
            json={
                "description": "TestShibbolethSAML::test_add_and_delete_valid_idp_provider",
                "sp_base_url": SP_BASE_URL,
                "idp_metadata": IDP_METADATA,
                }
            )
        assert r.status_code == 201

        # Clean up provider configuration
        r = superuser_api_session.iam.delete(
            '/auth/saml/providers/{}'.format(provider_id))
        assert r.status_code == 204

    def test_add_and_delete_valid_idp_provider_with_cli(
            self,
            dcoscli_enterprise,
            superuser_api_session,
            ipd_metadata_file,
            ):
        """
        Test adding and removing a valid SAML provider
        """
        provider_id = "shib-integration-test-crud"
        dcoscli_enterprise.exec_command(
            ["dcos", "security", "cluster", "saml", "add",
             "--description", "test_add_and_delete_valid_idp_provider_with_cli",
             "--sp-base-url", SP_BASE_URL,
             "--idp-metadata", ipd_metadata_file,
             provider_id]
            )

        stdout, _stderr = dcoscli_enterprise.exec_command(
            ["dcos", "security", "cluster", "saml", "show", provider_id])
        assert 'sp_base_url: {}'.format(SP_BASE_URL) in stdout

        # Clean up provider configuration
        r = superuser_api_session.iam.delete(
            '/auth/saml/providers/{}'.format(provider_id))
        assert r.status_code == 204

    @pytest.mark.skipif(
        bootstrap_config['security'] == 'disabled',
        reason='Shibboleth IdP expects DC/OS UI available on https://master.mesos',
        )
    def test_login_with_valid_user(
            self,
            superuser_api_session,
            shibboleth_idp,
            browser,
            ):
        """
        Tests whole login flow with a valid user and checks that user was
        authenticated and implicitly imported.
        """

        # Start login flow by visiting DC/OS frontpage. We're starting with
        # static master.mesos URL that is configured as Shibboleth Service
        # Provider
        browser.get(SP_BASE_URL)

        # Let browser driver work and render all service providers links and
        # wait until the link is clickable
        ui_xpath = ('//div[@class="login-modal-auth-providers"]' +
                    '//a[contains(@class, "login-modal-auth-provider")]' +
                    '[contains(@href, "shib")]')
        login_link = WebDriverWait(browser, 120).until(
            EC.element_to_be_clickable((By.XPATH, ui_xpath)))

        # Make sure that login link was found on frontpage
        assert login_link
        login_link.click()

        # Make sure that user got redirected to correct Shibboleth URL
        assert browser.current_url.startswith(
            'https://shibboleth.marathon.l4lb.thisdcos.directory:4443/' +
            'idp/profile/SAML2/Redirect/SSO'
            )

        # Fill user details and click login button
        browser.find_element_by_id('username').send_keys(
            self.SAML_USER.username)
        browser.find_element_by_id('password').send_keys(
            self.SAML_USER.password)
        browser.find_element_by_name('_eventId_proceed').click()

        # Browser should be redirected at Shibboleth page that offers user to
        # accept releasing user details to third party (bouncer)

        # Click Accept button which should complete SAML flow and create
        # new bouncer user
        browser.find_element_by_name('_eventId_proceed').click()

        # Make sure that user ended back at DC/OS URL
        assert SP_BASE_URL in browser.current_url

        # Validate that newly authenticated user exists in bouncer
        resp = superuser_api_session.iam.get(
            '/users/{}'.format(self.SAML_USER.email))
        resp.raise_for_status()

        # There is no need to delete newly authenticated user as
        # "iam_verify_and_reset" already handles that.

    @pytest.mark.skipif(
        bootstrap_config['security'] == 'disabled',
        reason='Shibboleth IdP expects DC/OS UI available on https://master.mesos',
        )
    def test_login_via_cli(
            self,
            dcoscli_enterprise,
            superuser_api_session,
            shibboleth_idp,
            browser,
            ):
        with dcoscli_enterprise.dcos_url(SP_BASE_URL):
            process = dcoscli_enterprise.start_command(
                ["dcos", "auth", "login",
                 "--provider={}".format(shibboleth_idp)],
                stderr=subprocess.STDOUT,
                )

            auth_url = None
            # Read stdout lines until the line contains an Auth URL
            stdout = io.TextIOWrapper(process.stdout, encoding='utf-8')
            while auth_url is None:
                line = stdout.readline().strip("\n ")
                if line.startswith('http'):
                    auth_url = line

            expected_auth_url = (
                SP_BASE_URL +
                '/acs/api/v1/auth/login?saml-provider={}'.format(
                    shibboleth_idp) +
                '&target=dcos:authenticationresponse:html')
            assert auth_url == expected_auth_url

            browser.get(auth_url)

            # Make sure that user got redirected to correct Shibboleth URL
            assert browser.current_url.startswith(
                'https://shibboleth.marathon.l4lb.thisdcos.directory:4443/' +
                'idp/profile/SAML2/Redirect/SSO'
                )

            # Fill user details and click login button
            browser.find_element_by_id('username').send_keys(
                self.SAML_USER.username)
            browser.find_element_by_id('password').send_keys(
                self.SAML_USER.password)
            browser.find_element_by_name('_eventId_proceed').click()

            # Browser should be redirected at Shibboleth page that offers user
            # to accept releasing user details to third party (bouncer)

            # Click Accept button which should complete SAML flow and create
            # new bouncer user
            browser.find_element_by_name('_eventId_proceed').click()

            # Make sure that user ended back at DC/OS URL
            assert SP_BASE_URL in browser.current_url

            # We should now be redirected to HTML page with auth token
            dcos_auth_token = WebDriverWait(browser, 30).until(
                EC.element_to_be_clickable(
                    (By.XPATH, "//div[@class='tokenbox wrap']"))).text

            # test `dcos_auth_token` with CLI
            stdout, _ = process.communicate(
                input=dcos_auth_token.encode(), timeout=None)
            assert 'Login successful!' in stdout.decode('utf-8')

            # Authenticate back as an admin
            dcoscli_enterprise.login()

            # Validate that newly authenticated user exists in the bouncer
            stdout, _ = dcoscli_enterprise.exec_command(
                ["dcos", "security", "org", "users", "show", self.SAML_USER.email])

            assert "SAML-authenticated (Provider ID: {})".format(shibboleth_idp) in stdout
            assert "is_remote: true" in stdout
            assert "is_service: false" in stdout
