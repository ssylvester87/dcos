import io

import json
import os
import subprocess

import pytest

from dcoscli_fixture import dcoscli_fixture

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


@pytest.fixture(scope='session')
def dcoscli(superuser_api_session):
    return dcoscli_fixture(superuser_api_session)


class TestDCOSCLI:
    def test_cli(self, dcoscli):
        dcoscli.login()

    def test_service_accounts(self, dcoscli):
        dcoscli.setup_enterprise()

        # configure service account
        service_accounts = ["dcos", "security", "org", "service-accounts"]
        dcoscli.exec_command(
            service_accounts + ["keypair", "/tmp/private-key.pem", "/tmp/public-key.pem"])
        dcoscli.exec_command(
            service_accounts + ["create", "-p", "/tmp/public-key.pem", "-d", "test", "test-principal"])
        os.chmod('/tmp/private-key.pem', 0o600)

        # create non strict sa secret in default store
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "security", "secrets", "create-sa-secret",
             "/tmp/private-key.pem", "sa-secret", "/sa-secret"])
        assert stdout == ''
        assert stderr == ''

        # delete secret
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "security", "secrets", "delete", "/sa-secret"])
        assert stdout == ''
        assert stderr == ''

        # login using service account
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "auth", "login", "--username=test-principal", "--private-key=/tmp/private-key.pem"])
        assert stdout == 'Login successful!\n'
        assert stderr == ''

    def test_secrets_management(self, dcoscli):
        dcoscli.login()

        # list secrets
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "security", "secrets", "list", "/"])
        assert stdout == ''
        assert stderr == ''

        # create secret
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "security", "secrets", "create", "--value=newsecret", "/foo"])
        assert stdout == ''
        assert stderr == ''

        # get secret
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "security", "secrets", "get", "/foo"])
        assert stdout == 'value: newsecret\n\n'
        assert stderr == ''

        # update secret
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "security", "secrets", "update", "--value=newestsecret", "/foo"])
        assert stderr == ''

        # list secret
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "security", "secrets", "list", "/"])
        assert stdout == '- foo\n\n'
        assert stderr == ''

        # delete secret
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "security", "secrets", "delete", "/foo"])
        assert stdout == ''
        assert stderr == ''

        # list secrets
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "security", "secrets", "list", "/"])
        assert stdout == ''
        assert stderr == ''

    def test_cluster_management(self, dcoscli):
        # show secret stores
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "security", "cluster", "secret-store", "show"])
        assert stdout == ("default:"
                          "\n    addr: http://127.0.0.1:8200"
                          "\n    description: DC/OS Default Secret Store Backend"
                          "\n    driver: vault"
                          "\n    initialized: true"
                          "\n    sealed: false\n\n")
        assert stderr == ''

        # get secret store seal-status
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "security", "cluster", "secret-store", "seal-status", "default"])
        assert stdout == 'progress: 0\nsealed: false\nshares: 1\nthreshold: 1\n\n'
        assert stderr == ''

        # get secret store status
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "security", "cluster", "secret-store", "status", "default"])
        assert stdout.find('initialized: true\n') == 0
        assert stderr == ''

        # fetch CA certificate
        cacert, stderr = dcoscli.exec_command(
            ["dcos", "security", "cluster", "ca", "cacert"])
        assert cacert != ''
        assert cacert.find('-----BEGIN CERTIFICATE-----') == 0
        assert stderr == ''

        # TODO: enable this as soon as it's fixed
        # list certificates issued by CA
        # stdout, stderr = dcoscli.exec_command(
        #    ["dcos", "security", "cluster", "ca", "certificates"])
        # assert stderr == b''

        # create&sign new certificate.
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "security", "cluster", "ca", "newcert", "--cn", "test-cert", "--host", "test"])
        assert stdout.find('certificate: \'-----BEGIN CERTIFICATE-----') == 0
        assert stderr == ''

        # create new key and CSR.
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "security", "cluster", "ca", "newkey", "--cn", "test-key", "--host", "test"])
        assert stdout.find('certificate: \'-----BEGIN CERTIFICATE-----') == 0
        assert stderr == ''

        # signing profile information.
        stdout, stderr = dcoscli.exec_command(
            ["dcos", "security", "cluster", "ca", "profile", "-j"])
        out = {
            "expiry": "87600h",
            "usages": [
                "signing",
                "key encipherment",
                "client auth",
                "server auth"
            ]
        }
        assert json.loads(stdout) == out
        assert stderr == ''

    def test_users_and_groups(self, dcoscli):
        users = ["dcos", "security", "org", "users"]
        groups = ["dcos", "security", "org", "groups"]

        # show users
        stdout, stderr = dcoscli.exec_command(
            users + ["show"])
        assert stdout == ("peter:"
                          "\n    description: An ordinarily weak Peter"
                          "\n    is_remote: false"
                          "\n    is_service: false"
                          "\ntestadmin:"
                          "\n    description: testadmin"
                          "\n    is_remote: false"
                          "\n    is_service: false\n\n")
        assert stderr == ''

        # show groups
        stdout, stderr = dcoscli.exec_command(
            groups + ["show"])
        assert stdout == 'superusers:\n    description: Superuser group\n\n'
        assert stderr == ''

        # create a user
        stdout, stderr = dcoscli.exec_command(
            users + ["create", "testuser", "-p", "testpass"])
        assert stdout == ''
        assert stderr == ''

        # create a group
        stdout, stderr = dcoscli.exec_command(
            groups + ["create", "testgroup"])
        assert stdout == ''
        assert stderr == ''

        # show a user
        stdout, stderr = dcoscli.exec_command(
            users + ["show"])
        assert stdout == ("peter:"
                          "\n    description: An ordinarily weak Peter"
                          "\n    is_remote: false"
                          "\n    is_service: false"
                          "\ntestadmin:"
                          "\n    description: testadmin"
                          "\n    is_remote: false"
                          "\n    is_service: false"
                          "\ntestuser:"
                          "\n    description: user account `testuser`"
                          "\n    is_remote: false"
                          "\n    is_service: false\n\n")

        assert stderr == ''

        # show groups
        stdout, stderr = dcoscli.exec_command(
            groups + ["show"])
        assert stdout == ("superusers:"
                          "\n    description: Superuser group"
                          "\ntestgroup:"
                          "\n    description: group `testgroup`\n\n")
        assert stderr == ''

        # add a user to group
        stdout, stderr = dcoscli.exec_command(
            groups + ["add_user", "testgroup", "testuser"])
        assert stderr == ''

        # list members of group
        stdout, stderr = dcoscli.exec_command(
            groups + ["members", "testgroup"])
        assert stdout == '- testuser\n\n'
        assert stderr == ''

        # del a user from group
        stdout, stderr = dcoscli.exec_command(
            groups + ["del_user", "testgroup", "testuser"])
        assert stdout == ''
        assert stderr == ''

        # list members of group
        stdout, stderr = dcoscli.exec_command(
            groups + ["members", "testgroup"])
        assert stdout == '[]\n\n'
        assert stderr == ''

        # delete a user
        stdout, stderr = dcoscli.exec_command(
            users + ["delete", "testuser"])
        assert stdout == ''
        assert stderr == ''

        # delete a group
        stdout, stderr = dcoscli.exec_command(
            groups + ["delete", "testgroup"])
        assert stdout == ''
        assert stderr == ''

        # show users
        stdout, stderr = dcoscli.exec_command(
            users + ["show"])
        assert stdout == ("peter:"
                          "\n    description: An ordinarily weak Peter"
                          "\n    is_remote: false"
                          "\n    is_service: false"
                          "\ntestadmin:"
                          "\n    description: testadmin"
                          "\n    is_remote: false"
                          "\n    is_service: false\n\n")
        assert stderr == ''

        # show groups
        stdout, stderr = dcoscli.exec_command(
            groups + ["show"])
        assert stdout == 'superusers:\n    description: Superuser group\n\n'
        assert stderr == ''

    def test_oidc_sso(self, dcoscli):

        base_url = dcoscli.url.scheme + "://localhost/"

        # google OIDC provider configured with localhost
        dcoscli.exec_command(
            ["dcos", "config", "set", "core.dcos_url", base_url])

        # configure OIDC provider
        cmd = ["dcos", "security", "cluster", "oidc", "add",
               "--description", "test",
               "--issuer", "https://accounts.google.com",
               "--base-url", base_url,
               "--client-secret", "LQhYKgiRzzS-b8V2KHe-e64N",
               "--client-id", "791234115532-m91hhinppf2fv7v96o1umoobbkg97vkb.apps.googleusercontent.com",
               "google-oidc-test"]
        dcoscli.exec_command(cmd)

        cmd = ["dcos", "auth", "login", "--provider=google-oidc-test"]
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            env=dcoscli.env,
            universal_newlines=False
        )

        txt_output = io.TextIOWrapper(process.stdout, encoding='utf-8')
        for i in range(4):
            # blocking call
            line = txt_output.readline()

        # ignore SSL cert warning
        driver = webdriver.PhantomJS(
            service_log_path='/tmp/ghostdriver.log',
            service_args=['--ignore-ssl-errors=true', '--ssl-protocol=any']
        )

        # start OIDC auth
        expected_auth_url = base_url + "acs/api/v1/auth/login" + \
            "?oidc-provider=google-oidc-test&target=dcos:authenticationresponse:html"
        auth_url = line.strip("\n ")
        assert expected_auth_url == auth_url
        driver.get(auth_url)

        # We should now be on gmail login page
        # At this point we enter credentials and login to continue auth process

        # add email
        email_field = driver.find_element_by_id('Email')
        # note the spelling below...
        email_field.send_keys('mesophere.oidc.test@gmail.com')
        next_button = driver.find_element_by_id('next')
        next_button.click()

        # wait for dom to update with new fields
        password = WebDriverWait(driver, 120).until(
            EC.element_to_be_clickable(
                (By.XPATH, "//div[@id='password-shown']//input[@id='Passwd']")))
        # add password
        password.send_keys("thefuture")
        # signin
        signin = driver.find_element_by_id('signIn')
        signin.click()

        # allow google access to give info to Relying Party
        # wait for dom to update with "clickable" field
        time.sleep(5)
        allow_access = driver.find_element_by_id('submit_approve_access')
        allow_access.click()

        # We should now be redirected to HTML page with auth token
        dcos_auth_token = driver.find_element_by_class_name('tokenbox').text
        driver.close()

        # test `dcos_auth_token` with CLI
        stdout, _ = process.communicate(input=bytes(dcos_auth_token, 'utf-8'), timeout=None)
        assert stdout.decode('utf-8') == 'Login successful!\n'

        # clean up - remove authenticated user

        # login as superuser
        dcoscli.login()
        # delete user
        cmd = ["dcos", "security", "org", "users", "delete", "mesophere.oidc.test@gmail.com"]
        stdout, stderr = dcoscli.exec_command(cmd)
        assert stdout == ''
        assert stderr == ''
