import json

import pytest


@pytest.fixture()
def secrets_fixture(dcoscli, request):
    value, path = request.param

    dcoscli.setup_enterprise()
    # create secret
    stdout, stderr = dcoscli.exec_command(
        ["dcos", "security", "secrets", "create", "--value={}".format(value), path])
    assert stdout == ''
    assert stderr == ''

    yield dcoscli

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


class TestDCOSCLI:
    def test_cli(self, dcoscli):
        dcoscli.setup()

    def test_service_accounts(self, service_accounts_fixture):
        cli, name, private_key, public_key = service_accounts_fixture

        # create non strict sa secret in default store
        stdout, stderr = cli.exec_command(
            ["dcos", "security", "secrets", "create-sa-secret",
             private_key, "sa-secret", "/sa-secret"])
        assert stdout == ''
        assert stderr == ''

        # delete secret
        stdout, stderr = cli.exec_command(
            ["dcos", "security", "secrets", "delete", "/sa-secret"])
        assert stdout == ''
        assert stderr == ''

    @pytest.mark.parametrize('secrets_fixture', [
        ("newsecret", "/foo")
        ], indirect=True)
    def test_secrets_management(self, secrets_fixture):

        # get secret
        stdout, stderr = secrets_fixture.exec_command(
            ["dcos", "security", "secrets", "get", "/foo"])
        assert stdout == 'value: newsecret\n\n'
        assert stderr == ''

        # update secret
        stdout, stderr = secrets_fixture.exec_command(
            ["dcos", "security", "secrets", "update", "--value=newestsecret", "/foo"])
        assert stderr == ''

        # list secret
        stdout, stderr = secrets_fixture.exec_command(
            ["dcos", "security", "secrets", "list", "/"])
        assert stdout == '- foo\n\n'
        assert stderr == ''

    def test_cluster_management(self, dcoscli):
        dcoscli.setup_enterprise()

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

    def test_users_and_groups(self, dcoscli, iam_verify_and_reset):
        dcoscli.setup_enterprise()

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
