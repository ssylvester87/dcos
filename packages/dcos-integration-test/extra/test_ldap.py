"""
Test Bouncer's LDAP features.
"""

import logging
from collections import OrderedDict

import pytest
import requests

from dcos_test_utils.helpers import session_tempfile

log = logging.getLogger(__name__)

pytestmark = [pytest.mark.security]


class DirectoryBackend:
    """Base class that directory definition classes must inherit from."""

    _user_credentials = {}

    def credentials(self, user):
        return self._user_credentials[user]


class ADS1(DirectoryBackend):
    """
    Requires that ads1.mesosphere.com is available and set up in a special
    way.

    The AWS SimpleAD does not support LDAPS (start out with a TLS-wrapped
    socket), but it supports StartTLS.

    Note(JP): do not know where to obtain a CA cert to validate against.
    """

    config = OrderedDict([
        ('host', 'ads1.mesosphere.com'),
        ('port', 389),
        ('enforce-starttls', True),
        ('use-ldaps', False),
        ('lookup-dn', 'cn=lookupuser,cn=Users,dc=mesosphere,dc=com'),
        ('lookup-password', 'pw-l00kup'),
        ('group-search', {
            'search-filter-template':
            '(&(objectclass=group)(sAMAccountName=%(groupname)s))',
            'search-base': 'cn=Users,dc=mesosphere,dc=com'
        }),
        ('user-search', {
            'search-filter-template': '(sAMAccountName=%(username)s)',
            'search-base': 'cn=Users,dc=mesosphere,dc=com'
        })
    ])

    _user_credentials = {
        'john1': {'uid': 'john1', 'password': 'pw-john1'},
        'john2': {'uid': 'john2', 'password': 'pw-john2'},
        'john3': {'uid': 'john4', 'password': 'pw-john3'},
    }


class FreeIPAClient:

    def __init__(self, host, username, password):
        self._host = host

        # perform login and store the authentication cookies
        self._login(username, password)

        self.ca_cert = None
        self.ca_cert_file = None

        # get and store the CA certificate from the server
        self._set_ca()

    def _set_ca(self):
        query = {
            'id': 0,
            'method':
            'cert_show',
            'params': [['1'], {'version': '2.156'}]
        }
        # we cannot verify the SSL certificates yet as we don't have
        # them yet. That is the point of this function
        r = self._json_rpc(query, should_verify=False)
        certjson = r.json()
        self.ca_cert = '' \
            + '-----BEGIN CERTIFICATE-----\n' \
            + certjson['result']['result']['certificate'] + '\n' \
            + '-----END CERTIFICATE-----\n'
        self.ca_cert_file = session_tempfile(self.ca_cert.encode())

    def _login(self, username, password):
        """
        Log into freeIPA instance and store the resulting cookies
        """
        headers = {
            'Referer': 'https://' + self._host + '/ipa',
            'Accept': 'text/plain'
        }
        creds = {'user': username, 'password': password}
        # since we need to log in before we can
        # obtain the cert, we have no choice but to set
        # verify=False
        r = requests.post(
            'https://' + self._host + '/ipa/session/login_password',
            headers=headers,
            data=creds,
            verify=False
        )
        r.raise_for_status()
        self._cookies = r.cookies

    def add_group(self, group):
        """
        Add a group with the given name to freeIPA.
        """
        query = {
            "id": 0,
            "method": "group_add",
            "params": [
                [
                    group
                ],
                {
                    "all": False,
                    "external": False,
                    "no_members": False,
                    "nonposix": False,
                    "raw": False,
                    "version": "2.156"
                }
            ]
        }
        self._json_rpc(query)

    def add_user(self, username, password):
        """
        Add a user with the given username and password to freeIPA.
        """
        realm = "FREEIPA.MARATHON.L4LB.THISDCOS.DIRECTORY"
        query = {
            "id": 0,
            "method": "user_add",
            "params": [
                [
                    username
                ],
                {
                    "all": False,
                    "cn": username.capitalize() + " Test",
                    "displayname": username.capitalize() + " Test",
                    "gecos": username.capitalize() + " Test",
                    "givenname": username.capitalize(),
                    "initials": "MT",
                    "krbprincipalname": username + "@" + realm,
                    "no_members": False,
                    "noprivate": False,
                    "random": False,
                    "raw": False,
                    "sn": "Test",
                    "userpassword": password,
                    "version": "2.156"
                }
            ]
        }
        self._json_rpc(query)

    def add_group_members(self, group, members):
        """
        Add the given list of members (a list of strings) to
        the group with the given name.
        """
        query = {
            "id": 0,
            "method": "group_add_member",
            "params": [
                [
                    group
                ],
                {
                    "all": False,
                    "no_members": False,
                    "raw": False,
                    "user": members,
                    "version": "2.156"
                }
            ]
        }
        self._json_rpc(query)

    def delete_user(self, username):
        query = {
            "id": 0,
            "method": "user_del",
            "params": [
                [
                    [
                        username
                    ]
                ],
                {
                    "continue": False,
                    "version": "2.156"
                }
            ]
        }
        self._json_rpc(query)

    def _json_rpc(self, query, should_verify=True):
        """
        Perform a JSON-RPC POST against the freeIPA service,
        injecting the given query dictionary appropriately.

        Returns: The response to the JSON-RPC request.
        """

        headers = {
            'Referer': 'https://' + self._host + '/ipa',
            'Accept': 'application/json'
        }
        url = 'https://' + self._host + '/ipa/session/json'

        verify = False
        if should_verify:
            verify = self.ca_cert_file

        r = requests.post(
            url,
            headers=headers,
            cookies=self._cookies,
            json=query,
            verify=verify
        )
        r.raise_for_status()
        return r


class FreeIPA(DirectoryBackend):

    _user_credentials = {
        'manager': {'uid': 'manager', 'password': 'Secret123'},
    }

    def __init__(self, host, ca_cert):
        dc = ','.join(['dc=' + level for level in host.split('.')])
        self.config = OrderedDict([
            ('host', host),
            ('port', 636),
            ('enforce-starttls', True),
            ('use-ldaps', True),
            ('lookup-dn', 'uid=employee,cn=users,cn=compat,' + dc),
            ('lookup-password', 'Secret123'),
            ('user-search', {
                'search-filter-template': '(uid=%(username)s)',
                'search-base': 'cn=users,cn=compat,' + dc
            }),
            ('group-search', {
                'search-filter-template': '(cn=%(groupname)s)',
                'search-base': 'cn=groups,cn=compat,' + dc
            }),
            ('ca-certs', ca_cert),
        ])


def set_config(config, superuser_api_session):
    """
    Submit `directory_backend.config` as current DC/OS LDAP configuration.
    """
    log.info("Set LDAP config: %s", config)
    r = superuser_api_session.iam.put('/ldap/config', json=config)
    r.raise_for_status()
    assert r.status_code == 200


def remove_config(superuser_api_session):
    """
    Remove current DC/OS LDAP configuration.
    """
    log.info("Remove current LDAP config")
    r = superuser_api_session.iam.delete('/ldap/config')
    if not r.status_code == 204:
        assert r.status_code == 400
        assert r.json()['code'] == 'ERR_LDAP_CONFIG_NOT_AVAILABLE'


@pytest.fixture()
def ads1(superuser_api_session):
    d = ADS1()
    set_config(d.config, superuser_api_session)
    yield d
    remove_config(superuser_api_session)


@pytest.fixture(scope="module")
def freeipa(superuser_api_session):
    """
    The freeipa fixture starts and populates a freeIPA container
    running on marathon in the DC/OS cluster under test. It destroys
    the application when the tests have finished.
    """

    # start the freeIPA application on marathon
    # and clean it up once the tests complete
    with superuser_api_session.marathon.deploy_and_cleanup(
            _freeipa_marathon_definition(),
            timeout=1200):
        # the hostname of the freeIPA server
        host = "freeipa.marathon.l4lb.thisdcos.directory"

        # connect to freeIPA using a requests wrapper
        client = FreeIPAClient(
            host,
            username='admin',
            password='Secret123'
        )

        # create users and groups for tests
        client.add_user("manager", "Secret123")
        client.add_user("employee", "Secret123")
        client.add_group("employees")
        client.add_group_members("employees", ["manager", "employee"])

        # configure bouncer to use freeIPA as backend
        d = FreeIPA(host, client.ca_cert)
        set_config(d.config, superuser_api_session)
        yield d
        # remove freeIPA config from bouncer
        remove_config(superuser_api_session)


def _freeipa_marathon_definition():
    """
    Returns the appropriate marathon app definition as a dictionary
    ready to be marshalled to JSON.
    """

    ipa_url = "https://freeipa.marathon.l4lb.thisdcos.directory/ipa"
    referer = ipa_url
    login_url = ipa_url + "/session/login_password"
    headers = [
        "Content-Type:application/x-www-form-urlencoded",
        "Accept:text/plain"
    ]
    curl_cmd = "curl {opts} {headers} {url}".format(
        opts="-fk --referer '{referer}' --data '{data}' -XPOST".format(
            referer=referer,
            data="user=admin&password=Secret123"
        ),
        headers=' '.join(["-H '{}'".format(header) for header in headers]),
        url=login_url
    )
    return {
        "id": "/freeipa",
        "env": {
            "IPA_SERVER_INSTALL_OPTS": ' '.join([
                "--ds-password=Secret123",
                "--admin-password=Secret123",
                "--realm=FREEIPA.MARATHON.L4LB.THISDCOS.DIRECTORY",
                "--domain=freeipa.marathon.l4lb.thisdcos.directory",
                "--hostname=freeipa.marathon.l4lb.thisdcos.directory",
                "--unattended",
                "--no-host-dns"
            ])
        },
        "instances": 1,
        "cpus": 1,
        "mem": 4096,
        "maxLaunchDelaySeconds": 3600,
        "container": {
            "docker": {
                "image": "mesosphere/freeipa-server:4.3",
                "privileged": True,
                "parameters": [
                    {
                        "key": "hostname",
                        "value": "freeipa.marathon.l4lb.thisdcos.directory"
                    }
                ],
                "portMappings": [
                    {
                        "containerPort": 80,
                        "protocol": "tcp",
                        "name": "http",
                        "servicePort": 80,
                        "labels": {
                            "VIP_0": "/freeipa:80"
                        }
                    },
                    {
                        "containerPort": 636,
                        "protocol": "tcp",
                        "name": "ldaps",
                        "servicePort": 636,
                        "labels": {
                            "VIP_1": "/freeipa:636"
                        }
                    },
                    {
                        "containerPort": 443,
                        "protocol": "tcp",
                        "name": "https",
                        "servicePort": 443,
                        "labels": {
                            "VIP_2": "/freeipa:443"
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
                "gracePeriodSeconds": 900,
                "intervalSeconds": 10,
                "timeoutSeconds": 10,
                "maxConsecutiveFailures": 1
            }
        ],
        "ipAddress": {
            "networkName": "dcos"
        }
    }


@pytest.mark.usefixtures("iam_verify_and_reset")
class TestADS1:

    def test_configtester(self, ads1, superuser_api_session):

        r = superuser_api_session.iam.post('/ldap/config/test', json=ads1.credentials('john1'))
        r.raise_for_status()
        assert r.json()['code'] == 'TEST_PASSED'

    def test_authentication_delegation(self, superuser_api_session, noauth_api_session, ads1):

        r = noauth_api_session.iam.post('/auth/login', json=ads1.credentials('john1'))
        r.raise_for_status()
        token = r.json()['token']
        assert r.cookies['dcos-acs-auth-cookie'] == token

        # Verify user john1 has ben (implicitly) imported in the process of
        # delegating authentication to the directory back-end. Note that the
        # `iam_verify_and_reset` ensures that john1 does not exist prior to
        # executing this test.
        r = superuser_api_session.iam.get('/users')
        r.raise_for_status()

        # Create dictionary with keys being uids and values being
        # user dictionaries.
        users = {d['uid']: d for d in r.json()['array']}
        assert users['john1']['is_remote'] is True

    def test_groupimport(self, ads1, superuser_api_session):

        r = superuser_api_session.iam.post('/ldap/importgroup', json={"groupname": "johngroup"})
        assert r.status_code == 201

        john_uids = ('john1', 'john2', 'john3')

        # Verify users have been (implicitly) imported
        # and labeled as remote users.
        r = superuser_api_session.iam.get('/users')
        r.raise_for_status()
        users = {d['uid']: d for d in r.json()['array']}
        for uid in john_uids:
            assert users[uid]['is_remote'] is True

        # Verify that `johngroup` exists and that it has
        # the expected set of members.
        r = superuser_api_session.iam.get('/groups/johngroup/users')
        r.raise_for_status()
        assert set((d['user']['uid'] for d in r.json()['array'])) == set(john_uids)


@pytest.mark.usefixtures("iam_verify_and_reset")
class TestFreeIPA:

    def test_configtester(self, freeipa, superuser_api_session):
        r = superuser_api_session.iam.post('/ldap/config/test', json=freeipa.credentials('manager'))
        r.raise_for_status()
        assert r.json()['code'] == 'TEST_PASSED'

    def test_authentication_delegation(self, freeipa, noauth_api_session):
        """
        check that bouncer delegates authentication to the
        configured freeipa authentication service and responds
        with an appropriate DCOS authentication token
        """
        r = noauth_api_session.iam.post('/auth/login', json=freeipa.credentials('manager'))
        r.raise_for_status()
        token = r.json()['token']
        assert r.cookies['dcos-acs-auth-cookie'] == token

    def test_groupimport(self, freeipa, superuser_api_session):

        r = superuser_api_session.iam.post('/ldap/importgroup', json={"groupname": "employees"})
        assert r.status_code == 201

        expected_uids = ('manager', 'employee')

        # Verify users have been (implicitly) imported
        # and labeled as remote users.
        r = superuser_api_session.iam.get('/users')
        r.raise_for_status()
        users = {d['uid']: d for d in r.json()['array']}
        for uid in expected_uids:
            assert users[uid]['is_remote'] is True

        # Verify that a group with gid `employees` exists
        # and that it has the expected set of members.
        r = superuser_api_session.iam.get('/groups/employees/users')
        r.raise_for_status()
        assert set((d['user']['uid'] for d in r.json()['array'])) == set(expected_uids)
