"""
Test Bouncer's LDAP features.
"""

import logging
from collections import OrderedDict
from textwrap import dedent

import pytest
import requests

from dcostests import IAMUrl


log = logging.getLogger(__name__)


pytestmark = [pytest.mark.security]


class DirectoryBackend:
    """Base class that directory definition classes must inherit from."""

    # Class attributes required to be defined in child classes.
    config = None
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
            'search-filter-template': '(&(objectclass=group)(sAMAccountName=%(groupname)s))',
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


class FreeIPA(DirectoryBackend):
    """
    This requires availability of the freeIPA demo at ipa.demo1.freeipa.org.

    The freeIPA demos supports LDAPS on port 636.

    The configuration implies verification of the server certificate against a
    CA cert chain. The CA cert has been downloaded manually from the demo UI
    at https://ipa.demo1.freeipa.org/ipa/ui/#/e/cert/details/1
    """

    _ca_certs = dedent("""
        -----BEGIN CERTIFICATE-----
        MIIDnTCCAoWgAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MRowGAYDVQQKDBFERU1P
        MS5GUkVFSVBBLk9SRzEeMBwGA1UEAwwVQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4X
        DTE0MDYwNDEwMzQwNVoXDTM0MDYwNDEwMzQwNVowPDEaMBgGA1UECgwRREVNTzEu
        RlJFRUlQQS5PUkcxHjAcBgNVBAMMFUNlcnRpZmljYXRlIEF1dGhvcml0eTCCASIw
        DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALX0IpLxvJ4/chzIdt597mUzOErw
        K8UGga3t/Aspf1x+/+iUqulU+sa4LIn5zXbYAQRNM4eh4VwkW2u6FUr3Dpvsu4rJ
        eEFOYmkcbIfTmM56hFMgBdKam9Txf/Yg+9zYk7LND5pvrCpDbEnO147NAnYryEa4
        +PHQeTH+h8WNbXhrpKEOrWQS1TUdKVdzKOW/UQEpUadWjOHO0jaz3mvr7WgZ4jtB
        G2nT/jXLLdxdKfHFR5NfIZqrCUYcdVah21SFK3Jr79ZGsxhewvAPsyemJ3etY46h
        aqU8c2L8aaKvlJlRc2axVmsUSxWC0hazCBI/PI71bQrxzgcJaHOoQx78uaMCAwEA
        AaOBqTCBpjAfBgNVHSMEGDAWgBQlv+uoMsiGBvVjMQrl7Q4HK3H1UjAPBgNVHRMB
        Af8EBTADAQH/MA4GA1UdDwEB/wQEAwIBxjAdBgNVHQ4EFgQUJb/rqDLIhgb1YzEK
        5e0OBytx9VIwQwYIKwYBBQUHAQEENzA1MDMGCCsGAQUFBzABhidodHRwOi8vaXBh
        LmRlbW8xLmZyZWVpcGEub3JnOjgwL2NhL29jc3AwDQYJKoZIhvcNAQELBQADggEB
        AAQxoZNrwd0Zy64aLp7qib6CIvYmzhNm8isZDek9vrgmgQ2AJQ1T3CXSqfNkYz6z
        +qufLPxRvDz555b2giU33wBlWW73wTlSm8OcPsVdglfjH7SdEs/hvkvHKJXB14tJ
        SdDB4FDcH1WR8PDgwxiaVK+74OgZ2uf9AX/VcaxvgKrla+fveNZpXhvVwuZ1llQT
        HLfjgoVUBdPvxLmszjeuLRQ9E6YeYUsog6sV8BylFrlGY0Ft9MmXZZw6darhlOfC
        xrfgPM4UB6S2dyaPslP3ivTUKFGqi9DTmu9ipHYJwJBP/Ea0yNZN94+5aCKxwCAF
        FGBbIc59FVGTGUo01C7/6t8=
        -----END CERTIFICATE-----
        """)

    config = OrderedDict([
        ('host', 'ipa.demo1.freeipa.org'),
        ('port', 636),
        ('enforce-starttls', True),
        ('use-ldaps', True),
        ('lookup-dn', 'uid=employee,cn=users,cn=compat,dc=demo1,dc=freeipa,dc=org'),
        ('lookup-password', 'Secret123'),
        ('user-search', {
            'search-filter-template': '(uid=%(username)s)',
            'search-base': 'cn=users,cn=compat,dc=demo1,dc=freeipa,dc=org'
            }),
        ('ca-certs', _ca_certs),
        ])

    _user_credentials = {
        'manager': {'uid': 'manager', 'password': 'Secret123'},
        }


def set_config(directory_backend, superuser):
    """
    Submit `directory_backend.config` as current DC/OS LDAP configuration.
    """
    log.info("Set LDAP config: %s", directory_backend.config)
    r = requests.put(
        IAMUrl('/ldap/config'),
        json=directory_backend.config,
        headers=superuser.auth_header
        )
    r.raise_for_status()
    assert r.status_code == 200


def remove_config(superuser):
    """
    Remove current DC/OS LDAP configuration.
    """
    log.info("Remove current LDAP config")
    r = requests.delete(
        IAMUrl('/ldap/config'),
        headers=superuser.auth_header
        )
    if not r.status_code == 204:
        assert r.status_code == 400
        assert r.json()['code'] == 'ERR_LDAP_CONFIG_NOT_AVAILABLE'


@pytest.yield_fixture()
def ads1(superuser):
    d = ADS1()
    set_config(d, superuser)
    yield d
    remove_config(superuser)


@pytest.yield_fixture()
def freeipa(superuser):
    d = FreeIPA()
    set_config(d, superuser)
    yield d
    remove_config(superuser)


@pytest.mark.usefixtures("iam_verify_and_reset")
class TestADS1:

    def test_configtester(self, ads1, superuser):

        r = requests.post(
            IAMUrl('/ldap/config/test'),
            json=ads1.credentials('john1'),
            headers=superuser.auth_header
            )
        r.raise_for_status()
        assert r.json()['code'] == 'TEST_PASSED'

    def test_authentication_delegation(self, superuser, ads1):

        r = requests.post(
            IAMUrl('/auth/login'),
            json=ads1.credentials('john1')
            )
        r.raise_for_status()
        token = r.json()['token']
        assert r.cookies['dcos-acs-auth-cookie'] == token

        # Verify user john1 has ben (implicitly) imported in the process of
        # delegating authentication to the directory back-end. Note that the
        # `iam_verify_and_reset` ensures that john1 does not exist prior to
        # executing this test.
        r = requests.get(
            IAMUrl('/users'),
            headers=superuser.auth_header
            )
        r.raise_for_status()

        # Create dictionary with keys being uids and values being
        # user dictionaries.
        users = {d['uid']: d for d in r.json()['array']}
        assert users['john1']['is_remote'] is True

    def test_groupimport(self, ads1, superuser):

        r = requests.post(
            IAMUrl('/ldap/importgroup'),
            json={"groupname": "johngroup"},
            headers=superuser.auth_header
            )
        assert r.status_code == 201

        john_uids = ('john1', 'john2', 'john3')

        # Verify users have been (implicitly) imported
        # and labeled as remote users.
        r = requests.get(
            IAMUrl('/users'),
            headers=superuser.auth_header
            )
        r.raise_for_status()
        l = r.json()['array']
        users = {d['uid']: d for d in l}
        for uid in john_uids:
            assert users[uid]['is_remote'] is True

        # Verify that `johngroup` exists and that it has
        # the expected set of members.
        r = requests.get(
            IAMUrl('/groups/johngroup/users'),
            headers=superuser.auth_header
            )
        r.raise_for_status()
        l = r.json()['array']
        assert set((d['user']['uid'] for d in l)) == set(john_uids)


@pytest.mark.usefixtures("iam_verify_and_reset")
class TestFreeIPA:

    def test_configtester(self, freeipa, superuser):

        r = requests.post(
            IAMUrl('/ldap/config/test'),
            json=freeipa.credentials('manager'),
            headers=superuser.auth_header
            )
        r.raise_for_status()
        assert r.json()['code'] == 'TEST_PASSED'

    def test_authentication_delegation(self, freeipa):

        r = requests.post(
            IAMUrl('/auth/login'),
            json=freeipa.credentials('manager')
            )
        r.raise_for_status()
        token = r.json()['token']
        assert r.cookies['dcos-acs-auth-cookie'] == token
