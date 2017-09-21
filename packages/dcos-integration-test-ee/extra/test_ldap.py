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
        MIIDnTCCAoWgAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MRowGAYDVQQKDBFERU1PMS5GUkVF
        SVBBLk9SRzEeMBwGA1UEAwwVQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTE3MDYxNzIwMDEx
        N1oXDTM3MDYxNzIwMDExN1owPDEaMBgGA1UECgwRREVNTzEuRlJFRUlQQS5PUkcxHjAcBgNV
        BAMMFUNlcnRpZmljYXRlIEF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
        ggEBAJ74Ls217EF9bKBX9rXh82UKOZV6OqlVBokwflAA/syyLuxgSNUfnCvB2P9dOArahUlk
        pjoRXA78xh8W9W0C2XpMpkxmxyhZ9eyvahZJ/Cg9wmhUR5cHBkmT0nabyk/5LIjdwlWdo64V
        My5qSbZwCvxpL3KiBdmDDE6P7X3Ml5vW5kYfoa3+aJ2vqJ7YUL5vbSLphgbnMkdlmFlQA6mY
        y5wf4iQKwOBrbFMUmQZ3YT3yzaliAeVTryZkhXMn+a4pJLFTSL+eq5sApJHXrI4IPS7zv41x
        gDFNun/JdyCkMNcY50mLev1rIb+9dESfgFhccUpgKwhsipfBzqn+Agelq3sCAwEAAaOBqTCB
        pjAfBgNVHSMEGDAWgBQqGKV6KM2CtMlHFSqGcYPoE2s1kDAPBgNVHRMBAf8EBTADAQH/MA4G
        A1UdDwEB/wQEAwIBxjAdBgNVHQ4EFgQUKhileijNgrTJRxUqhnGD6BNrNZAwQwYIKwYBBQUH
        AQEENzA1MDMGCCsGAQUFBzABhidodHRwOi8vaXBhLWNhLmRlbW8xLmZyZWVpcGEub3JnL2Nh
        L29jc3AwDQYJKoZIhvcNAQELBQADggEBAAQuFYzVey5X9pVLGnpeKBnmeMZf6bpC6yqDsnXw
        +PNqtSUu6bfkm/USvobSDKDlMC2pcuYrp32fS6toZ0Qy8h/J27YdG0RAML93JGXoTtOqQuPE
        ecR1u8bdcmb9Zw0ICdDQPaQLPbAzIEtM7sxXQYJgIVr2nnZtxB77B/brvRPdrmC/EuMZEeMZ
        YNY/k5TKUsdp+peylCbdJteXlUg6F665/RKJz2eYOJHQ2g11MLjvqkumviohlUPHuGs6QgMl
        9cultf14vMzAeyDvJXsT5o92rK8xWHQUX7tdcJAf5H5SGhvCr9xV+T7pz2S6nTTY+uTK+sbg
        LsZeJ1MP/At2tpA=
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
        headers=superuser.authheader
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
        headers=superuser.authheader
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
            headers=superuser.authheader
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
            headers=superuser.authheader
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
            headers=superuser.authheader
            )
        assert r.status_code == 201

        john_uids = ('john1', 'john2', 'john3')

        # Verify users have been (implicitly) imported
        # and labeled as remote users.
        r = requests.get(
            IAMUrl('/users'),
            headers=superuser.authheader
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
            headers=superuser.authheader
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
            headers=superuser.authheader
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
