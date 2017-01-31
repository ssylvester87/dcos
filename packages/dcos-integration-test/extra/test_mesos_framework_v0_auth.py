# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

import json
import logging
import os
import subprocess

from tempfile import mkstemp

import pytest
import retrying

from ee_helpers import bootstrap_config
from test_iam import generate_RSA_keypair
from util import parse_dotenv

test_framework_name = "integration_test"
test_zknode = test_framework_name


def _create_temp_service(superuser_api_session, uid, keypair):
    superuser_api_session.iam.create_service(uid, keypair[1], 'Integration Test Service')

    credentials = superuser_api_session.iam.make_service_account_credentials(uid, keypair[0])

    fd, path = mkstemp()
    os.write(fd, json.dumps(credentials).encode('ascii'))
    os.close(fd)

    return path


def _delete_temp_service(superuser_api_session, uid, credentials):
    os.remove(credentials)
    superuser_api_session.iam.delete_service(uid)


@pytest.fixture(scope="function")
def zk_test_session():
    yield
    subprocess.check_call([
        "source /opt/mesosphere/environment.export; "
        "/opt/mesosphere/active/exhibitor/usr/zookeeper/bin/zkCli.sh -server 127.0.0.1:2181 "
        "rmr /" + test_zknode
    ], shell=True)


@pytest.fixture(scope="module")
def service_accounts(superuser_api_session):
    alice_keypair = generate_RSA_keypair()
    bob_keypair = generate_RSA_keypair()

    services = {
        # 'alice' has permissions setup to register frameworks for the role
        # '*'.
        'default': {
            'uid': 'alice',
            'path': '',
            'keypair': alice_keypair,
            'action': 'create',
            'rid': 'dcos:mesos:master:framework:role:*'
        },
        # 'bob' has permissions setup to register frameworks for the role
        # 'foo'.
        'secondary': {
            'uid': 'bob',
            'path': '',
            'keypair': bob_keypair,
            'action': 'create',
            'rid': 'dcos:mesos:master:framework:role:foo'
        },
        # 'broken' has an unmatching combination of public and private key
        # setup.
        'invalid': {
            'uid': 'broken',
            'path': '',
            'keypair': [alice_keypair[0], bob_keypair[1]],
            'action': '',
            'rid': ''
        }
    }

    params = ["default", "secondary", "invalid"]

    for param in params:
        logging.info('Creating service account \'{}\'...'.format(param))

        services[param]['path'] = _create_temp_service(
            superuser_api_session, services[param]['uid'], services[param]['keypair'])

        if len(services[param]['rid']) and len(services[param]['action']):
            superuser_api_session.iam.create_acl(services[param]['rid'], 'Integration Test Framework Role')
            superuser_api_session.iam.create_user_permission(
                services[param]['uid'],
                services[param]['action'],
                services[param]['rid'])

    yield services

    for param in params:
        if len(services[param]['rid']) and len(services[param]['action']):
            superuser_api_session.iam.delete_user_permission(
                services[param]['uid'],
                services[param]['action'],
                services[param]['rid'])
            superuser_api_session.iam.delete_acl(services[param]['rid'])

        _delete_temp_service(superuser_api_session, services[param]['uid'], services[param]['path'])


def _run_framework(authenticate, principal, credentials, role):
    """Run classic RPC framework to register depending on the use of
    authentication.

    Args:
        authenticate: use classic RPC authenticatee module
        principal: framework principal
        credentials: service account credentials
        role: framework role when registering

    Returns:
        Popen
    """

    # Use test environment as a baseline.
    env = os.environ.copy()

    # Add crucial environment variables specific to Marathon.
    # TODO(tillt): Consider parsing the Marathon service description
    # and thereby all effective environment modifications.
    for i in parse_dotenv("/opt/mesosphere/etc/marathon-extras"):
        env[i[0]] = i[1]

    # Clean out any variables that may cause conflicts due to this
    # additional test-framework (marathon) instance.
    if 'LIBPROCESS_PORT' in env:
        del env['LIBPROCESS_PORT']

    # Clean out any variables we need to mutate for this test.
    if 'DCOS_SERVICE_ACCOUNT_CREDENTIAL' in env:
        del env['DCOS_SERVICE_ACCOUNT_CREDENTIAL']
    if 'MESOS_FRAMEWORK_AUTHN' in env:
        del env['MESOS_FRAMEWORK_AUTHN']

    # Mutate the environment depending on the test parameters.
    if authenticate:
        env['DCOS_SERVICE_ACCOUNT_CREDENTIAL'] = "file://" + credentials
        env['MESOS_FRAMEWORK_AUTHN'] = "true"

    cmd = []

    cmd.append("sudo")
    # Explicitly copy variables into `sudo` environment.
    for key, value in env.items():
        cmd.append(key + "=" + value)

    cmd.extend([
        "/opt/mesosphere/bin/java", "-Xmx2G", "-jar", "/opt/mesosphere/active/marathon/usr/marathon.jar",
        "--zk", "zk://localhost:2181/" + test_zknode,
        "--master", "leader.mesos:5050",
        "--framework_name", test_framework_name,
        "--http_port", "8081"])

    if len(role):
        cmd.append("--mesos_role")
        cmd.append(role)

    if authenticate:
        cmd.append("--mesos_authentication")
        cmd.append("--mesos_authentication_principal")
        cmd.append(principal)

    return subprocess.Popen(cmd, env=env)


class FrameworkAborted(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


@retrying.retry(wait_fixed=1000,
                stop_max_attempt_number=30,
                retry_on_result=lambda ret: ret is False,
                retry_on_exception=lambda x: False)
def _wait_for_framework_to_connect(dcos_api_session, p):
    if p.poll():
        raise FrameworkAborted("Framework pid %d has aborted - exiting retries" % (p.pid))

    r = dcos_api_session.get("/mesos/master/state-summary")

    if r.status_code != 200:
        logging.info("Mesos master returned status code {} != 200 - continuing to wait...".format(r.status_code))
        return False

    data = r.json()

    if not data.get('frameworks'):
        logging.info("Mesos master has no frameworks - continuing to wait...")
        return False

    for framework in data['frameworks']:
        if (framework['name'] == test_framework_name) and framework['connected']:
            logging.info("Test framework connected")
            return True

    return False


@pytest.mark.parametrize("authenticate, hash_uid, hash_path, role, expect_connect", [
    # Assert that registration without authentication works only when
    # authentication is not enforced.
    (False, 'default', 'default', '', not bootstrap_config['framework_authentication_required']),
    # Assert that an authenticated registration for the role '*' succeeds
    # for a service account that has such permission setup if authentication
    # is enabled.
    (True, 'default', 'default', '', bootstrap_config['framework_authentication_enabled']),
    # Assert that an authenticated registration for the role 'foo'
    # succeeds for a service account that has such permission setup.
    (True, 'secondary', 'secondary', 'foo', bootstrap_config['framework_authentication_enabled']),
    # Assert that an authenticated registration for the role 'foo' succeeds
    # for a service account that has been setup with permissions for role
    # '*' if authentication is enabled but not required.
    (True, 'default', 'default', 'foo',
        (bootstrap_config['framework_authentication_enabled'] and
            not bootstrap_config['mesos_authz_enforced'])),
    # Assert that an authenticated registration for the role '*' succeeds
    # for a service account that has been setup with permissions for role
    # 'foo' if authentication is enabled but not required.
    (True, 'secondary', 'secondary', '',
        (bootstrap_config['framework_authentication_enabled'] and
            not bootstrap_config['mesos_authz_enforced'])),
    # Assert that a registration for the role 'foo' succeeds for a service
    # account that has been setup with permissions for role '*' if
    # authentication is not enforced.
    (False, 'default', 'default', 'foo', not bootstrap_config['framework_authentication_required']),
    # Assert that a registration for the role '*' succeeds for a service
    # account that has been setup with permissions for role 'foo' if
    # authentication is not enforced.
    (False, 'secondary', 'secondary', '', not bootstrap_config['framework_authentication_required']),
    # Assert that authentication with a non matching framework principal
    # always fails.
    (True, 'invalid', 'default', '', False),
    # Assert that authentication fails when the private key does not
    # match the public key.
    (True, 'invalid', 'invalid', '', False)
])
def test_framework_registration(
        superuser_api_session, service_accounts, zk_test_session,
        authenticate, hash_uid, hash_path, role, expect_connect):
    """Assert that V0 framework registration w/out authentication works
    in expected ways.

    Args:
        authenticate: use classic RPC authenticatee module
        hash_uid: service hash for the uid to use
        hash_path: service hash for the credentials path to use
        role: framework role when registering
        exp_connect: expect registered framework connection
    """

    logging.info('Starting framework...')
    p = _run_framework(
        authenticate=authenticate,
        principal=service_accounts[hash_uid]['uid'],
        credentials=service_accounts[hash_path]['path'],
        role=role)

    connected = False

    try:
        _wait_for_framework_to_connect(superuser_api_session, p)
        connected = True

    except retrying.RetryError as e:
        logging.warning('Framework did not register in time')

    except FrameworkAborted as e:
        logging.warning('Framework has aborted: {}'.format(e.value))

    if not p.poll():
        logging.warning('Terminating framework...')
        subprocess.Popen(["sudo", "kill", str(p.pid)])

    p.wait()
    logging.info('Framework is gone now')

    assert connected == expect_connect
