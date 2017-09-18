# Copyright (C) Mesosphere, Inc. See LICENSE file for details.
import json
import logging
import os
import subprocess
import uuid

from tempfile import mkstemp

import pytest
import retrying

from ee_helpers import bootstrap_config, generate_RSA_keypair, parse_dotenv

log = logging.getLogger(__name__)


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


@pytest.fixture
def service_accounts(superuser_api_session, iam_verify_and_reset):
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
        log.info('Creating service account \'{}\'...'.format(param))

        services[param]['path'] = _create_temp_service(
            superuser_api_session, services[param]['uid'], services[param]['keypair'])

        if len(services[param]['rid']) and len(services[param]['action']):
            superuser_api_session.iam.create_acl(services[param]['rid'], 'Integration Test Framework Role')
            superuser_api_session.iam.grant_user_permission(
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


@pytest.fixture
def run_framework(service_accounts, request):
    """ Run classic RPC framework to register depending on the use of
        authentication. After the test, kill the framework process if
        it is still running.

    Args:
        authenticate: use classic RPC authenticatee module
        principal: framework principal
        credentials: service account credentials
        role: framework role when registering
    """
    test_framework_name = 'integration_test_' + uuid.uuid4().hex

    authenticate, hash_uid, hash_path, role = request.param
    principal = service_accounts[hash_uid]['uid']
    credentials = service_accounts[hash_path]['path']

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

    cmd = ['sudo']

    extra_args_str = env.pop("MARATHON_EXTRA_ARGS")
    if extra_args_str is None:
        extra_args = []
    else:
        extra_args = extra_args_str.split(" ")

    # Explicitly copy variables into `sudo` environment.
    for key, value in env.items():
        cmd.append(key + "=" + value)

    cmd.extend([
        "JAVA_HOME=/opt/mesosphere",
        "/opt/mesosphere/active/marathon/marathon/bin/marathon",
        "--zk", "zk://localhost:2181/" + test_framework_name,
        "--master", "leader.mesos:5050",
        "--framework_name", test_framework_name,
        "--http_port", "8081"])

    for arg in ["--disable_http", ""]:
        if arg in extra_args:
            extra_args.pop(extra_args.index(arg))

    cmd.extend(extra_args)

    if len(role):
        cmd.append("--mesos_role")
        cmd.append(role)

    if authenticate:
        cmd.append("--mesos_authentication")
        cmd.append("--mesos_authentication_principal")
        cmd.append(principal)

    log.info('Starting framework...')
    p = subprocess.Popen(cmd, env=env, preexec_fn=os.setpgrp)

    yield p, test_framework_name

    # Kill the process if it didn't already die.
    if not p.poll():
        log.warning('Terminating framework...')
        subprocess.check_call(['sudo', '-i', 'kill', str(p.pid)])

    p.wait()
    log.info('Framework is gone now')

    subprocess.check_call([
        "source /opt/mesosphere/environment.export; "
        "/opt/mesosphere/active/exhibitor/usr/zookeeper/bin/zkCli.sh -server 127.0.0.1:2181 "
        "rmr /" + test_framework_name
    ], shell=True)


class FrameworkAborted(Exception):
    pass


@retrying.retry(wait_fixed=1000,
                stop_max_attempt_number=30,
                retry_on_result=lambda ret: ret is False,
                retry_on_exception=lambda x: False)
def _wait_for_framework_to_connect(dcos_api_session, p, test_framework_name):
    if p.poll():
        raise FrameworkAborted("Framework pid %d has aborted - exiting retries" % (p.pid))

    r = dcos_api_session.get("/mesos/master/state-summary")

    if r.status_code != 200:
        log.info("Mesos master returned status code {} != 200 - continuing to wait...".format(r.status_code))
        return False

    data = r.json()

    if not data.get('frameworks'):
        log.info("Mesos master has no frameworks - continuing to wait...")
        return False

    for framework in data['frameworks']:
        if (framework['name'] == test_framework_name) and framework['connected']:
            log.info("Test framework connected")
            return True

    return False


@pytest.mark.parametrize('run_framework,expect_connect', [
    # Assert that registration without authentication works only when
    # authentication is not enforced.
    ((False, 'default', 'default', ''), not bootstrap_config['framework_authentication_required']),
    # Assert that an authenticated registration for the role '*' succeeds
    # for a service account that has such permission setup if authentication
    # is enabled.
    ((True, 'default', 'default', ''), bootstrap_config['framework_authentication_enabled']),
    # Assert that an authenticated registration for the role 'foo'
    # succeeds for a service account that has such permission setup.
    ((True, 'secondary', 'secondary', 'foo'), bootstrap_config['framework_authentication_enabled']),
    # Assert that an authenticated registration for the role 'foo' succeeds
    # for a service account that has been setup with permissions for role
    # '*' if authentication is enabled but not required.
    ((True, 'default', 'default', 'foo'),
        (bootstrap_config['framework_authentication_enabled'] and
            not bootstrap_config['mesos_authz_enforced'])),
    # Assert that an authenticated registration for the role '*' succeeds
    # for a service account that has been setup with permissions for role
    # 'foo' if authentication is enabled but not required.
    ((True, 'secondary', 'secondary', ''),
        (bootstrap_config['framework_authentication_enabled'] and
            not bootstrap_config['mesos_authz_enforced'])),
    # Assert that a registration for the role 'foo' succeeds for a service
    # account that has been setup with permissions for role '*' if
    # authentication is not enforced.
    ((False, 'default', 'default', 'foo'), not bootstrap_config['framework_authentication_required']),
    # Assert that a registration for the role '*' succeeds for a service
    # account that has been setup with permissions for role 'foo' if
    # authentication is not enforced.
    ((False, 'secondary', 'secondary', ''), not bootstrap_config['framework_authentication_required']),
    # Assert that authentication with a non matching framework principal
    # always fails.
    ((True, 'invalid', 'default', ''), False),
    # Assert that authentication fails when the private key does not
    # match the public key.
    ((True, 'invalid', 'invalid', ''), False)
], indirect=['run_framework'])
def test_framework_registration(superuser_api_session, run_framework, expect_connect):
    """ Assert that a V0 framework registration w/out authentication
        works in expected ways.
    """
    connected = False
    p, test_framework_name = run_framework

    try:
        _wait_for_framework_to_connect(superuser_api_session, p, test_framework_name)
        connected = True

    except retrying.RetryError as e:
        log.warning('Framework did not register in time')

    except FrameworkAborted as e:
        log.warning('Framework has aborted')

    assert connected == expect_connect
