import uuid

import pytest

from ee_helpers import bootstrap_config


def create_and_grant_user_permission(superuser_api_session, uid, action, rid, description):
    superuser_api_session.iam.create_user_permission(uid, action, rid, description)
    superuser_api_session.iam.grant_user_permission(uid, action, rid)


@pytest.mark.usefixtures("iam_verify_and_reset")
def test_dcos_checks_ee(superuser_api_session):
    if bootstrap_config['security'] == 'strict':
        create_and_grant_user_permission(
            superuser_api_session,
            'dcos_marathon',
            'create',
            'dcos:mesos:master:task:user:dcos_3dt',
            'Grants marathon access to start task as dcos_3dt user'
        )

        create_and_grant_user_permission(
            superuser_api_session,
            'dcos_marathon',
            'create',
            'dcos:mesos:agent:task:user:dcos_3dt',
            'Grants marathon access to start task as dcos_3dt user'
        )

    # target contains a dcos-checks subcommand as a key and tuple of optional parameters as a value.
    target = {
        "components": ()
    }

    cmd_tpl = "/opt/mesosphere/bin/dcos-checks --config /opt/mesosphere/etc/dcos-checks-config-ee.yaml {} {}"
    cmds = [cmd_tpl.format(subcommand, " ".join(arg for arg in args)) for subcommand, args in target.items()]
    test_uuid = uuid.uuid4().hex
    cmd = " && ".join(cmds)
    check_job = {
        'id': 'test-dcos-checks-' + test_uuid,
        'user': 'dcos_3dt',
        'instances': 1,
        'cpus': .1,
        'mem': 128,
        'disk': 0,
        'cmd': cmd + ' && sleep 3600'}

    with superuser_api_session.marathon.deploy_and_cleanup(check_job, check_health=False):
        pass
