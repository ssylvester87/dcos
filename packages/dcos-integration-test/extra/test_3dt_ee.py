import uuid

import pytest

from ee_helpers import bootstrap_config


def create_and_grant_user_permission(superuser_api_session, uid, action, rid, description):
    superuser_api_session.iam.create_user_permission(uid, action, rid, description)
    superuser_api_session.iam.grant_user_permission(uid, action, rid)


@pytest.mark.usefixtures("iam_verify_and_reset")
def test_ee_3dt_runner_poststart(superuser_api_session):
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

    cmd = [
        "/opt/mesosphere/bin/3dt",
        "check",
        "node-poststart",
        "&&",
        "sleep",
        "3600"
    ]
    test_uuid = uuid.uuid4().hex
    poststart_job = {
        'id': 'test-dcos-3dt-runner-poststart-ee-' + test_uuid,
        'user': 'dcos_3dt',
        'instances': 1,
        'cpus': .1,
        'mem': 128,
        'disk': 0,
        'cmd': ' '.join(cmd)
    }

    with superuser_api_session.marathon.deploy_and_cleanup(poststart_job, check_health=False):
        pass
