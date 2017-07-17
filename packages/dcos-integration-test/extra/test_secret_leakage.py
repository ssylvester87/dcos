import logging

import pytest

from dcos_test_utils.marathon import Container, get_test_app


def _create_secret(superuser_api_session, path, value):
    logging.info('Creating secret path {} value {}'.format(path, value))
    r = superuser_api_session.secrets.put('/secret{}'.format(path), json={'value': value})
    assert r.status_code == 201


def _delete_secret(superuser_api_session, path):
    logging.info('Removing secret path {}'.format(path))
    r = superuser_api_session.secrets.delete('/secret{}'.format(path))
    assert r.status_code == 204


def _has_secret(superuser_api_session, path):
    r = superuser_api_session.secrets.get('/secret{}'.format(path))
    return r.status_code == 200


@pytest.fixture(scope="module")
def secret(superuser_api_session):
    path = '/default'
    name = '/test'
    value = 'Foo My BaR!'

    _create_secret(superuser_api_session, path + name, value)
    assert _has_secret(superuser_api_session, path + name)

    yield {'name': name, 'value': value}

    _delete_secret(superuser_api_session, path + name)
    assert not _has_secret(superuser_api_session, path + name)


@pytest.mark.parametrize('containerizer,image', [
    (Container.MESOS, None),            # Mesos containerizer.
    (Container.MESOS, "alpine"),        # Mesos containerizer (UCR).
    (Container.DOCKER, "alpine")        # Docker containerizer.
])
def test_application_secret_leakage(superuser_api_session, secret, containerizer, image):
    """Marathon app deployment integration test validating if tasks using
    a secret reference their value in clear text in the sandbox log files
    (stdout & stderr).
    """
    app, test_uuid = get_test_app(container_type=containerizer)

    if image is not None:
        app['container']['docker'] = {
            'image': image
        }

    app['secrets'] = {
        'secret0': {
            'source': secret['name']
        }
    }

    app['env'] = {
        'TEST_SECRET_VARIABLE': {
            'secret': 'secret0'
        }
    }

    app['cmd'] = 'pwd && sleep 1000'

    with superuser_api_session.marathon.deploy_and_cleanup(app, check_health=False):
        marathon_framework_id = superuser_api_session.marathon.get('/v2/info').json()['frameworkId']
        app_task = superuser_api_session.marathon.get('/v2/apps/{}/tasks'.format(app['id'])).json()['tasks'][0]

        for required_sandbox_file in ('stdout', 'stderr'):
            content = superuser_api_session.mesos_sandbox_file(
                app_task['slaveId'], marathon_framework_id, app_task['id'], required_sandbox_file)

            assert content, 'File {} should not be empty'.format(required_sandbox_file)

            logging.info('File {} contains:\n{}\n'.format(required_sandbox_file, content))

            assert secret['value'] not in content, 'File {} should not contain any references of \'{}\''.format(
                required_sandbox_file, secret['value'])
