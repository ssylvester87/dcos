import time
import uuid

import ee_helpers
import pytest


def test_framework_principal_present(superuser_api_session):
    """ Test that the framework_principal is present as a dimension in EE
    superuser_api_sessions.
    """
    def framework_principal_present(node):
        """Ensure that framework_principal is present in the container's
        dimensions struct, and that it has a non-empty value.
        """
        containers = superuser_api_session.metrics.get('containers', node=node.host)

        assert containers.status_code == 200, 'Excepted 200 response, got '
        '{}'.format(containers.status_code)

        assert len(containers.json()) > 0, 'Expected at least 1 container'
        'present from /containers endpoint, got {}'.format(containers.json())

        for container in containers.json():
            resp = superuser_api_session.metrics.get('/'.join(['containers', container]), node=node.host)

            assert resp.status_code == 200, 'Expected 200 status code, got '
            '{}, content is {}'.format(resp.status_code, resp.content)

            assert 'dimensions' in resp.json(), 'Expected dimensions key in '
            'response, got {}'.format(resp.content)

            assert 'framework_principal' in resp.json()['dimensions'], '"framework_principal" '
            'not present in {}'.format(resp.content)

            assert resp.json()['dimensions']['framework_principal'] != "", 'Expected '
            'framework_principal to not be empty (but it was!)'

        return True

    app = ee_helpers.sleep_app_definition("dcos-metrics-%s" % str(uuid.uuid4()))
    with superuser_api_session.marathon.deploy_and_cleanup(app, check_health=False) as endpoints:
        time.sleep(60)  # dcos-metrics has a poll interval of 60 seconds so we have to wait until cache is filled
        for node in endpoints:
            framework_principal_present(node)
