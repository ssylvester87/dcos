import uuid

import ee_helpers
import pytest


@pytest.mark.xfail(
    ee_helpers.dcos_config['security'] in ['disabled', 'permissive'],
    reason='framework_principal" should only be present in strict mode',
    strict=True
)
def test_framework_principal_present(cluster):
    """ Test that the framework_principal is present as a dimension in EE
    clusters.
    """
    def framework_principal_present(node, superuser):
        """Ensure that framework_principal is present in the container's
        dimensions struct, and that it has a non-empty value.
        """
        containers = cluster.metrics.get(
            'containers',
            node=node.host,
            headers=superuser.auth_header)

        assert containers.status_code == 200, 'Excepted 200 response, got '
        '{}'.format(containers.status_code)

        assert len(containers.json()) > 0, 'Expected at least 1 container'
        'present from /containers endpoint, got {}'.format(containers.json())

        for container in containers.json():
            resp = cluster.metrics.get(
                '/'.join(['containers', container]),
                node=node.host,
                headers=superuser.auth_header)

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
    with cluster.marathon.deploy_and_cleanup(app, check_health=False) as endpoints:
        for node in endpoints:
            framework_principal_present(node, cluster.web_auth_default_user)
