import pytest

from dcostests import dcos

from test_util.marathon import get_test_app


@pytest.mark.xfail(
    dcos.config['security'] in ['disabled', 'permissive'],
    reason='framework_principal" should only be present in strict mode',
    strict=True
)
def test_framework_principal_present(cluster):
    """ Test that teh framework_principal is present as a dimension
    in EE clusters.
    """
    def framework_principal_present(node):
        response = cluster.metrics.get('containers', node=node.host)

        assert response.status_code == 200, 'Excepted 200 response, got {}'.format(response.status_code)
        json_response = response.json()

        assert len(json_response) > 0, 'Expected at least 1 container present from /containers'
        ', got {}'.format(json_response)

        for c in json_response:
            container_response = cluster.metrics.get('containers/{}'.format(c), node=node.host)

            assert container_response.status_code == 200, 'Expected 200 status code, got {}, '
            'content is {}'.format(response.status_code, response.content)

            assert 'dimensions' in container_response.json(), 'Expected dimensions key in response'
            ' got {}'.format(response.content)

            assert 'framework_principal' in json_response['dimensions'], ''
            '"framework_principal" not present in {}'.format(response.content)

            assert len(json_response['dimensions']['framework_principal']) != 0, ''
            '"framework_principal" length is 0'

    test_app1, _ = get_test_app()
    with cluster.marathon.deploy_and_cleanup(test_app1) as app_endpoints:
        for node in app_endpoints:
            framework_principal_present(node)
