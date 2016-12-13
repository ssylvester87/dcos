import pytest

from dcostests import dcos


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
        response = cluster.metrics.get('/containers', node=node)
        json_response = response.json()

        assert response.status_code == 200, 'Status code: {}, Content: {}'.format(
            response.status_code,
            response.content)

        assert 'dimensions' in json_response, '"dimensions" key not found in content, got {}'.format(
            response.content)

        assert 'framework_principal' in json_response['dimensions'], '"framework_principal" not present in {}'.format(
            response.content)

        assert len(json_response['dimensions']['framework_principal']) != 0, '"framework_principal" length is 0'

    for agent in cluster.slaves:
        framework_principal_present(agent)
