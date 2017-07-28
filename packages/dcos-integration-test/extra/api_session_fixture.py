from dcos_test_utils import enterprise
from ee_helpers import bootstrap_config


def make_session_fixture():
    cluster_args = enterprise.EnterpriseApiSession.get_args_from_env()

    # make the customizations that require knowing about configs
    if bootstrap_config['ssl_enabled']:
        cluster_args['dcos_url'] = cluster_args['dcos_url'].replace('http', 'https')

    cluster_api = enterprise.EnterpriseApiSession(**cluster_args)

    # If SSL enabled and no CA cert is given, then grab it
    if bootstrap_config['ssl_enabled']:
        cluster_api.set_ca_cert()

    cluster_api.wait_for_dcos()
    cluster_api.set_initial_resource_ids()

    return cluster_api
