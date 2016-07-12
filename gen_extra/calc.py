import gen.calc


def validate_customer_key(customer_key):
    assert isinstance(customer_key, str), "Must be a string."

__default_isolation_modules = [
    'cgroups/cpu',
    'cgroups/mem',
    'posix/disk'
]

__metrics_isolator_slave_module_name = 'com_mesosphere_MetricsIsolatorModule'
__metrics_resource_estimator_slave_module_name = 'com_mesosphere_MetricsResourceEstimatorModule'

def get_ui_auth_json(ui_organization, ui_networking):
    # Hacky. Use '%' rather than .format() to avoid dealing with escaping '{'
    return '"authentication":{"enabled":true},"oauth":{"enabled":false}, ' \
        '"organization":{"enabled":%s}, ' \
        '"networking":{"enabled":%s},' % (ui_organization, ui_networking)


entry = {
    'validate': [
        validate_customer_key
    ],
    'must': {
        'oauth_enabled': 'false',
        'oauth_available': 'false',
        'adminrouter_auth_enabled': 'true',
        'ui_networking': 'true',
        'ui_organization': 'true',
        'ui_external_links': 'true',
        'ui_branding': 'true',
        'minuteman_forward_metrics': 'true',
        'custom_auth': 'true',
        'custom_auth_json': get_ui_auth_json,
        'mesos_isolation_modules': ','.join(__default_isolation_modules + [
            __metrics_isolator_slave_module_name]),
        'mesos_resource_estimator_module': __metrics_resource_estimator_slave_module_name
    }
}

provider_template_defaults = {
    'superuser_username': '',
    'superuser_password_hash': '',
    'customer_key': 'Cloud Template Missing Parameter'
}
