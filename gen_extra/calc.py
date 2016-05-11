import gen.calc


def validate_customer_key(customer_key):
    assert isinstance(customer_key, str), "Must be a string."

__stats_isolator_slave_module_name = 'com_mesosphere_StatsIsolatorModule'
__stats_hook_slave_module_name = 'com_mesosphere_StatsEnvHook'
__stats_slave_module = {
    'file': '/opt/mesosphere/lib/libstats-slave.so',
    'modules': [{
        'name': __stats_isolator_slave_module_name,
    }, {
        'name': __stats_hook_slave_module_name,
        'parameters': [
            {'key': 'dest_host', 'value': 'metrics.marathon.mesos'},
            {'key': 'dest_port', 'value': '8125'},
            {'key': 'dest_refresh_seconds', 'value': '60'},
            {'key': 'listen_host', 'value': '127.0.0.1'},
            {'key': 'listen_port_mode', 'value': 'ephemeral'},
            {'key': 'annotation_mode', 'value': 'key_prefix'},
            {'key': 'chunking', 'value': 'true'},
            {'key': 'chunk_size_bytes', 'value': '512'},
        ]
    }]
}


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
        'mesos_hooks': __stats_hook_slave_module_name,
        'mesos_isolation_modules': ','.join(gen.calc.default_isolation_modules + [__stats_isolator_slave_module_name]),
        'mesos_slave_modules_json': gen.calc.calculate_mesos_slave_modules_json(
            gen.calc.default_mesos_slave_modules + [__stats_slave_module])
    }
}

provider_template_defaults = {
    'superuser_username': '',
    'superuser_password_hash': '',
    'customer_key': 'Cloud Template Missing Parameter'
}
