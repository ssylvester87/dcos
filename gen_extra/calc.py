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
__metrics_slave_module = {
    'file': '/opt/mesosphere/lib/libmetrics-module.so',
    'modules': [{
        'name': __metrics_isolator_slave_module_name,
    }, {
        'name': __metrics_resource_estimator_slave_module_name,
        'parameters': [
            {'key': 'container_limit_amount_kbytes', 'value': '10240'},
            {'key': 'container_limit_period_secs', 'value': '60'},
            {'key': 'listen_interface', 'value': 'spartan'},
            {'key': 'listen_port_mode', 'value': 'ephemeral'},
            {'key': 'output_collector_enabled', 'value': 'true'},
            {'key': 'output_collector_ip', 'value': '127.0.0.1'},
            {'key': 'output_collector_port', 'value': '8124'},
            {'key': 'output_collector_chunking', 'value': 'true'},
            {'key': 'output_collector_chunk_size_datapoints', 'value': '100'},
            {'key': 'output_collector_chunk_timeout_seconds', 'value': '10'},
            {'key': 'output_statsd_enabled', 'value': 'true'},
            {'key': 'output_statsd_host', 'value': 'metrics.marathon.mesos'},
            {'key': 'output_statsd_host_refresh_seconds', 'value': '60'},
            {'key': 'output_statsd_port', 'value': '8125'},
            {'key': 'output_statsd_annotation_mode', 'value': 'key_prefix'},
            {'key': 'output_statsd_chunking', 'value': 'true'},
            {'key': 'output_statsd_chunk_size_bytes', 'value': '512'},
            {'key': 'state_path_dir',
             'value': '/var/run/mesos/isolators/com_mesosphere_MetricsIsolatorModule/'},
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
        'mesos_isolation_modules': ','.join(__default_isolation_modules + [
            __metrics_isolator_slave_module_name]),
        'mesos_resource_estimator_module': __metrics_resource_estimator_slave_module_name,
        'mesos_slave_modules_json': gen.calc.calculate_mesos_slave_modules_json(
            gen.calc.default_mesos_slave_modules + [__metrics_slave_module])
    }
}

provider_template_defaults = {
    'superuser_username': '',
    'superuser_password_hash': '',
    'customer_key': 'Cloud Template Missing Parameter'
}
