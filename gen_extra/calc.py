def validate_customer_key(customer_key):
    assert isinstance(customer_key, str), "'customer_key' must be a string."
    assert len(customer_key) == 36 or len(customer_key) == 32, (
        "'customer_key' must be 36 characters long with hyphens and 32 characters without.")


def validate_security(security):
    assert security in ['strict', 'permissive', 'disabled'], "Must be either 'strict', 'permissive' or 'disabled'"


def calculate_ssl_support_downgrade(security):
    if security == 'strict':
        return 'false'

    elif security == 'permissive':
        return 'true'

    elif security == 'disabled':
        return 'true'


def calculate_adminrouter_enforce_https(security):
    if security == 'strict':
        return 'true'

    elif security == 'permissive':
        return 'true'

    elif security == 'disabled':
        return 'false'


def validate_bootstrap_secrets(bootstrap_secrets):
    # Should correspond with bootstrap_secrets in gen/azure/calc.py
    if bootstrap_secrets in ["[[[variables('bootstrapSecrets')]]]", '{ "Ref" : "BootstrapSecrets" }']:
        return
    can_be = ['true', 'false']
    assert bootstrap_secrets in can_be, 'Must be one of {}. Got {}'.format(can_be, bootstrap_secrets)


def validate_httpauth_enabled(httpauth_enabled):
    if httpauth_enabled in ["[[[variables('httpauthEnabled')]]]", '{ "Ref" : "HTTPAuthEnabled" }']:
        return
    can_be = ['true', 'false']
    assert httpauth_enabled in can_be, 'Must be one of {}. Got {}'.format(can_be, httpauth_enabled)


def calculate_httpauth_available(httpauth_enabled):
    return httpauth_enabled


def calculate_httpauth_enabled(security):
    if security == 'strict':
        return 'true'

    elif security == 'permissive':
        return 'true'

    elif security == 'disabled':
        return 'false'


def validate_mesos_authz_enforced(mesos_authz_enforced):
    if mesos_authz_enforced in ["[[[variables('mesosAuthzEnforced')]]]", '{ "Ref" : "MesosAuthzEnforced" }']:
        return
    can_be = ['true', 'false']
    assert mesos_authz_enforced in can_be, 'Must be one of {}. Got {}'.format(can_be, mesos_authz_enforced)


def calculate_mesos_authz_enforced(security):
    if security == 'strict':
        return 'true'

    elif security == 'permissive':
        return 'true'

    elif security == 'disabled':
        return 'false'


def calculate_mesos_authorizer(mesos_authz_enforced):
    if mesos_authz_enforced == 'true':
        return __authz_module_name

    else:
        return 'local'


def calculate_mesos_authenticate_frameworks(security):
    if security == 'strict':
        return 'true'

    elif security == 'permissive':
        return 'false'

    elif security == 'disabled':
        return 'false'


def calculate_marathon_extra_args(security):
    if security == 'strict':
        return '--disable_http'

    elif security == 'permissive':
        return ''

    elif security == 'disabled':
        return ''


__http_authn_module_name = 'com_mesosphere_dcos_http_Authenticator'
__authz_module_name = 'com_mesosphere_dcos_Authorizer'
__secrets_isolator_name = 'com_mesosphere_dcos_SecretsIsolator'
__secrets_hook_name = 'com_mesosphere_dcos_SecretsHook'
__framework_authenticator_module_name = 'com_mesosphere_dcos_ClassicRPCAuthenticator'
__framework_authenticatee_module_name = 'com_mesosphere_dcos_ClassicRPCAuthenticatee'


__default_isolation_modules = [
    'cgroups/cpu',
    'cgroups/mem',
    'disk/du',
    'filesystem/linux',
    'docker/volume',
    'network/cni',
    'docker/runtime'
]

__metrics_isolator_slave_module_name = 'com_mesosphere_MetricsIsolatorModule'

__enterprise_only_isolation_modules = [__metrics_isolator_slave_module_name, __secrets_isolator_name]
__enterprise_isolation_modules = __default_isolation_modules + __enterprise_only_isolation_modules
__enterprise_hook_modules = [__secrets_hook_name]


def get_ui_auth_json(ui_organization, ui_networking):
    # Hacky. Use '%' rather than .format() to avoid dealing with escaping '{'
    return '"authentication":{"enabled":true},"oauth":{"enabled":false}, ' \
        '"organization":{"enabled":%s}, ' \
        '"networking":{"enabled":%s},' % (ui_organization, ui_networking)


entry = {
    'validate': [
        validate_customer_key,
        validate_security,
        validate_bootstrap_secrets,
        validate_httpauth_enabled,
        validate_mesos_authz_enforced
    ],
    'default': {
        'security': 'permissive',
        'bootstrap_secrets': 'true',
        'httpauth_enabled': calculate_httpauth_enabled,  # 'false',
        'httpauth_available': calculate_httpauth_available,
        'mesos_authz_enforced': calculate_mesos_authz_enforced,  # 'false',
        'ssl_support_downgrade': calculate_ssl_support_downgrade,
        'marathon_extra_args': calculate_marathon_extra_args,
        'adminrouter_enforce_https': calculate_adminrouter_enforce_https,  # 'true',
        'superuser_username': '',
        'superuser_password_hash': '',
        'customer_key': '',
        'ui_tracking': 'true',
        'ui_banner': 'false',
        'ui_banner_background_color': '#1E232F',
        'ui_banner_foreground_color': '#FFFFFF',
        'ui_banner_header_title': 'null',
        'ui_banner_header_content': 'null',
        'ui_banner_footer_content': 'null',
        'ui_banner_image_path': 'null',
        'ui_banner_dismissible': 'null'
    },
    'must': {
        'oauth_enabled': 'false',
        'oauth_available': 'false',
        'adminrouter_auth_enabled': 'true',
        'ui_auth_providers': 'true',
        'ui_secrets': 'true',
        'ui_networking': 'true',
        'ui_organization': 'true',
        'ui_external_links': 'true',
        'ui_branding': 'true',
        'minuteman_forward_metrics': 'true',
        'custom_auth': 'true',
        'custom_auth_json': get_ui_auth_json,
        'mesos_isolation_modules': ','.join(__default_isolation_modules + [
            __metrics_isolator_slave_module_name])
        'mesos_http_authenticators': __http_authn_module_name,
        'mesos_authenticate_http': calculate_httpauth_available,
        'mesos_fwk_authenticators': __framework_authenticator_module_name,
        'mesos_authenticate_frameworks': calculate_mesos_authenticate_frameworks,
        'mesos_master_authorizers': calculate_mesos_authorizer,
        'mesos_agent_authorizer': calculate_mesos_authorizer,
        'mesos_hooks': ','.join(__enterprise_hook_modules),
        'mesos_isolation_modules': ','.join(__enterprise_isolation_modules),
        'mesos_resource_estimator_module': __metrics_resource_estimator_slave_module_name,
        'ssl_support_downgrade': calculate_ssl_support_downgrade,
        'marathon_extra_args': calculate_marathon_extra_args
    }
}

provider_template_defaults = {
    'superuser_username': '',
    'superuser_password_hash': '',
    'customer_key': 'Cloud Template Missing Parameter'
}
