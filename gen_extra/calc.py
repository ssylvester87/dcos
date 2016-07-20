import hashlib
from base64 import b64encode


def validate_customer_key(customer_key):
    assert isinstance(customer_key, str), "'customer_key' must be a string."
    assert len(customer_key) == 36, "'customer_key' must be 36 characters long with hyphens"


def validate_security(security):
    assert security in ['strict', 'permissive', 'disabled'], "Must be either 'strict', 'permissive' or 'disabled'"


def calculate_ssl_enabled(security):
    if security == 'strict':
        return 'true'

    elif security == 'permissive':
        return 'true'

    elif security == 'disabled':
        return 'false'


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


def validate_firewall_enabled(firewall_enabled):
    if firewall_enabled in ["[[[variables('firewallEnabled')]]]", '{ "Ref" : "FirewallEnabled" }']:
        return
    can_be = ['true', 'false']
    assert firewall_enabled in can_be, 'Must be one of {}. Got {}'.format(can_be, firewall_enabled)


def calculate_firewall_enabled(security):
    if security == 'strict':
        return 'true'

    elif security == 'permissive':
        return 'false'

    elif security == 'disabled':
        return 'false'


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
        return 'com_mesosphere_dcos_Authorizer'

    else:
        return 'local'


def calculate_mesos_authenticate_frameworks(security):
    if security == 'strict':
        return 'true'

    elif security == 'permissive':
        return 'false'

    elif security == 'disabled':
        return 'false'


def calculate_mesos_authenticate_agents(security):
    if security == 'strict':
        return 'true'

    elif security == 'permissive':
        return 'false'

    elif security == 'disabled':
        return 'false'


def calculate_agent_authn_enabled(security):
    if security == 'strict':
        return 'true'

    elif security == 'permissive':
        return 'true'

    elif security == 'disabled':
        return 'false'


def calculate_marathon_extra_args(security):
    if security == 'strict':
        return '--disable_http'

    elif security == 'permissive':
        return ''

    elif security == 'disabled':
        return ''


def empty(s):
    return not s or s == ''


def validate_zk_super_creds(zk_super_creds):
    if empty(zk_super_creds):
        return
    assert len(zk_super_creds.split(':', 1)) == 2, "Super ZK credentials must be of the form username:password"


def validate_zk_master_creds(zk_master_creds):
    if empty(zk_master_creds):
        return
    assert len(zk_master_creds.split(':', 1)) == 2, "Master ZK credentials must be of the form username:password"


def validate_zk_agent_creds(zk_agent_creds):
    if empty(zk_agent_creds):
        return
    assert len(zk_agent_creds.split(':', 1)) == 2, "Agent ZK credentials must be of the form username:password"


def calculate_digest(creds):
    if empty(creds):
        return ''
    username, password = creds.split(':', 1)
    credential = username.encode('utf-8') + b":" + password.encode('utf-8')
    cred_hash = b64encode(hashlib.sha1(credential).digest()).strip()
    return username + ":" + cred_hash.decode('utf-8')


def calculate_zk_super_digest(zk_super_creds):
    return calculate_digest(zk_super_creds)


def calculate_zk_master_digest(zk_master_creds):
    return calculate_digest(zk_master_creds)


def validate_os_type(os_type):
    can_be = ['coreos', 'el7']
    assert os_type in can_be, 'Must be one of {}. Got {}'.format(can_be, os_type)


def calculate_zk_agent_digest(zk_agent_creds):
    return calculate_digest(zk_agent_creds)


def calculate_zk_super_digest_jvmflags(zk_super_creds):
    if empty(zk_super_creds):
        return ''
    digest = calculate_zk_super_digest(zk_super_creds)
    return "JVMFLAGS=-Dzookeeper.DigestAuthenticationProvider.superDigest=" + digest


__default_isolation_modules = [
    'cgroups/cpu',
    'cgroups/mem',
    'disk/du',
    'filesystem/linux',
    'docker/volume',
    'network/cni',
    'docker/runtime'
]
__enterprise_isolation_modules = __default_isolation_modules + [
    'com_mesosphere_MetricsIsolatorModule',
    'com_mesosphere_dcos_SecretsIsolator'
]


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
        validate_firewall_enabled,
        validate_httpauth_enabled,
        validate_mesos_authz_enforced
    ],
    'default': {
        'security': 'permissive',
        'bootstrap_secrets': 'true',
        'firewall_enabled': calculate_firewall_enabled,
        'httpauth_enabled': calculate_httpauth_enabled,
        'httpauth_available': calculate_httpauth_available,
        'mesos_authz_enforced': calculate_mesos_authz_enforced,
        'ssl_support_downgrade': calculate_ssl_support_downgrade,
        'marathon_extra_args': calculate_marathon_extra_args,
        'adminrouter_enforce_https': calculate_adminrouter_enforce_https,
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
        'mesos_http_authenticators': 'com_mesosphere_dcos_http_Authenticator',
        'mesos_authenticate_http': calculate_httpauth_available,
        'mesos_fwk_authenticators': 'com_mesosphere_dcos_ClassicRPCAuthenticator',
        'mesos_authenticate_frameworks': calculate_mesos_authenticate_frameworks,
        'mesos_authenticate_agents': calculate_mesos_authenticate_agents,
        'agent_authn_enabled': calculate_agent_authn_enabled,
        'mesos_master_authorizers': calculate_mesos_authorizer,
        'mesos_agent_authorizer': calculate_mesos_authorizer,
        'mesos_hooks': 'com_mesosphere_dcos_SecretsHook',
        'mesos_isolation_modules': ','.join(__enterprise_isolation_modules),
        'ssl_enabled': calculate_ssl_enabled,
        'ssl_support_downgrade': calculate_ssl_support_downgrade,
        'marathon_extra_args': calculate_marathon_extra_args
    }
}

provider_template_defaults = {
    'superuser_username': '',
    'superuser_password_hash': '',
    'customer_key': 'Cloud Template Missing Parameter'
}
