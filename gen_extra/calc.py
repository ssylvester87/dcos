import hashlib
from base64 import b64encode


def validate_customer_key(customer_key):
    assert isinstance(customer_key, str), "'customer_key' must be a string."
    if customer_key == "Cloud Template Missing Parameter" or customer_key == "CUSTOMER KEY NOT SET":
        return
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


def calculate_adminrouter_master_enforce_https(security):
    return {
        'strict': 'all',
        'permissive': 'only_root_path',
        'disabled': 'none'
        }[security]


def calculate_adminrouter_agent_enforce_https(security):
    return {
        'strict': 'all',
        'permissive': 'none',
        'disabled': 'none'
        }[security]


def calculate_adminrouter_master_default_scheme(security):
    return {
        'strict': 'https://',
        'permissive': 'http://',
        'disabled': 'http://'
        }[security]


def calculate_firewall_enabled(security):
    if security == 'strict':
        return 'true'

    elif security == 'permissive':
        return 'false'

    elif security == 'disabled':
        return 'false'


def calculate_mesos_authenticate_http(security):
    if security == 'strict':
        return 'true'

    elif security == 'permissive':
        return 'true'

    elif security == 'disabled':
        return 'false'


# TODO(adam): DCOS-9027: Enable authz in permissive mode with default permissive ACLs.
def calculate_mesos_authz_enforced(security):
    if security == 'strict':
        return 'true'

    elif security == 'permissive':
        return 'false'

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


def calculate_default_task_user(security):
    if security == 'strict':
        return 'nobody'

    elif security == 'permissive':
        return 'root'

    elif security == 'disabled':
        return 'root'


def calculate_marathon_extra_args(security):
    if security == 'strict':
        return '--disable_http'

    elif security == 'permissive':
        return ''

    elif security == 'disabled':
        return ''


def calculate_zk_acls_enabled(security):
    if security == 'strict':
        return 'true'

    elif security == 'permissive':
        return 'true'

    elif security == 'disabled':
        return 'false'


def empty(s):
    return s == ''


def validate_zk_credentials(credentials, human_name):
    if credentials == '':
        return
    assert len(credentials.split(':', 1)) == 2, (
        "{human_name} must of the form username: password".format(human_name=human_name))


def validate_zk_super_credentials(zk_super_credentials):
    validate_zk_credentials(zk_super_credentials, "Super ZK")


def validate_zk_master_credentials(zk_master_credentials):
    validate_zk_credentials(zk_master_credentials, "Master ZK")


def validate_zk_agent_credentials(zk_agent_credentials):
    validate_zk_credentials(zk_agent_credentials, "Agent ZK")


def calculate_digest(credentials):
    if empty(credentials):
        return ''
    username, password = credentials.split(':', 1)
    credential = username.encode('utf-8') + b":" + password.encode('utf-8')
    cred_hash = b64encode(hashlib.sha1(credential).digest()).strip()
    return username + ":" + cred_hash.decode('utf-8')


def calculate_zk_agent_digest(zk_agent_credentials):
    return calculate_digest(zk_agent_credentials)


def calculate_zk_super_digest(zk_super_credentials):
    return calculate_digest(zk_super_credentials)


def calculate_zk_super_digest_jvmflags(zk_super_credentials):
    if empty(zk_super_credentials):
        return ''
    digest = calculate_zk_super_digest(zk_super_credentials)
    return "JVMFLAGS=-Dzookeeper.DigestAuthenticationProvider.superDigest=" + digest


# TODO(adam): Inherit this from dcos/dcos once we pull in the necessary upstream.
__default_isolation_modules = [
    'cgroups/cpu',
    'cgroups/mem',
    'disk/du',
    'filesystem/linux',
    'docker/volume',
    'network/cni',
    'docker/runtime'
]


def get_ui_auth_json(ui_organization, ui_networking, ui_secrets, ui_auth_providers):
    # Hacky. Use '%' rather than .format() to avoid dealing with escaping '{'
    return '"authentication":{"enabled":true},"oauth":{"enabled":false}, ' \
        '"organization":{"enabled":%s}, ' \
        '"networking":{"enabled":%s},' \
        '"secrets":{"enabled":%s},' \
        '"auth-providers":{"enabled":%s},' \
        % (ui_organization, ui_networking, ui_secrets, ui_auth_providers)


entry = {
    'validate': [
        validate_customer_key,
        validate_zk_super_credentials,
        validate_zk_master_credentials,
        validate_zk_agent_credentials,
        validate_security
    ],
    'default': {
        'security': 'permissive',
        'superuser_username': '',
        'superuser_password_hash': '',
        'zk_super_credentials': 'super:secret',
        'zk_master_credentials': 'dcos-master:secret1',
        'zk_agent_credentials': 'dcos-agent:secret2',
        'customer_key': 'CUSTOMER KEY NOT SET',
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
        'zk_super_digest_jvmflags': calculate_zk_super_digest_jvmflags,
        'zk_agent_digest': calculate_zk_agent_digest,
        'adminrouter_auth_enabled': 'true',
        'adminrouter_master_enforce_https': calculate_adminrouter_master_enforce_https,
        'adminrouter_agent_enforce_https': calculate_adminrouter_agent_enforce_https,
        'adminrouter_master_default_scheme': calculate_adminrouter_master_default_scheme,
        'bootstrap_secrets': 'true',
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
        'mesos_authenticate_http': calculate_mesos_authenticate_http,
        'mesos_classic_authenticator': 'com_mesosphere_dcos_ClassicRPCAuthenticator',
        'mesos_authenticate_frameworks': calculate_mesos_authenticate_frameworks,
        'mesos_authenticate_agents': calculate_mesos_authenticate_agents,
        'agent_authn_enabled': calculate_agent_authn_enabled,
        'mesos_authz_enforced': calculate_mesos_authz_enforced,
        'mesos_master_authorizers': calculate_mesos_authorizer,
        'mesos_agent_authorizer': calculate_mesos_authorizer,
        'mesos_hooks': 'com_mesosphere_dcos_SecretsHook',
        'mesos_isolation': ','.join(
            __default_isolation_modules + [
                'com_mesosphere_MetricsIsolatorModule',
                'com_mesosphere_dcos_SecretsIsolator'
            ]),
        'firewall_enabled': calculate_firewall_enabled,
        'ssl_enabled': calculate_ssl_enabled,
        'ssl_support_downgrade': calculate_ssl_support_downgrade,
        'default_task_user': calculate_default_task_user,
        'marathon_extra_args': calculate_marathon_extra_args,
        'zk_acls_enabled': calculate_zk_acls_enabled,
    }
}

provider_template_defaults = {
    'superuser_username': '',
    'superuser_password_hash': '',
    'customer_key': 'Cloud Template Missing Parameter'
}
