import hashlib
import json
import os.path
import sys
from base64 import b64encode
from collections import OrderedDict

from gen.calc import validate_true_false
from gen.internals import validate_one_of

# Precisely control import.
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))


def validate_customer_key(customer_key):
    assert isinstance(customer_key, str), "'customer_key' must be a string."
    if customer_key == "Cloud Template Missing Parameter" or customer_key == "CUSTOMER KEY NOT SET":
        return
    assert len(customer_key) == 36, "'customer_key' must be 36 characters long with hyphens"


def calculate_ssl_enabled(security):
    return {
        'strict': 'true',
        'permissive': 'true',
        'disabled': 'false'
        }[security]


def calculate_ssl_support_downgrade(security):
    return {
        'strict': 'false',
        'permissive': 'true',
        'disabled': 'true'
        }[security]


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
        'permissive': 'https://',
        'disabled': 'http://'
        }[security]


def calculate_firewall_enabled(security):
    return {
        'strict': 'true',
        'permissive': 'false',
        'disabled': 'false'
        }[security]


def calculate_mesos_authenticate_http(security):
    return {
        'strict': 'true',
        'permissive': 'true',
        'disabled': 'false'
        }[security]


def calculate_mesos_authz_enforced(security):
    return {
        'strict': 'true',
        'permissive': 'false',
        'disabled': 'false'
        }[security]


def calculate_mesos_elevate_unknown_users(security):
    return {
        'strict': 'false',
        'permissive': 'true',
        'disabled': 'false'
        }[security]


def calculate_mesos_authorizer(security):
    return {
        'strict': 'com_mesosphere_dcos_Authorizer',
        'permissive': 'com_mesosphere_dcos_Authorizer',
        'disabled': 'local'
        }[security]


def calculate_framework_authentication_required(security):
    return {
        'strict': 'true',
        'permissive': 'false',
        'disabled': 'false'
        }[security]


def calculate_agent_authentication_required(security):
    return {
        'strict': 'true',
        'permissive': 'false',
        'disabled': 'false'
        }[security]


def calculate_framework_authentication_enabled(security):
    return {
        'strict': 'true',
        'permissive': 'true',
        'disabled': 'false'
        }[security]


def calculate_agent_authn_enabled(security):
    return {
        'strict': 'true',
        'permissive': 'true',
        'disabled': 'false'
        }[security]


def calculate_executor_authentication_required(security):
    return {
        'strict': 'true',
        'permissive': 'false',
        'disabled': 'false'
        }[security]


def calculate_executor_secret_generation_enabled(security):
    return {
        'strict': 'true',
        'permissive': 'true',
        'disabled': 'false'
        }[security]


def calculate_mesos_classic_authenticator(framework_authentication_enabled, agent_authn_enabled):
    if framework_authentication_enabled == 'true' or agent_authn_enabled == 'true':
        return 'com_mesosphere_dcos_ClassicRPCAuthenticator'
    else:
        return 'crammd5'


def calculate_mesos_agent_http_authenticators(executor_authentication_required):
    if executor_authentication_required == 'true':
        return 'com_mesosphere_dcos_http_Authenticator,com_mesosphere_dcos_executor_Authenticator'
    else:
        return 'com_mesosphere_dcos_http_Authenticator'


def calculate_default_task_user(security):
    return {
        'strict': 'nobody',
        'permissive': 'root',
        'disabled': 'root'
        }[security]


def calculate_marathon_authn_mode(security):
    return {
        'strict': 'dcos/jwt',
        'permissive': 'dcos/jwt+anonymous',
        'disabled': 'disabled'
        }[security]


def calculate_marathon_https_enabled(security):
    return {
        'strict': 'true',
        'permissive': 'true',
        'disabled': 'false'
        }[security]


def calculate_marathon_extra_args(security):
    return {
        'strict': '--disable_http',
        'permissive': '',
        'disabled': ''
        }[security]


def calculate_zk_acls_enabled(security):
    return {
        'strict': 'true',
        'permissive': 'true',
        'disabled': 'false'
        }[security]


def load_file_utf8(path):
    """Read byte content from file located at `path`, decode using UTF-8, and
    return text.

    Return an empty string if no file exists at the given path. Assume that the
    file contents are decodable using UTF-8.
    """
    if not os.path.isfile(path):
        return ''

    with open(path, 'rb') as f:
        return f.read().decode('utf-8')


def calculate_ca_certificate(
        ca_certificate_path,
        ca_certificate_key_path,
        ca_certificate_chain_path
        ):
    """
    Translate the non-sensitive part of the user-given CA certificate data into
    a JSON document.

    Assume that the given file paths exist and that the data has previously been
    validated.

    Note: This function accepts `ca_certificate_key_path` parameter that isn't
    being processed anywhere. This is because how `gen` package processes
    dependencies and calculates which validation functions can be invoked.
    Removing the parameter from calculate function will cause that
    `validate_ca_certificate` wouldn't be invoked.

    Args:
        ca_certificate_path (str): Path pointing to a file containing a
            PEM encoded certificate.

        ca_certificate_key_path (str): Path pointing to a file containing a
            PEM encoded private key for the certificate.

        ca_certificate_chain_path (str): Path pointing to a file containing a
            PEM encoded chain of certificates.

    Raises:
        AssertionError: If provided custom CA certificate validation failed.
    """

    # Handle case where no custom CA certificate was provided.
    if not ca_certificate_path:
        return ''

    cert = load_file_utf8(ca_certificate_path)

    # Treat the CA certificate chain as optional.
    chain = ''
    if ca_certificate_chain_path:
        chain = load_file_utf8(ca_certificate_chain_path)

    # Build a single-line JSON representation from data (i.e. a string that does
    # not contain newline characters; for complication-free transmission of the
    # data through a YAML document.
    serialized_config = json.dumps(OrderedDict((
        ('ca_certificate', cert),
        ('ca_certificate_chain', chain)
        )))

    return serialized_config


def validate_ca_certificate(
        ca_certificate_path,
        ca_certificate_key_path,
        ca_certificate_chain_path
        ):
    config = {
        'ca_certificate_path': ca_certificate_path,
        'ca_certificate_key_path': ca_certificate_key_path,
        'ca_certificate_chain_path': ca_certificate_chain_path,
        }

    # Filter for non-empty config values.
    filepaths = {key: path for key, path in config.items() if path}

    # If none of the three file paths were given (if they are an empty string)
    # it means that there was no attempt to provide a custom CA certificate.
    if not filepaths:
        return

    # Cert and key are required when installing a custom CA certificate.
    for required_key in ('ca_certificate_path', 'ca_certificate_key_path'):
        if required_key not in filepaths:
            raise AssertionError(
                'Definition of `{}` is required when setting up a custom '
                'CA certificate'.format(required_key)
                )

    # All provided paths must point to files.
    for key, path in filepaths.items():
        if not os.path.isfile(path):
            raise AssertionError(
                'Config key `{}` does not point to a file: {}'.format(key, path)
                )

    cert = load_file_utf8(ca_certificate_path)
    key = load_file_utf8(ca_certificate_key_path)
    chain = load_file_utf8(ca_certificate_chain_path)
    if chain == '':
        chain = None

    # Import here becuase `cryptography` module loaded in `ca_validate` isn't
    # available in the build time
    from ca_validate import CustomCACertValidationError, CustomCACertValidator  # noqa=I100
    # Run data validation.
    try:
        CustomCACertValidator(cert, key, chain, allow_ec_key=False).validate()
    except CustomCACertValidationError as err:
        raise AssertionError(str(err))


def calculate_ca_certificate_enabled(ca_certificate):
    return "true" if not empty(ca_certificate) else "false"


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


def validate_bouncer_expiration_auth_token_days(bouncer_expiration_auth_token_days):
    try:
        float(bouncer_expiration_auth_token_days)
    except ValueError:
        raise AssertionError(
            "bouncer_expiration_auth_token_days must be a number of days or decimal thereof.")
    assert float(bouncer_expiration_auth_token_days) > 0, "bouncer_expiration_auth_token_days must be greater than 0."


def calculate_superuser_credentials_given(superuser_username, superuser_password_hash):
    pair = (superuser_username, superuser_password_hash)

    if all(pair):
        return 'true'

    if not any(pair):
        return 'false'

    # `calculate_` functions are not supposed to error out, but
    # in this case here (multi-arg input) this check cannot
    # currently be replaced by a `validate_` function.
    raise AssertionError(
        "'superuser_username' and 'superuser_password_hash' "
        "must both be empty or both be non-emtpy")


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


def calculate_mesos_enterprise_isolation(mesos_isolation, ssl_enabled):
    isolation = ','.join([
        mesos_isolation,
        'com_mesosphere_dcos_SecretsIsolator'
    ])
    if ssl_enabled == 'true':
        isolation += ',com_mesosphere_dcos_SSLExecutorIsolator'
    return isolation


def get_ui_auth_json(
    ui_organization,
    ui_networking,
    ui_secrets,
    ui_auth_providers,
    ui_bootstrap_config,
    ui_service_upgrades
):
    # Hacky. Use '%' rather than .format() to avoid dealing with escaping '{'
    return '"authentication":{"enabled":true},"oauth":{"enabled":false}, ' \
        '"organization":{"enabled":%s}, ' \
        '"networking":{"enabled":%s},' \
        '"secrets":{"enabled":%s},' \
        '"auth-providers":{"enabled":%s},' \
        '"bootstrap-config":{"enabled":%s},' \
        '"service-upgrades":{"enabled":%s},' \
        % (ui_organization, ui_networking, ui_secrets, ui_auth_providers, ui_bootstrap_config, ui_service_upgrades)


def calculate_mesos_enterprise_hooks(dcos_remove_dockercfg_enable, ssl_enabled):
    hooks = 'com_mesosphere_dcos_SecretsHook'
    if ssl_enabled == 'true':
        hooks += ',com_mesosphere_dcos_SSLExecutorHook'
    if dcos_remove_dockercfg_enable == 'true':
        hooks += ",com_mesosphere_dcos_RemoverHook"
    return hooks


def calculate_marathon_port(security):
    if security in ('strict', 'permissive'):
        return "8443"
    assert security == 'disabled'
    return "8080"


def calculate_adminrouter_master_port(security):
    if security in ('strict', 'permissive'):
        return "443"
    assert security == 'disabled'
    return "80"


def calculate_adminrouter_agent_port(security):
    if security in ('strict', 'permissive'):
        return "61002"
    assert security == 'disabled'
    return "61001"


def calculate_check_config(check_time, security, ssl_enabled, adminrouter_master_port, adminrouter_agent_port):
    scheme = 'https'
    if security == 'disabled':
        scheme = 'http'

    force_tls = ""
    ca_cert = ""
    if ssl_enabled == "true":
        force_tls = "--force-tls"
        ca_cert = "--ca-cert=/run/dcos/pki/CA/ca-bundle.crt"

    check_config = {
        'cluster_checks': {
            'mesos_leader': {
                'description': 'There is an elected Mesos leader',
                'cmd': [
                    '/opt/mesosphere/bin/dcos-checks',
                    '--iam-config',
                    '/run/dcos/etc/dcos-checks/checks_service_account.json',
                    force_tls,
                    ca_cert,
                    'cluster',
                    'mesos-leader'
                ],
                'timeout': '1s'
            },
            'marathon_leader': {
                'description': 'There is an elected Marathon leader',
                'cmd': [
                    '/opt/mesosphere/bin/dcos-checks',
                    '--iam-config',
                    '/run/dcos/etc/dcos-checks/checks_service_account.json',
                    force_tls,
                    ca_cert,
                    'cluster',
                    'marathon-leader'
                ],
                'timeout': '1s'
            },
            'metronome_leader': {
                'description': 'There is an elected Metronome leader',
                'cmd': [
                    '/opt/mesosphere/bin/dcos-checks',
                    '--iam-config',
                    '/run/dcos/etc/dcos-checks/checks_service_account.json',
                    force_tls,
                    ca_cert,
                    'cluster',
                    'metronome-leader'
                ],
                'timeout': '1s'
            }
        },
        'node_checks': {
            'checks': {
                'components_master': {
                    'description': 'All DC/OS components are healthy.',
                    'cmd': [
                        '/opt/mesosphere/bin/dcos-checks',
                        '--role',
                        'master',
                        '--iam-config',
                        '/run/dcos/etc/dcos-checks/checks_service_account.json',
                        force_tls,
                        ca_cert,
                        'components',
                        '--scheme', scheme,
                        '--port', adminrouter_master_port
                    ],
                    'timeout': '3s',
                    'roles': ['master']
                },
                'components_agent': {
                    'description': 'All DC/OS components are healthy',
                    'cmd': [
                        '/opt/mesosphere/bin/dcos-checks',
                        '--role',
                        'agent',
                        '--iam-config',
                        '/run/dcos/etc/dcos-checks/checks_service_account.json',
                        force_tls,
                        ca_cert,
                        'components',
                        '--scheme', scheme,
                        '--port', adminrouter_agent_port
                    ],
                    'timeout': '3s',
                    'roles': ['agent']
                },
                'xz': {
                    'description': 'The xz utility is available',
                    'cmd': ['/opt/mesosphere/bin/dcos-checks', 'executable', 'xz'],
                    'timeout': '1s'
                },
                'tar': {
                    'description': 'The tar utility is available',
                    'cmd': ['/opt/mesosphere/bin/dcos-checks', 'executable', 'tar'],
                    'timeout': '1s'
                },
                'curl': {
                    'description': 'The curl utility is available',
                    'cmd': ['/opt/mesosphere/bin/dcos-checks', 'executable', 'curl'],
                    'timeout': '1s'
                },
                'unzip': {
                    'description': 'The unzip utility is available',
                    'cmd': ['/opt/mesosphere/bin/dcos-checks', 'executable', 'unzip'],
                    'timeout': '1s'
                },
                'ip_detect_script': {
                    'description': 'The IP detect script produces valid output',
                    'cmd': ['/opt/mesosphere/bin/dcos-checks', 'ip'],
                    'timeout': '1s'
                },
                'mesos_master_replog_synchronized': {
                    'description': 'The Mesos master has synchronized its replicated log',
                    'cmd': [
                        '/opt/mesosphere/bin/dcos-checks',
                        '--role',
                        'master',
                        '--iam-config',
                        '/run/dcos/etc/dcos-checks/checks_service_account.json',
                        force_tls,
                        ca_cert,
                        'mesos-metrics'
                    ],
                    'timeout': '1s',
                    'roles': ['master']
                },
                'mesos_agent_registered_with_masters': {
                    'description': 'The Mesos agent has registered with the masters',
                    'cmd': [
                        '/opt/mesosphere/bin/dcos-checks',
                        '--role',
                        'agent',
                        '--iam-config',
                        '/run/dcos/etc/dcos-checks/checks_service_account.json',
                        force_tls,
                        ca_cert,
                        'mesos-metrics'
                    ],
                    'timeout': '1s',
                    'roles': ['agent']
                },
                'zookeeper_serving': {
                    'description': 'The ZooKeeper instance is serving',
                    'cmd': [
                        '/opt/mesosphere/bin/dcos-checks',
                        '--role',
                        'master',
                        force_tls,
                        ca_cert,
                        '--iam-config',
                        '/run/dcos/etc/dcos-checks/checks_service_account.json',
                        'zk-quorum'
                    ],
                    'timeout': '3s',
                    'roles': ['master']
                },
            },
            'prestart': [],
            'poststart': [
                'components_master',
                'components_agent',
                'xz',
                'tar',
                'curl',
                'unzip',
                'ip_detect_script',
                'mesos_master_replog_synchronized',
                'mesos_agent_registered_with_masters',
                'zookeeper_serving',
            ],
        },
    }

    if check_time == 'true':
        # Add the clock sync check.
        clock_sync_check_name = 'clock_sync'
        check_config['node_checks']['checks'][clock_sync_check_name] = {
            'description': 'System clock is in sync.',
            'cmd': ['/opt/mesosphere/bin/dcos-checks', 'time'],
            'timeout': '1s'
        }
        check_config['node_checks']['poststart'].append(clock_sync_check_name)

    return json.dumps(check_config)


entry = {
    'validate': [
        validate_bouncer_expiration_auth_token_days,
        validate_customer_key,
        validate_zk_super_credentials,
        validate_zk_master_credentials,
        validate_zk_agent_credentials,
        lambda auth_cookie_secure_flag: validate_true_false(auth_cookie_secure_flag),
        lambda security: validate_one_of(security, ['strict', 'permissive', 'disabled']),
        lambda dcos_audit_logging: validate_true_false(dcos_audit_logging),
        validate_ca_certificate,
        lambda ca_certificate_enabled: validate_true_false(ca_certificate_enabled),
    ],
    'default': {
        'bouncer_expiration_auth_token_days': '5',
        'security': 'permissive',
        'dcos_audit_logging': 'true',
        'superuser_username': '',
        'superuser_password_hash': '',
        'superuser_credentials_given': calculate_superuser_credentials_given,
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
        'ui_banner_dismissible': 'null',
        'ca_certificate_path': '',
        'ca_certificate_key_path': '',
        'ca_certificate_chain_path': '',
    },
    'must': {
        'oauth_available': 'false',
        'zk_super_digest_jvmflags': calculate_zk_super_digest_jvmflags,
        'zk_agent_digest': calculate_zk_agent_digest,
        'adminrouter_auth_enabled': 'true',
        'adminrouter_master_enforce_https': calculate_adminrouter_master_enforce_https,
        'adminrouter_agent_enforce_https': calculate_adminrouter_agent_enforce_https,
        'adminrouter_master_default_scheme': calculate_adminrouter_master_default_scheme,
        'bootstrap_secrets': 'true',
        'ui_auth_providers': 'true',
        'ui_bootstrap_config': 'true',
        'ui_secrets': 'true',
        'ui_networking': 'true',
        'ui_organization': 'true',
        'ui_external_links': 'true',
        'ui_branding': 'true',
        'ui_service_upgrades': 'true',
        'ui_telemetry_metadata': '{"openBuild": false}',
        'minuteman_forward_metrics': 'true',
        'custom_auth': 'true',
        'custom_auth_json': get_ui_auth_json,
        'mesos_master_http_authenticators': 'com_mesosphere_dcos_http_Authenticator',
        'mesos_agent_http_authenticators': calculate_mesos_agent_http_authenticators,
        'mesos_authenticate_http': calculate_mesos_authenticate_http,
        'mesos_classic_authenticator': calculate_mesos_classic_authenticator,
        'framework_authentication_required': calculate_framework_authentication_required,
        'agent_authentication_required': calculate_agent_authentication_required,
        'agent_authn_enabled': calculate_agent_authn_enabled,
        'executor_authentication_required': calculate_executor_authentication_required,
        'executor_secret_generation_enabled': calculate_executor_secret_generation_enabled,
        'executor_secret_key_path': '/var/lib/dcos/mesos/executor_key',
        'framework_authentication_enabled': calculate_framework_authentication_enabled,
        'mesos_authz_enforced': calculate_mesos_authz_enforced,
        'mesos_master_authorizers': calculate_mesos_authorizer,
        'mesos_agent_authorizer': calculate_mesos_authorizer,
        'mesos_elevate_unknown_users': calculate_mesos_elevate_unknown_users,
        'mesos_hooks': calculate_mesos_enterprise_hooks,
        'mesos_enterprise_isolation': calculate_mesos_enterprise_isolation,
        'mesos_secret_resolver': 'com_mesosphere_dcos_SecretResolver',
        'firewall_enabled': calculate_firewall_enabled,
        'ssl_enabled': calculate_ssl_enabled,
        'ssl_support_downgrade': calculate_ssl_support_downgrade,
        'default_task_user': calculate_default_task_user,
        'marathon_authn_mode': calculate_marathon_authn_mode,
        'marathon_https_enabled': calculate_marathon_https_enabled,
        'marathon_extra_args': calculate_marathon_extra_args,
        'zk_acls_enabled': calculate_zk_acls_enabled,
        'marathon_port': calculate_marathon_port,
        'adminrouter_master_port': calculate_adminrouter_master_port,
        'adminrouter_agent_port': calculate_adminrouter_agent_port,
        'ca_certificate': calculate_ca_certificate,
        'ca_certificate_enabled': calculate_ca_certificate_enabled,
        'check_config': calculate_check_config
    }
}

provider_template_defaults = {
    'superuser_username': '',
    'superuser_password_hash': '',
    'customer_key': 'Cloud Template Missing Parameter'
}
