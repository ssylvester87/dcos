import json

import yaml

import gen
from gen.tests.utils import make_arguments


def test_secret_config_is_hidden():
    secret_config = {
        'superuser_password_hash': 'secret',
        'zk_super_credentials': 'secret:secret',
        'zk_master_credentials': 'secret:secret',
        'zk_agent_credentials': 'secret:secret',
    }
    secret_derived_variables = ['zk_super_digest_jvmflags', 'zk_agent_digest']

    generated = gen.generate(arguments=make_arguments(new_arguments=secret_config))
    expanded_config = json.loads(generated.arguments['expanded_config'])
    expanded_config_full = json.loads(generated.arguments['expanded_config_full'])
    user_arguments = json.loads(generated.arguments['user_arguments'])
    user_arguments_full = json.loads(generated.arguments['user_arguments_full'])
    config_yaml = yaml.load(generated.arguments['config_yaml'])
    config_yaml_full = yaml.load(generated.arguments['config_yaml_full'])

    for var_name, var_value in secret_config.items():
        assert var_name not in expanded_config
        assert expanded_config_full[var_name] == var_value

        assert user_arguments[var_name] == '**HIDDEN**'
        assert user_arguments_full[var_name] == var_value

        assert config_yaml[var_name] == '**HIDDEN**'
        assert config_yaml_full[var_name] == var_value

    for var_name in secret_derived_variables:
        assert var_name not in expanded_config
        assert var_name in expanded_config_full
