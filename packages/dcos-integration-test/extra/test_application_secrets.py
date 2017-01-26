import uuid

import pytest


@pytest.mark.usefixtures("secrets_verify_and_reset")
def test_enterprise_if_application_run_with_secrets(superuser_api_session, service_accounts_fixture):
    # Create service account keypair and service account
    cli, _, private_key_filepath, _ = service_accounts_fixture

    # Create service account secret
    stdout, stderr = cli.exec_command(
        ["dcos", "security", "secrets", "create-sa-secret",
         private_key_filepath, "mlb-secret", "/mlb-secret"])
    assert stdout == ''
    assert stderr == ''

    # Install marathon_lb
    # TODO: Test fixture for package cleanup
    headers = {
        'Accept': 'application/vnd.dcos.package.install-response+json;charset=utf-8;version=v1',
        'Content-Type': 'application/vnd.dcos.package.install-request+json;charset=utf-8;version=v1'
    }

    endpoint = '/package/install'

    marathon_lb = {
        'packageName': 'marathon-lb',
        'packageVersion': '1.7.0-1',
        'options': {
            'marathon-lb': {
                'auto-assign-service-ports': False,
                'bind-http-https': True,
                'cpus': 2,
                'haproxy_global_default_options': 'redispatch,http-server-close,dontlognull',
                'haproxy-group': 'internal',
                'haproxy-map': True,
                'instances': 1,
                'mem': 1024,
                'minimumHealthCapacity': 0.5,
                'maximumOverCapacity': 0.2,
                'name': 'marathon-lb',
                'role': 'slave_public',
                'strict-mode': False,
                'sysctl-params': 'net.ipv4.tcp_tw_reuse=1 '
                                 'net.ipv4.tcp_fin_timeout=30 '
                                 'net.ipv4.tcp_max_syn_backlog=10240 '
                                 'net.ipv4.tcp_max_tw_buckets=400000 '
                                 'net.ipv4.tcp_max_orphans=60000 '
                                 'net.core.somaxconn=10000',
                'marathon-uri': 'http://marathon.mesos:8080',
                'secret_name': 'mlb-secret'
            }
        }
    }

    r = superuser_api_session.post(endpoint, json=marathon_lb, headers=headers)
    assert r.status_code == 200

    headers = {
        'Content-Type': 'application/vnd.dcos.package.uninstall-request+json;charset=utf-8;version=v1',
        'Accept': 'application/vnd.dcos.package.uninstall-response+json;charset=utf-8;version=v1'
    }
    r = superuser_api_session.post('/package/uninstall', json=marathon_lb, headers=headers)

    # creating a secret
    r = superuser_api_session.secrets.put('/secret/default/testpassword', json={'value': 'anewpassword'})
    assert r.status_code == 201

    test_uuid = uuid.uuid4().hex

    # redis server app definition using the secret
    # TODO(jimenez): Fix health check secret of type command using a secret
    # TODO(jimenez): Fix cleanup to work with services namespaces
    server_id = 'integration-test-redis{}'.format(test_uuid)
    redis_server_definition = {
        'id': '/%s' % server_id,
        'cpus': 0.5,
        'mem': 128,
        'cmd': 'redis-server --requirepass $APPLICATION_PASSWORD --bind 0.0.0.0',
        'instances': 1,
        'container': {
            'type': 'DOCKER',
            'docker': {
                'image': 'redis',
                'forcePullImage': False,
                'priviledged': False,
                'network': 'BRIDGE',
                'portMappings': [
                    {
                        'containerPort': 6379,
                        'hostPort': 0,
                        'labels': {
                            'VIP_0': '%s:6379' % server_id,
                        },
                        'protocol': 'tcp',
                        'name': 'redis',
                    }
                ]
            }
        },
        'acceptedResourceRoles': ['slave_public'],
        'env': {
            'APPLICATION_PASSWORD':
            {
                'secret': 'redis-password'
            }
        },
        'secrets': {
            'redis-password': {
                'source': '/testpassword'
            }
        },
        'labels': {
            'HAPROXY_GROUP': 'internal',
        },
    }

    # redis client app definition
    redis_client_definition = {
        'id': '/integration-test-second-container-with-secret{}'.format(test_uuid),
        'cpus': 0.5,
        'mem': 128,
        'cmd': ('redis-cli '
                '-a $APPLICATION_PASSWORD '
                '-h %s.marathon.l4lb.thisdcos.directory '
                '-p 6379 '
                '-x set foo '
                '&& sleep 1000' % server_id),
        'instances': 1,
        'container': {
            'type': 'DOCKER',
            'docker': {
                'image': 'redis',
                'forcePullImage': False,
                'priviledged': False,
            }
        },
        'acceptedResourceRoles': ['slave_public'],
        'env': {
            'APPLICATION_PASSWORD':
            {
                'secret': 'redis-password'
            }
        },
        'secrets': {
            'redis-password': {
                'source': '/testpassword'
            }
        },
        'labels': {
            'HAPROXY_GROUP': 'internal',
        }
    }

    with superuser_api_session.marathon.deploy_and_cleanup(redis_server_definition, check_health=False):
        with superuser_api_session.marathon.deploy_and_cleanup(redis_client_definition, check_health=False):
            pass
        pass
