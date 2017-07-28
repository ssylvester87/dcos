"""
Test Enterprise DC/OS Network Api Service
"""
import logging
import socket
import uuid

import requests
import retrying


@retrying.retry(
    wait_fixed=1000,
    stop_max_delay=300 * 1000,
    retry_on_result=lambda ret: ret is False,
    retry_on_exception=lambda x: False)
def wait_for_networking_api_up(host, port, is_ip, session):
    try:
        r = requests.get('http://{}:{}'.format(host, port))
        if not r.ok or 'imok' not in r.text:
            return False
        r = session.get('/networking/api/v1/vips')
        ips = r.json().get('array', [])
        logging.info('GET /networking/api/v1/vips returned: {}'.format(ips))
        expected = list(filter(is_ip, ips))
        if r.status_code < 400 and len(expected) == 1:
            logging.info("Networking api is probably up")
            return True
        else:
            msg = "Waiting for networking api, resp is: {}: {}"
            logging.info(msg.format(r.status_code, r.text))
            return False
    except Exception as e:
        logging.info("Failed to query networking api: {}".format(e))
        return False


def app_definition(app_name, app_ip, app_port):
    return {
        'id': '/{}'.format(app_name),
        'cmd': 'touch imok && /opt/mesosphere/bin/python -mhttp.server ${PORT0}',
        'cpus': 0.1,
        'mem': 32,
        'instances': 1,
        'healthChecks': [{
            'protocol': 'HTTP',
            'path': '/',
            'portIndex': 0,
            'gracePeriodSeconds': 5,
            'intervalSeconds': 10,
            'timeoutSeconds': 10,
            'maxConsecutiveFailures': 3}],
        'portDefinitions': [{
            'protocol': 'tcp',
            'port': 0,
            'labels': {'VIP_0': '{}:{}'.format(app_ip, app_port)}
            }]
        }


def test_network_api_vips(superuser_api_session):
    """Test if we are able to connect to a task with a vip using minuteman.
    """
    app_port = '5000'
    app_ip = '1.2.3.4'
    app_name = 'test-network-api-vips-{}'.format(uuid.uuid4().hex)
    app_def = app_definition(app_name, app_ip, app_port)

    def is_vip(x):
        return x.get('ip', '') == app_ip and x.get('port', '') == app_port

    with superuser_api_session.marathon.deploy_and_cleanup(app_def):
        endpoints = superuser_api_session.marathon.get_app_service_endpoints(app_def['id'])
        logging.info('endpoint is {}:{}'.format(endpoints[0].host, endpoints[0].port))
        wait_for_networking_api_up(app_ip, app_port, is_vip, superuser_api_session)


def test_network_api_named_vips(superuser_api_session):
    """Test if we are able to connect to a task with a named vip using minuteman.
    """
    app_port = '6000'
    # use a short name for dns queries
    app_name = 'id{}'.format(uuid.uuid4().hex)[1:10]
    app_def = app_definition(app_name, app_name, app_port)
    app_host = '{}.marathon.l4lb.thisdcos.directory'.format(app_name)
    logging.info('hostname is {}'.format(app_host))

    @retrying.retry(
        wait_fixed=1000,
        stop_max_delay=300 * 1000,
        retry_on_result=lambda ret: ret is False)
    def wait_for_addr():
        logging.info("resolving {}".format(app_host))
        addrs = socket.getaddrinfo(app_host, None, family=socket.AF_INET, proto=socket.SOCK_STREAM)
        if(addrs is None or addrs[0] is None):
            return False
        ip = addrs[0][4][0]
        if ip is None:
            return False
        logging.info('{} ip {}'.format(app_host, ip))
        return ip

    with superuser_api_session.marathon.deploy_and_cleanup(app_def):
        endpoints = superuser_api_session.marathon.get_app_service_endpoints(app_def['id'])
        logging.info('endpoint is {}:{}'.format(endpoints[0].host, endpoints[0].port))
        app_ip = wait_for_addr()

        def is_named_vip(x):
            rv = x.get('port', '') == app_port
            rv = rv and x.get('ip', '') == app_ip
            rv = rv and x.get('protocol', '') == 'tcp'
            rv = rv and x.get('name', '') == '{}.marathon'.format(app_name)
            return rv

        wait_for_networking_api_up(app_host, app_port, is_named_vip, superuser_api_session)
