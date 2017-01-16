"""
Test Enterprise DC/OS Network Api Service
"""
import logging
import socket
import uuid

import pytest
import requests
import retrying

from dcostests import dcos, marathon
from dcostests.marathon import MarathonApp


timeout = 300


def wait_for_networking_api_up(host, port, is_ip):
    try:
        r = requests.get('http://{}:{}'.format(host, port))
        if not r.ok or 'imok' not in r.text:
            return False
        r = dcos.get('/networking/api/v1/vips')
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
    app_def = marathon.sleep_app_definition('')
    # this test requires short names for dns queries
    app_def['id'] = '/{}'.format(app_name)
    app_def['cmd'] = 'touch imok && /opt/mesosphere/bin/python -mhttp.server ${PORT0}'
    app_def['healthChecks'] = [{
        'protocol': 'HTTP',
        'path': '/',
        'portIndex': 0,
        'gracePeriodSeconds': 5,
        'intervalSeconds': 10,
        'timeoutSeconds': 10,
        'maxConsecutiveFailures': 3
    }]
    app_def['portDefinitions'] = [{
        "protocol": "tcp",
        "port": 0,
        "labels": {
            "VIP_0": '{}:{}'.format(app_ip, app_port)
        },
    }]
    return app_def


def test_network_api_vips(superuser):
    """Test if we are able to connect to a task with a vip using minuteman.
    """
    app_port = '5000'
    app_ip = '1.2.3.4'
    app_name = 'test-network-api-vips-{}'.format(uuid.uuid4().hex)
    app_def = app_definition(app_name, app_ip, app_port)
    app = MarathonApp(app_def)
    r = app.deploy(headers=superuser.authheader)
    logging.info(r.text)
    assert r.ok
    endpoints = app.wait(headers=superuser.authheader)
    logging.info('endpoint is {}:{}'.format(endpoints[0].host, endpoints[0].port))

    @retrying.retry(wait_fixed=1000,
                    stop_max_delay=timeout * 1000,
                    retry_on_result=lambda ret: ret is False,
                    retry_on_exception=lambda x: False)
    def run():
        def is_vip(x):
            return x.get('ip', '') == app_ip and x.get('port', '') == app_port
        return wait_for_networking_api_up(app_ip, app_port, is_vip)
    try:
        assert run()
    except retrying.RetryError:
        pytest.fail("Network api query failed - operation was not "
                    "completed in {} seconds.".format(timeout))


def test_network_api_named_vips(superuser):
    """Test if we are able to connect to a task with a named vip using minuteman.
    """
    app_port = '6000'
    # use a short name for dns queries
    app_name = 'id{}'.format(uuid.uuid4().hex)[1:10]
    app_def = app_definition(app_name, app_name, app_port)
    app = MarathonApp(app_def)
    r = app.deploy(headers=superuser.authheader)
    logging.info(r.text)
    assert r.ok
    endpoints = app.wait(headers=superuser.authheader)
    logging.info('endpoint is {}:{}'.format(endpoints[0].host, endpoints[0].port))

    @retrying.retry(wait_fixed=1000,
                    stop_max_delay=timeout * 1000,
                    retry_on_result=lambda ret: ret is False,
                    retry_on_exception=lambda x: False)
    def run():
        app_host = '{}.marathon.l4lb.thisdcos.directory'.format(app_name)
        logging.info('hostname is {}'.format(app_host))

        def getaddr(host):
            logging.info("resolving {}".format(host))
            try:
                addrs = socket.getaddrinfo(host, None, family=socket.AF_INET, proto=socket.SOCK_STREAM)
            except socket.error:
                return None
            if(addrs is None or addrs[0] is None):
                return None
            ip = addrs[0][4][0]
            logging.info('{} ip {}'.format(host, ip))
            return ip

        app_ip = getaddr(app_host)
        if(app_ip is None):
            return False

        def is_named_vip(x):
            rv = x.get('port', '') == app_port
            rv = rv and x.get('ip', '') == app_ip
            rv = rv and x.get('protocol', '') == 'tcp'
            return rv
        return wait_for_networking_api_up(app_host, app_port, is_named_vip)

    try:
        assert run()
    except retrying.RetryError:
        pytest.fail("Network api query failed - operation was not "
                    "completed in {} seconds.".format(timeout))
