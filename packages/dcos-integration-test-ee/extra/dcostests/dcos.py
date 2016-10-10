# -*- coding: utf-8 -*-
# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""Provide DC/OS context for integration test run."""


import atexit
import functools
import json
import logging
import os
import socket
import tempfile

import dns.exception
import dns.resolver
import pytest
import requests
import retrying

logfmt = "%(asctime)s.%(msecs)03d %(name)s %(funcName)s() %(levelname)s: %(message)s"
datefmt = "%y%m%d-%H:%M:%S"
logging.basicConfig(
    level=logging.INFO,
    format=logfmt,
    datefmt=datefmt
    )

# Decrease verbosity of 3rd party lib logs.
logging.getLogger("requests").setLevel(logging.ERROR)
logging.getLogger("kazoo").setLevel(logging.ERROR)


log = logging.getLogger(__name__)


class _DCOS:
    """An abstraction for the tested DC/OS instance.

    Supposed to be a singleton.
    """

    hostname = None
    ca_crt_file_path = None
    su_uid = None
    su_password = None
    authheader = None

    # Endpoints that are expected to be accessible only by users that have
    # special permissions explicitly set.
    ops_endpoints = [
        '/acs/api/v1/users/',
        '/dcos-history-service/',
        '/exhibitor',
        '/mesos',
        '/mesos_dns/v1/config',
        '/metadata',
        '/networking/api/v1/vips',
        '/pkgpanda/active.buildinfo.full.json',
        '/secrets/v1/store',
        '/system/health/v1',
        '/pkgpanda/active/',
        ]

    # TODO(greggomann): Automatically populate this list.
    initial_resource_ids = [
        "dcos:adminrouter:ops:metadata",
        "dcos:adminrouter:ops:historyservice",
        "dcos:adminrouter:package",
        "dcos:adminrouter:acs",
        "dcos:adminrouter:ops:mesos",
        "dcos:adminrouter:service:marathon",
        "dcos:adminrouter:ops:mesos-dns",
        "dcos:adminrouter:ops:exhibitor",
        "dcos:adminrouter:ops:ca:ro",
        "dcos:adminrouter:ops:slave",
        "dcos:superuser",
        "dcos:adminrouter:ops:system-health",
        "dcos:adminrouter:ops:ca:rw",
        "dcos:adminrouter:ops:networking",
        "dcos:adminrouter:ops:pkgpanda",
        ]

    # Endpoints that are expected to be accessible by all authenticated users,
    # w/o setting permissions explicitly.
    authenticated_users_endpoints = [
        '/capabilities',
        '/navstar/lashup/key'
        ]

    def __init__(self):
        self.configure()
        self._wait_for_DCOS()

        # Security-related bootstrapping code creates these RIDs.
        if self.config['security'] == 'permissive':
            self.initial_resource_ids.extend([
                'dcos:mesos:master:framework',
                'dcos:mesos:master:reservation',
                'dcos:mesos:master:volume',
                'dcos:mesos:master:task'
                ])
        elif self.config['security'] == 'strict':
            self.initial_resource_ids.extend([
                'dcos:mesos:master:framework:role:slave_public',
                'dcos:mesos:master:framework:role:*',
                'dcos:mesos:master:reservation:role:slave_public',
                'dcos:mesos:master:reservation:principal:dcos_marathon',
                'dcos:mesos:master:volume:role:slave_public',
                'dcos:mesos:master:volume:principal:dcos_marathon',
                'dcos:mesos:master:task:user:nobody',
                'dcos:mesos:master:task:app_id'
                ])

    def configure(self):
        self._get_bootstrap_config()
        self._get_hostname()
        self._get_su_credentials()
        self._get_hosts()
        self._get_provider()
        if self.config['ssl_enabled']:
            self._make_ca_crt_file()

    def _get_bootstrap_config(self):
        with open('/opt/mesosphere/etc/bootstrap-config.json', 'rb') as f:
            self.config = json.loads(f.read().decode('ascii'))
        if self.config['ssl_enabled']:
            self.scheme = 'https://'
        else:
            self.scheme = 'http://'

    def _get_hosts(self):
        self.masters = sorted(os.environ['MASTER_HOSTS'].split(','))
        self.public_masters = sorted(os.environ['PUBLIC_MASTER_HOSTS'].split(','))
        self.private_agents = sorted(os.environ['SLAVE_HOSTS'].split(','))
        self.public_agents = sorted(os.environ['PUBLIC_SLAVE_HOSTS'].split(','))
        self.agents = sorted(self.private_agents + self.public_agents)

        # Build ZK hostports string.
        self.zk_hostports = ','.join(
            ':'.join([host, '2181']) for host in self.public_masters
            )

    def _get_su_credentials(self):
        self.su_uid = os.environ['DCOS_LOGIN_UNAME']
        self.su_password = os.environ['DCOS_LOGIN_PW']

    def _get_hostname(self):
        dns = os.environ['DCOS_DNS_ADDRESS']
        h = dns.split('//')[-1]
        log.info('Test if host `%s` can be resolved.', h)
        try:
            socket.gethostbyname(h)
        except Exception as e:
            pytest.exit(
                "Cannot reach DCOS_DNS_ADDRESS `%s`: %s" % (h, str(e)))
        self.hostname = h

    def _get_provider(self):
        self.provider = os.environ['DCOS_PROVIDER']

    def _make_ca_crt_file(self):
        def _remove_file():
            if os.path.exists(self.ca_crt_file_path):
                os.remove(self.ca_crt_file_path)

        # Attempt to get CA bundle from cluster. Follow redirects (might
        # redirect to HTTPS), but do not attempt to verify cert.
        log.info('Attempt to get CA bundle via CA HTTP API')
        r = requests.post(
            'https://%s/ca/api/v2/info' % self.hostname,
            json={'profile': ''},
            verify=False
            )
        assert r.status_code == 200
        data = r.json()
        crt = data['result']['certificate'].encode('ascii')
        # crt = os.getenv('DCOS_CA_CRT').encode('ascii')

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(crt)
            self.ca_crt_file_path = f.name

        # Attempt to remove the file upon normal interpreter exit.
        atexit.register(_remove_file)

        # requests by default attempts to verify certificates when
        # communicating HTTPS (and also performs hostname verification).
        # Instruct it to verify against this bundle.
        # Don't use REQUESTS_CA_BUNDLE for achieving this, as this
        # affects other requests package instances executed in the
        # context of this test runner (such as botocore's).

        for m in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
            orig = getattr(requests, m)
            patched = functools.partial(orig, verify=self.ca_crt_file_path)
            setattr(requests, m, patched)

    @retrying.retry(wait_fixed=1000,
                    retry_on_result=lambda ret: ret is False,
                    retry_on_exception=lambda x: False)
    def _wait_for_leader_election(self):
        mesos_resolver = dns.resolver.Resolver()
        mesos_resolver.nameservers = self.public_masters
        mesos_resolver.port = 61053
        try:
            # Yeah, we can also put it in retry_on_exception, but
            # this way we will loose debug messages
            mesos_resolver.query('leader.mesos', 'A')
        except dns.exception.DNSException as e:
            msg = "Cannot resolve leader.mesos, error string: '{}', continuing to wait"
            logging.info(msg.format(e))
            return False
        else:
            logging.info("leader.mesos dns entry is UP!")
            return True

    @retrying.retry(wait_fixed=1000,
                    retry_on_result=lambda ret: ret is False,
                    retry_on_exception=lambda x: False)
    def _wait_for_Marathon_up(self):
        r = self.get('/marathon/ui/')
        # resp_code >= 500 -> backend is still down probably
        if r.status_code < 500:
            logging.info("Marathon is probably up")
            return True
        else:
            msg = "Waiting for Marathon, resp code is: {}"
            logging.info(msg.format(r.status_code))
            return False

    @retrying.retry(wait_fixed=1000,
                    retry_on_result=lambda ret: ret is False,
                    retry_on_exception=lambda x: False)
    def _wait_for_slaves_to_join(self):
        # using state instead of slaves because of
        # Mesos endpoint firewall in strict mode
        r = self.get('/mesos/master/state')
        if r.status_code != 200:
            msg = "Mesos master returned status code {} != 200 "
            msg += "continuing to wait..."
            logging.info(msg.format(r.status_code))
            return False
        data = r.json()
        # Check that there are all the slaves the test knows about. They are all
        # needed to pass the test.
        num_slaves = len(data['slaves'])
        if num_slaves >= len(self.agents):
            msg = "Sufficient ({} >= {}) number of slaves have joined the cluster"
            logging.info(msg.format(num_slaves, self.agents))
            return True
        else:
            msg = "Current number of slaves: {} < {}, continuing to wait..."
            logging.info(msg.format(num_slaves, self.agents))
            return False

    @retrying.retry(wait_fixed=1000,
                    retry_on_result=lambda ret: ret is False,
                    retry_on_exception=lambda x: False)
    def _wait_for_DCOS_history_up(self):
        r = self.get('/dcos-history-service/ping')
        # resp_code >= 500 -> backend is still down probably
        if r.status_code <= 500:
            logging.info("DC/OS History is probably up")
            return True
        else:
            msg = "Waiting for DC/OS History, resp code is: {}"
            logging.info(msg.format(r.status_code))
            return False

    # Retry if returncode is False, do not retry on exceptions.
    @retrying.retry(wait_fixed=2000,
                    retry_on_result=lambda r: r is False,
                    retry_on_exception=lambda _: False)
    def _wait_for_srouter_slaves_endpoints(self):
        # Get currently known agents. This request is served straight from
        # Mesos (no AdminRouter-based caching is involved).
        logging.info('Fetching agents from Mesos')
        # using state instead of slaves because of
        # Mesos endpoint firewall in strict mode
        r = self.get('/mesos/master/state')
        assert r.status_code == 200

        data = r.json()
        slaves_ids = sorted(x['id'] for x in data['slaves'])

        for slave_id in slaves_ids:
            # AdminRouter's slave endpoint internally uses cached Mesos
            # state data. That is, slave IDs of just recently joined
            # slaves can be unknown here. For those, this endpoint
            # returns a 404. Retry in this case, until this endpoint
            # is confirmed to work for all known agents.
            uri = '/slave/{}/slave%281%29/state.json'.format(slave_id)
            logging.info('Fetching agent state from {}'.format(uri))
            r = self.get(uri)
            if r.status_code == 404:
                return False
            assert r.status_code == 200
            data = r.json()
            assert "id" in data
            assert data["id"] == slave_id

    @retrying.retry(wait_fixed=2000,
                    retry_on_result=lambda r: r is False,
                    retry_on_exception=lambda _: False)
    def _wait_for_metronome(self):
        r = self.get('/service/metronome/v1/jobs')
        # Metronome may respond with 500 or 504 during startup, see DCOS-9120.
        if r.status_code in (500, 504):
            logging.info("Continue waiting for Metronome")
            return False
        assert r.status_code == 200

    @retrying.retry(wait_fixed=1000,
                    retry_on_result=lambda ret: ret is False,
                    retry_on_exception=lambda x: False)
    def _login(self):
        r = requests.post('{}{}/acs/api/v1/auth/login'.format(self.scheme, self.hostname),
                          json={'uid': self.su_uid, 'password': self.su_password})
        r.raise_for_status()
        data = r.json()
        self.authheader = {'Authorization': 'token=%s' % data['token']}

    def get(self, path="", params=None, **kwargs):
        return requests.get(self.scheme + self.hostname + path, params=params, headers=self.authheader, **kwargs)

    def _wait_for_DCOS(self):
        self._login()
        self._wait_for_leader_election()
        self._wait_for_Marathon_up()
        self._wait_for_slaves_to_join()
        self._wait_for_DCOS_history_up()
        self._wait_for_srouter_slaves_endpoints()
        self._wait_for_metronome()

# Instantiate singleton.
dcos = _DCOS()
