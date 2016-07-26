# -*- coding: utf-8 -*-
# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""Provide DC/OS context for integration test run."""


import atexit
import logging
import os
import socket
import re
import tempfile

import pytest
import requests


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
        '/ca/api/v2/certificates',
        '/system/health/v1'
        ]

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
        "dcos:adminrouter:ops:networking"
        ]

    # Endpoints that are expected to be accessible by all authenticated users,
    # w/o setting permissions explicitly.
    authenticated_users_endpoints = [
        '/capabilities',
        '/navstar/lashup/key'
        ]

    def __init__(self):
        self.configure()

    def configure(self):
        self._get_hostname()
        self._get_su_credentials()
        self._get_hosts()
        self._make_ca_crt_file()

    def _get_hosts(self):
        self.masters = re.split('[,\s]+', os.environ['MASTER_HOSTS'])
        self.public_masters = os.environ['PUBLIC_MASTER_HOSTS'].split(',')
        self.agents = re.split('[,\s]+', os.environ['SLAVE_HOSTS'])

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
        os.environ['REQUESTS_CA_BUNDLE'] = f.name


# Instantiate singleton.
dcos = _DCOS()
