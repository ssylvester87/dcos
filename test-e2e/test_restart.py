"""
Tests for cluster restart scenarios.
"""

import logging
import threading
import uuid
from pathlib import Path
from subprocess import CalledProcessError

import pytest
from dcos_e2e.backends import ClusterBackend
from dcos_e2e.cluster import Cluster
from passlib.hash import sha512_crypt


log = logging.getLogger(__name__)


class TestServiceStopStart:
    """
    Test for expected recovery behaviour in the event of a
    cluster-wide service stop/start sequence.
    """

    def test_cockroach_stop_start(
        self,
        dcos_docker_backend: ClusterBackend,
        artifact_path: Path,
    ):
        """
        Test that a cluster consisting of multiple master nodes becomes
        healthy after shutting down CockroachDB on every master node
        and starting it again.
        """

        superuser_username = str(uuid.uuid4())
        superuser_password = str(uuid.uuid4())
        config = {
            'superuser_username': superuser_username,
            # We can hash the password with any `passlib`-based method here.
            # We choose `sha512_crypt` arbitrarily.
            'superuser_password_hash': sha512_crypt.hash(superuser_password),
            'security': 'strict',
        }

        with Cluster(
            log_output_live=True,
            extra_config=config,
            cluster_backend=dcos_docker_backend,
            generate_config_path=artifact_path,
            masters=3,
        ) as cluster:
            # Wait for the cluster to become healthy initially.
            log.info("Waiting for cluster to become healthy.")
            cluster.wait_for_dcos()
            # Stop CockroachDB on all master nodes.
            stop_cmd = ['systemctl', 'stop', 'dcos-cockroach']
            diagnostics_args = ['/opt/mesosphere/bin/dcos-diagnostics', '--diag']
            for master in cluster.masters:
                # Confirm that the master is healthy by running diagnostics.
                master.run_as_root(args=diagnostics_args)
                log.info("Stopping cockroachdb on master `{}`.".format(master.ip_address))
                master.run_as_root(args=stop_cmd)
                # Confirm that the master is unhealthy by asserting
                # that diagnostics fail.
                with pytest.raises(CalledProcessError):
                    log.info("Confirming that diagnostics fail with stopped cockroachdb instance.")
                    master.run_as_root(args=diagnostics_args)

            # Start CockroachDB on all master nodes.
            start_cockroach_on_masters(cluster.masters)

            # Wait for the cluster to become healthy again.
            log.info("Waiting for cluster to become healthy.")
            cluster.wait_for_dcos()


def start_cockroach_on_masters(masters):
    """
    CockroachDB only starts successfully once sufficient members have
    rejoined the cluster. That means that starting them serially won't
    work: the first will hang waiting for the others and eventually
    the test will time out.

    We execute each start command in a separate thread and wait for
    them all to finish.
    """

    def start_cockroach(master):
        log.info("Starting cockroachdb on master `{}`.".format(master.ip_address))
        start_cmd = ['systemctl', 'start', 'dcos-cockroach']
        master.run_as_root(args=start_cmd)
        log.info("Started cockroachdb on master `{}`.".format(master.ip_address))

    threads = []
    for master in masters:
        t = threading.Thread(target=start_cockroach, args=(master,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
