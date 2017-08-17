"""
Tests for cluster restart scenarios.
"""

import logging
import threading
import uuid
from pathlib import Path
from subprocess import CalledProcessError

import pytest
import retrying
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
        healthy after shutting down cockroachdb on every master node
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

            # Confirm that cockroachdb is running on all the masters.
            _wait_for_cockroachdb_cluster_healthy(cluster.masters)

            # Stop cockroachdb on all masters.
            _stop_cockroachdb_on_masters(cluster.masters)

            # Check that cockroachdb instances are unhealthy.
            _assert_cockroachdb_cluster_unhealthy(cluster.masters)

            # Start cockroachdb on all master nodes.
            _start_cockroachdb_on_masters(cluster.masters)

            # Confirm that cockroachdb is running on all the masters.
            _wait_for_cockroachdb_cluster_healthy(cluster.masters)


@retrying.retry(
    stop_max_delay=2 * 60 * 1000,
    retry_on_exception=lambda x: isinstance(x, CalledProcessError))
def _wait_for_cockroachdb_cluster_healthy(masters):
    """Wait for cockroachdb to be running on the master."""
    for master in masters:
        # Confirm that the cockroachdb instance is running.
        log.info("Confirming that cockroachdb is running on master `{}`".format(
            master.ip_address))
        _check_cockroachdb_status(master)


def _assert_cockroachdb_cluster_unhealthy(masters):
    """Wait for cockroachdb to not be running on the master."""
    for master in masters:
        # Confirm that the cockroachdb instance is not running.
        log.info("Confirming that cockroachdb is not running on master `{}`".format(
            master.ip_address))
        with pytest.raises(CalledProcessError):
            _check_cockroachdb_status(master)


def _check_cockroachdb_status(master):
    """Confirm that cockroachdb is running on the master."""
    # Running `systemctl status` will return a non-zero exit status
    # if the listed unit is not active.
    cockroachdb_status_args = ['systemctl', 'status', 'dcos-cockroach']
    master.run_as_root(args=cockroachdb_status_args)


def _stop_cockroachdb_on_masters(masters):
    """Stop cockroachdb on all master nodes."""
    stop_cmd = ['systemctl', 'stop', 'dcos-cockroach']
    for master in masters:
        log.info("Stopping cockroachdb on master `{}`".format(master.ip_address))
        master.run_as_root(stop_cmd)


def _start_cockroachdb_on_masters(masters):
    """
    cockroachdb only starts successfully once sufficient members have
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
