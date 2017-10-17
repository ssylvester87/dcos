"""
Test CockroachDB.
"""

import json
import os.path
import subprocess
import sys
import uuid
from typing import Optional, Tuple

import kazoo.exceptions
import pytest
from dcos_test_utils.enterprise import EnterpriseApiSession
from kazoo.client import KazooClient

from dcos_internal_utils.utils import detect_ip

# Import the cockroach start script.
sys.path.append("/opt/mesosphere/active/cockroach/bin")
import register  # noqa: E402


def _master_count() -> int:
    with open("/opt/mesosphere/etc/master_count", encoding='utf-8') as f:
        return int(f.read())


class TestCockroachCluster:

    def test_admin_ui_superuser(self, superuser_api_session: EnterpriseApiSession) -> None:
        r = superuser_api_session.get("/cockroachdb/", allow_redirects=False)
        assert r.status_code == 200

    def test_admin_ui_peteruser(self, peter_api_session: EnterpriseApiSession) -> None:
        r = peter_api_session.get("/cockroachdb/", allow_redirects=False)
        assert r.status_code == 403

    def test_admin_ui_noauth(self, noauth_api_session: EnterpriseApiSession) -> None:
        r = noauth_api_session.get("/cockroachdb/", allow_redirects=False)
        assert r.status_code == 401

    def test_cluster_ensemble(self) -> None:
        """
        Test that all the CockroachDB instances have joined the cluster.

        This test compares the number of instances that form part of the
        CockroachDB cluster to the number of expected master nodes and asserts
        that the two values are equal.
        """
        # Get the node status in tsv format.
        # Note: `sudo` is required to read the private key.
        my_ip = detect_ip()
        opts = "--format=tsv --certs-dir=/run/dcos/pki/cockroach --host={}".format(my_ip)
        out = subprocess.check_output(
            "sudo /opt/mesosphere/bin/cockroach node ls {opts}".format(opts=opts),
            shell=True).decode('utf-8')
        # This counts the number of nodes in the CockroachDB ensemble. Two lines are
        # skipped. The first shows the number of records and the second the headers.
        # We skip empty lines to defend against the `cockroach` command output changing
        # subtly.
        number_of_nodes = len([l for l in out.splitlines() if l]) - 2
        assert number_of_nodes == _master_count()

    def test_diagnostics_disabled(self) -> None:
        """Test that CockroachDB's diagnostic reporting is disabled.

        This test reads the value of `diagnostics.reporting.enabled` and checks
        that it is 'false'.
        """
        # Note: `sudo` is required to read client.root.key.
        my_ip = detect_ip()
        opts = "--certs-dir=/run/dcos/pki/cockroach --host={}".format(my_ip)
        cmd = "SHOW CLUSTER SETTING diagnostics.reporting.enabled;"
        out = subprocess.check_output(
            "sudo /opt/mesosphere/bin/cockroach sql {opts} -e '{cmd}'".format(opts=opts, cmd=cmd),
            shell=True).decode('utf-8')
        assert "false" in out


def clean_test_znode(zk: KazooClient, zk_path: str) -> None:
    """
    Ensures the ZNode at `zk_path` exists and is empty.
    """
    contender_id = gen_contender_id()
    with register._zk_lock(
            zk=zk,
            lock_path=register.ZK_LOCK_PATH,
            contender_id=contender_id,
            timeout=register.ZK_LOCK_TIMEOUT):
        # Create the ZNode if it doesn't already exist.
        try:
            zk.create(zk_path)
        except kazoo.exceptions.NodeExistsError:
            pass
        zk.set(zk_path, b'')


def creds_from_file(secret_file: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Read the ZooKeeper username and secret from `secret_file`.

    Args:
        secret_file (str):
            The path to a file containing zookeeper credentials
            in KEY=value format. The expected keys are
            `DATASTORE_ZK_USER` and `DATASTORE_ZK_SECRET`.

    Returns:
        (str, str):
            The username and secret to use for ZooKeeper authentication.
        (None, None):
            If the file does not exist or the credentials are not specified.
    """
    zk_user = None
    zk_secret = None
    if not os.path.exists(secret_file):
        return zk_user, zk_secret
    # sudo is required to read the credentials
    cmdline = ['sudo', 'cat', secret_file]
    contents = subprocess.check_output(
        cmdline,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        )
    for line in contents.split('\n'):
        fields = line.rstrip('\n').split('=')
        if fields[0] == 'DATASTORE_ZK_USER':
            zk_user = fields[1]
        if fields[0] == 'DATASTORE_ZK_SECRET':
            zk_secret = fields[1]
    return zk_user, zk_secret


def zk_connect() -> KazooClient:
    """
    Calls `register.zk_connect()` with the appropriate credentials.
    """
    zk_user, zk_secret = creds_from_file('/run/dcos/etc/cockroach')
    return register.zk_connect(zk_user=zk_user, zk_secret=zk_secret)


def gen_contender_id() -> str:
    return "test-contender-{}".format(str(uuid.uuid4()))


class TestCockroachLaunchScript:

    def test_zk_connect(self) -> None:
        """
        Test that `zk_connect()` returns properly authenticated
        ZooKeeper client that can be used to retrieve data from
        ZooKeeper.
        """
        zk = zk_connect()
        zk.sync(register.ZK_NODES_PATH)
        data, _ = zk.get(register.ZK_NODES_PATH)
        # As the integration tests only run once the cluster is
        # healthy we expect the list of masters to be populated.
        assert data, "The cockroach `ZK_NODES_PATH` ZNode is empty"

    def test_zk_lock(self) -> None:
        """
        Test that _zk_lock can only be called by one client at a time.

        It does so by trying to acquire the ZK lock while holding it.
        """
        contender_id1 = gen_contender_id()
        contender_id2 = gen_contender_id()
        zk1 = zk_connect()
        zk2 = zk_connect()

        with register._zk_lock(
                zk=zk1,
                lock_path=register.ZK_LOCK_PATH,
                contender_id=contender_id1,
                timeout=1,
                ):
            with pytest.raises(kazoo.exceptions.LockTimeout):
                with register._zk_lock(
                        zk=zk2,
                        lock_path=register.ZK_LOCK_PATH,
                        contender_id=contender_id2,
                        timeout=1,
                        ):
                    pass

    def test_get_registered_nodes(self) -> None:
        """
        Test that a `_get_registered_nodes` returns a list of registered nodes.
        """
        zk = zk_connect()
        test_path = register.ZK_PATH + "/test-nodes"
        contender_id = gen_contender_id()
        # Remove any stale testing data.
        clean_test_znode(zk=zk, zk_path=test_path)
        # Assert that there aren't any registered nodes.
        nodes = register._get_registered_nodes(zk=zk, zk_path=test_path)
        assert nodes == []
        # Populate the ZNode.
        expected = ["10.10.10.10"]
        with register._zk_lock(
                zk=zk,
                lock_path=register.ZK_LOCK_PATH,
                contender_id=contender_id,
                timeout=register.ZK_LOCK_TIMEOUT):
            zk.set(test_path, json.dumps({"nodes": expected}).encode("ascii"))
            zk.sync(test_path)
        # Assert that there is now one registered node.
        nodes = register._get_registered_nodes(zk=zk, zk_path=test_path)
        assert nodes == expected

    def test_register_cluster_membership(self) -> None:
        """
        Test that `_register_cluster_membership` correctly registers the node.
        """
        zk = zk_connect()
        test_path = register.ZK_PATH + "/test-nodes"
        ip = "10.10.10.10"
        # Remove any stale testing data.
        clean_test_znode(zk=zk, zk_path=test_path)
        # Assert that there aren't any registered nodes.
        nodes = register._get_registered_nodes(zk=zk, zk_path=test_path)
        assert nodes == []
        register._register_cluster_membership(
            zk=zk,
            zk_path=test_path,
            ip=ip)
        # Assert that the node was registered.
        nodes = register._get_registered_nodes(zk=zk, zk_path=test_path)
        assert nodes == [ip]
        # Check that the function is idempotent by confirming that the
        # node is still registered and appears exactly once in the
        # list of registered nodes.
        register._register_cluster_membership(
            zk=zk,
            zk_path=test_path,
            ip=ip)
        nodes = register._get_registered_nodes(zk=zk, zk_path=test_path)
        assert nodes == [ip]
