#!/usr/bin/env python

"""Start CockroachDB.

CockroachDB clusters need to be bootstrapped.

This is done by starting the very first node without the
--join=<ip1,ip2,...,ipN> parameter. Once bootstrapped, no node must
ever be started without the --join parameter again, doing so would
initialize a new cluster causing the old cluster to be effectively
discarded.

This poses an interesting problem for us as it means we need to know whether a
cluster has been bootstrapped before, from any of the masters in the cluster.

Additionally, once a cluster has been bootstrapped by starting a node in this
"initial master mode" all subsequent nodes need to be started with one or more
peer IP addresses provided to them via the --join<ip1,ip2,...,ipN> parameter.

As this list of IPs is used for discovery through the gossip protocol, not all
the provided IP addresses actually need to be up or reachable (that would
introduce a chicken and egg problem, anyway.) An example bootstrap sequence
would be:

node1:
./cockroach

node2:
./cockroach --join=node1

node3:
./cockroach --join=node1,node2

Then, after any crashes or server reboots, any of these nodes can be started
with the following command and they will discover one another:

./cockroach --join=node1,node2,node3

Here we have used the hostname of the nodes (node1, node2, etc.) but for DC/OS
we would use the internal IP addresses of the master nodes instead.

CockroachDB also supports a --background parameter which starts the server in
daemon mode. It conveniently blocks until the server is started successfully and
is ready to accept connections.

The bootstrap and discovery strategy we designed is as follows:

1. Connect to ZooKeeper.

2. Determine whether the cluster has already been initialized by
  checking whether the list of IPs at `zk_nodes_path` exists. This
  does not require the lock to be held as nodes can only ever be
  added, never removed: if the list of IPs at `zk_nodes_path` is
  non-empty, we know the cluster has been bootstrapped.

3. If the list is empty:

3.1 Take and hold the ZK lock.

3.2 Check the `zk_nodes_path` again to ensure the value hasn't been
    updated since we checked it in step 2.

3.3 If it is now non-empty goto step 4 as the cluster has since been initialized.

3.4 If it is still empty, we need to bootstrap the cluster.

3.5 Start CockroachDB without the --join=... parameter to initialize
    the new cluster.

3.6 Add the current node's IP address to the list at `zk_nodes_path`.

3.7 Release the lock and exit 0.

4. If `zk_nodes_path` is non-empty:

4.1 If our IP is not yet in the list, briefly take the ZK lock and add
    our IP to ZK. Release the lock.

4.2 Start CockroachDB with the --join=... parameter set to IPs listed
    in `zk_nodes_path`.

4.3 Once CockroachDB has started with the '--background' passed to it,
    exit 0.

See
https://jira.mesosphere.com/browse/DCOS-16183 and then
https://jira.mesosphere.com/browse/DCOS-17886


Note that for long-running processes using Kazoo and especially Kazoo's lock
recipe it is recommended to add a connection state change event handler that
takes care of communicating the current connection state to the rest of the
application so that it can respond to it (which enables e.g. delayed lock
release). This process here , however, is shortlived. Errors that occur during
ZooKeeper interaction lead to an application crash. In that case (when this
program exits with a non-zero exit code) the outer systemd wrapper makes sure
that potentially orphaned child processes (CockroachDB!) are killed and reaped.

"""

import json
import logging
import os
import socket
import subprocess
import sys

from contextlib import contextmanager

from kazoo.client import KazooClient
from kazoo.exceptions import (
    ConnectionLoss,
    LockTimeout,
    SessionExpiredError,
)
from kazoo.retry import KazooRetry
from kazoo.security import make_digest_acl

from dcos_internal_utils import utils


log = logging.getLogger(__name__)


def zk_connect():
    """Connect to ZooKeeper.

    The ZooKeeper user is read from the `DATASTORE_ZK_USER` environment variable if it is present.
    The ZooKeeper secret is read from the `DATASTORE_ZK_SECRET` environment variable if it is present.

    On connection failure, the function attempts to reconnect indefinitely with exponential backoff
    up to 3 seconds. If a command fails, that command is retried every 300ms for 3 attempts before failing.

    These values are chosen to suit a human-interactive time.

    Returns:
        A ZooKeeper client connection in the form of a `kazoo.client.KazooClient`.
    """
    # Try to reconnect indefinitely, with time between updates going
    # exponentially to ~3s. Then every retry occurs every ~3 seconds.
    conn_retry_policy = KazooRetry(
        max_tries=-1,
        delay=0.3,
        backoff=1.3,
        max_jitter=1,
        max_delay=3,
        ignore_expire=True,
        )
    # Retry commands every 0.3 seconds, for a total of <1s (usually 0.9)
    cmd_retry_policy = KazooRetry(
        max_tries=3,
        delay=0.3,
        backoff=1,
        max_jitter=0.1,
        max_delay=1,
        ignore_expire=False,
        )
    default_acl = None
    auth_data = None
    zk_user = os.environ.get('DATASTORE_ZK_USER')
    zk_secret = os.environ.get('DATASTORE_ZK_SECRET')
    if zk_user and zk_secret:
        default_acl = [make_digest_acl(zk_user, zk_secret, all=True)]
        scheme = 'digest'
        credential = "{}:{}".format(zk_user, zk_secret)
        auth_data = [(scheme, credential)]
    zk = KazooClient(
        hosts="127.0.0.1:2181",
        timeout=30,
        connection_retry=conn_retry_policy,
        command_retry=cmd_retry_policy,
        default_acl=default_acl,
        auth_data=auth_data,
        )
    zk.start()
    return zk


# The prefix used for cockroachdb in ZK.
zk_path = "/cockroach"
# The path of the ZNode used for locking.
zk_lock_path = zk_path + "/lock"
# The path of the ZNode containing the list of cluster members.
zk_nodes_path = zk_path + "/nodes"
# The id to use when contending for the ZK lock.
lock_contender_id = "{hostname}:{pid}".format(
    hostname=socket.gethostname(),
    pid=os.getpid(),
    )


@contextmanager
def _zk_lock(zk, lock_path, contender_id, timeout):
    """This contextmanager takes a ZooKeeper lock, yields, then releases the lock."""
    lock = zk.Lock(lock_path, contender_id)
    try:
        log.info("Acquiring ZooKeeper lock.")
        lock.acquire(blocking=True, timeout=timeout)
    except (ConnectionLoss, SessionExpiredError) as e:
        msg_fmt = "Failed to acquire lock: {}"
        msg = msg_fmt.format(e.__class__.__name__)
        log.exception(msg)
        raise e
    except LockTimeout as e:
        msg_fmt = "Failed to acquire lock in `{}` seconds"
        msg = msg_fmt.format(timeout)
        log.exception(msg)
        raise e
    else:
        log.info("ZooKeeper lock acquired.")
    yield
    log.info("Releasing ZooKeeper lock")
    lock.release()
    log.info("ZooKeeper lock released. ")


def _get_registered_nodes(zk):
    """
    Load a list of previously initialized nodes from ZooKeeper.

    The ZNode `zk_nodes_path` is expected to exist, having been
    created during cluster bootstrap.

    Args:
        zk (kazoo.client.KazooClient):
            The client to use to communicate with ZooKeeper.

    Returns:
        A list of internal IP addresses of nodes that have
        previously joined the CockroachDB cluster.
    """
    # We call `sync()` before reading the value in order to
    # read the latest data written to ZooKeeper.
    # See https://zookeeper.apache.org/doc/r3.1.2/zookeeperProgrammers.html#ch_zkGuarantees
    log.info("Calling sync() on ZNode `{}`".format(zk_nodes_path))
    zk.sync(zk_nodes_path)
    log.info("Loading data from ZNode `{}`".format(zk_nodes_path))
    data, _ = zk.get(zk_nodes_path)
    if data:
        log.info("Cluster was previously initialized.")
        nodes = json.loads(data.decode('ascii'))['nodes']
        log.info("Found registered nodes: {}".format(nodes))
        return nodes
    else:
        log.info("Found no registered nodes.")
        return []


def _start_cockroachdb(ip, nodes):
    """
    Starts CockroachDB listening on `ip`. If `nodes` is non-empty it
    will be passed as a comma-separated value of the `--join=`
    parameter.

    This function blocks until the CockroachDB instance is ready to
    accept new connections.

    Args:
        ip (str):
            The IP that CockroachDB should listen on.
            This should be the internal IP of the current host.
        nodes (list(str)):
            A list of IP addresses to try and connect to when
            joining the cluster.

    """
    cockroach_args = [
        '/opt/mesosphere/active/cockroach/bin/cockroach',
        'start',
        '--logtostderr',
        '--cache=100MiB',
        '--store=/var/lib/dcos/cockroach',
        '--certs-dir=/run/dcos/pki/cockroach',
        '--advertise-host={}'.format(ip),
        '--host={}'.format(ip),
        '--http-host=127.0.0.1',
        '--http-port=8090',
        '--pid-file=/run/dcos/cockroach/cockroach.pid',
        '--background',
    ]

    # If no nodes have ever been initialized we need to bootstrap
    # the CockroachDB cluster by running without the --join parameter.
    # If the cluster has been initialized previously, the list of
    # nodes will be non-empty and will contain a list of IP addresses
    # which we pass to `--join=`.
    if nodes:
        log.info("CockroachDB will join existing cluster: {}".format(nodes))
        cockroach_args.append('--join={}'.format(','.join(nodes)))
    else:
        log.info("CockroachDB will bootstrap new cluster.")

    # Due to the `--background` argument this will block until the process
    # is ready to accept connections.
    log.info("Starting CockroachDB: {}".format(' '.join(cockroach_args)))
    subprocess.check_call(cockroach_args, stderr=sys.stderr, stdout=sys.stdout)
    log.info("Started CockroachDB")


def _register_cluster_membership(zk, ip):
    """
    Add `ip` to the list of cluster members registered in ZooKeeper.

    The ZK lock must be held around the call to this function.

    Args:
        zk (kazoo.client.KazooClient):
            The client to use to communicate with ZooKeeper.
        ip (str):
            The ip to add to the list of cluster member IPs in ZooKeeper.
    """
    log.info("Registering cluster membership for `{}`".format(ip))
    # Get the latest list of cluster members.
    nodes = _get_registered_nodes(zk=zk)
    if ip in nodes:
        # We're already registered with ZK.
        log.info("Cluster member `{}` already registered in ZooKeeper. Skipping.".format(ip))
        return
    log.info("Adding `{}` to list of nodes `{}`".format(ip, nodes))
    nodes.append(ip)
    zk.set(zk_nodes_path, json.dumps({"nodes": nodes}).encode("ascii"))
    zk.sync(zk_nodes_path)
    log.info("Successfully registered cluster membership for `{}`".format(ip))


def _join_existing_cluster(zk, ip, nodes):
    """
    Add `ip` to the list of cluster members in ZK if it isn't already
    present then start CockroachDB as a member of the cluster.

    This function may briefly take the lock if it determines that `ip`
    is not listed in ZK yet.

    Args:
        zk (kazoo.client.KazooClient):
            The client to use to communicate with ZooKeeper.
        ip (str):
            The internal IP that CockroachDB will be listening on.
            This IP will be added to ZK if it is not already present.
        nodes (list(str)):
            A list of IPs of nodes whose CockroachDB instances form
            part of the cluster.
    """
    # If our IP is not already listed as part of the cluster, we
    # briefly take the lock to add our IP to the list of
    # cluster members, then release the lock.
    #
    # It is not important to hold the lock until cockroachdb
    # starts as the cluster has already been bootstrapped and the
    # gossip protocol used by cockroachdb tries all listed IPs and
    # needs only one of them to respond in order to join the
    # cluster, so if cockroachdb fails to start after we've
    # added our IP to ZK, that's OK.
    log.info("Joining existing cluster `{}` as `{}`.".format(nodes, ip))
    if ip not in nodes:
        with _zk_lock(zk=zk, lock_path=zk_lock_path, contender_id=lock_contender_id, timeout=5):
            _register_cluster_membership(zk=zk, ip=ip)
    # Start cockroachdb and tell it to join the existing cluster.
    _start_cockroachdb(ip=ip, nodes=nodes)


def main():
    logging.basicConfig(format='[%(levelname)s] %(message)s', level='INFO')

    # Determine our internal IP.
    my_ip = utils.detect_ip()
    log.info("My IP is `{}`".format(my_ip))

    # Connect to ZooKeeper.
    log.info("Connecting to ZooKeeper.")
    zk = zk_connect()
    # We are connected to ZooKeeper.

    # Determine whether the cluster has been bootstrapped already by
    # checking whether the `zk_nodes_path` ZNode has children. This is
    # best-effort as we aren't holding the lock, but we do call
    # `zk.sync()` which is supposed to ensure that we read the latest
    # value from ZK.
    nodes = _get_registered_nodes(zk=zk)
    if nodes:
        # The cluster has already been initialized. Join the cluster
        # and return. This may take the lock briefly while adding our
        # IP to ZK if it isn't there already.
        log.info("Cluster has members registered already.")
        _join_existing_cluster(zk=zk, ip=my_ip, nodes=nodes)
        return

    log.info("Found no existing cluster members registered in ZooKeeper.")
    # No cockroachdb nodes have been registered with ZK yet. We
    # assume that we need to bootstrap the cluster so we take the ZK
    # lock and hold it until the cluster is bootstrapped and our IP
    # has been successfully registered with ZK.
    #
    # The lock needs to be held around the entire cockroachdb startup
    # procedure as only the first instance should start without the
    # --join parameter (and thereby bootstrap the cluster.) This lock
    # prevents multiple instances from starting without --join at the
    # same time.
    with _zk_lock(zk=zk, lock_path=zk_lock_path, contender_id=lock_contender_id, timeout=5):
        # We check that the cluster hasn't been bootstrapped since we
        # first read the list of nodes from ZK.
        log.info("Checking for registered nodes while holding lock.")
        nodes = _get_registered_nodes(zk=zk)
        if nodes:
            # The cluster has been bootstrapped since we checked.
            # We'll join the existing cluster below.
            log.info("Cluster has been initialized.")
            pass
        else:
            log.info("Cluster has not been initialized yet.")
            # The cluster still has not been bootstrapped. We start
            # cockroachdb without a list of cluster IPs to join,
            # which will cause it to bootstrap the cluster.
            _start_cockroachdb(ip=my_ip, nodes=[])
            # Only now that CockroachDB has started successfully and
            # thus bootstrapped the cluster do we add our IP to the
            # list of nodes that have successfully joined the cluster
            # at one stage or another.
            #
            # If this fails, the cockroachdb instance will be killed
            # by systemd and the fact that a cluster was initialized
            # will be ignored by subsequent runs as our IP won't be
            # present in ZK.
            _register_cluster_membership(zk=zk, ip=my_ip)
            log.info("Successfully initialized cluster.")
            return

    # The cluster was bootstrapped by the time we checked the list of
    # registered nodes while holding the lock. We join the existing
    # cluster normally.
    _join_existing_cluster(zk=zk, ip=my_ip, nodes=nodes)


if __name__ == '__main__':
    main()
