#!/usr/bin/env python

"""Start CockroachDB.

CockroachDB clusters need to be bootstrapped.

This is done by starting the very first node without the
--join=<ip1,ip2,...,ipN> parameter. Once bootstrapped, no node must ever be
started without the --join parameter again.

This poses an interesting problem for us as it means we need to know whether a
cluster has been bootstrapped before, from any of the masters in the cluster.

Additionally, once a cluster has been bootstrapped by starting a node in this
"initial master mode" all subsequent nodes need to be started with one or more
peers' IP addresses provided to them via the --join<ip1,ip2,...,ipN> parameter.

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

2. Take and hold a lock on a ZNode reserved for purposes of CockroachDB node
discovery.

3. Determine whether any CockroachDB instance has already been launch and
bootstrapped.

4. If false, start CockroachDB without the --join=... parameter to initialize
the new cluster.

5. If true, read the list of IP addresses of nodes that have previously (at some
point) joined the cluster and start the server, passing those peers' IP
addresses to --join=....

6. Wait for the CockroachDB instance to start, then add it's local IP to
the ZNode if it hasn't been added already.

7. Release the lock.

See https://jira.mesosphere.com/browse/DCOS-16183.

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


zk_path = "/cockroach"
zk_lock_path = zk_path + "/lock"
zk_nodes_path = zk_path + "/nodes"


@contextmanager
def _zk_lock(zk, lock_path, contender_id, timeout):
    """This contextmanager takes a ZooKeeper lock, yields, then releases the lock."""
    lock = zk.Lock(lock_path, contender_id)
    try:
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
        log.info("Acquired lock")
    yield
    log.info("Releasing Lock")
    lock.release()


def _get_registered_nodes(zk):
    """Load a list of previously initialized nodes from ZooKeeper.

    Returns:
        A list of internal IP addresses.
    """
    # Load a list of previously initialized nodes.
    data, _ = zk.get(zk_nodes_path)
    if data:
        log.info("Cluster was previously initialized")
        nodes = json.loads(data.decode("utf-8"))['nodes']
    else:
        nodes = []
    return nodes


def main():
    logging.basicConfig(format='[%(levelname)s] %(message)s', level='INFO')

    log.info("Connecting to ZooKeeper.")
    zk = zk_connect()

    # We are finally connected to ZooKeeper.
    # We now take the lock to determine whether somewhere in the cluster the DB
    # has already been initialized.
    lock_contender_id = "{hostname}:{pid}".format(
        hostname=socket.gethostname(),
        pid=os.getpid(),
        )

    # This lock needs to be held around the entire cockroachdb startup procedure
    # as only the first instance should start without the --join parameter and
    # thereby bootstrap the cluster. This lock prevents multiple instances from
    # starting without --join at the same time.
    with _zk_lock(zk=zk, lock_path=zk_lock_path, contender_id=lock_contender_id, timeout=5):
        nodes = _get_registered_nodes(zk)
        my_ip = utils.detect_ip()

        cockroach_args = [
            '/opt/mesosphere/active/cockroach/bin/cockroach',
            'start',
            '--logtostderr',
            '--cache=100MiB',
            '--store=/var/lib/dcos/cockroach',
            '--certs-dir=/run/dcos/pki/cockroach',
            '--advertise-host={}'.format(my_ip),
            '--host={}'.format(my_ip),
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
            cockroach_args.append('--join={}'.format(','.join(nodes)))

        # Due to the `--background` argument this will block until the process
        # is ready to accept connections.
        log.info("Starting CockroachDB")
        subprocess.check_call(cockroach_args, stderr=sys.stderr, stdout=sys.stdout)
        log.info("Started CockroachDB")

        # Now that CockroachDB has started successfully we add our IP to the
        # list of nodes that have successfully joined the cluster at one stage
        # or another.
        if my_ip not in nodes:
            nodes.append(my_ip)
            zk.set(zk_nodes_path, json.dumps({"nodes": nodes}).encode("utf-8"))
            zk.sync(zk_nodes_path)


if __name__ == '__main__':
    main()
