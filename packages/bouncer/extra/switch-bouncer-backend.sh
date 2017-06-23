#!/usr/bin/env bash

set -e

usage="
Usage: $(basename "$0") [zookeeper|cockroachdb]

Switch the bouncer datastore between ZooKeeper and CockroachDB.

The switch will only take effect when the master node is rebooted. This change
applies only to the master node this command is run on. Any data in the current
backend will be unavailable in the new backend. It does not get removed from the
current backend so if you switch back your current data will be available once
again.

While some masters run the current backend and some the new backend the IAM can
return inconsistent data. For this reason you must take care not to switch
backends after having modified the default IAM state as created during cluster
bootstrap.

This script is intended to be run as follows (to switch from CockroachDB to
ZooKeeper):

1. The DC/OS cluster is installed.
2. Before performing any manual IAM modifications such as creating users or
   changing your default password, perform the following on every master node,
   one at a time.
2.1 Log into the master server.
2.2 Run 'switch-bouncer-backend.sh zookeeper'
2.3 Reboot the server
2.4 Wait for the server to boot and report being healthy.
2.5 Proceed to switch the next master node.
"

case "$1" in
    -h|--help) echo "$usage"; exit 0;;
    zookeeper)
        echo "Creating /var/lib/dcos/bouncer-legacy"
        touch /var/lib/dcos/bouncer-legacy
        echo "IAM configured to use ZooKeeper backend on next boot."
        exit 0
        ;;
    cockroachdb)
        echo "Removing /var/lib/dcos/bouncer-legacy"
        rm -f /var/lib/dcos/bouncer-legacy
        echo "IAM configured to use CockroachDB backend on next boot."
        exit 0
        ;;
    *)
        echo "Unexpected argument \`$1'"
        echo "$usage"
        exit 1
        ;;
esac
