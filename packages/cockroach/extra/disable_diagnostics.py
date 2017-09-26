#!/usr/bin/env python

"""
Disable reporting of anonymous diagnostics to cockroachlabs.

By default CockroachDB reports anonymous statistics on an hourly basis.
This can be prevented by launching CockroachDB with the
`COCKROACH_SKIP_ENABLING_DIAGNOSTIC_REPORTING=true` environment variable
set when the cluster is first initialized.

If the cluster has already been initialized the reporting can be disabled
by executing `SET CLUSTER SETTING diagnostics.reporting.enabled = false;`
using the CockroachDB sql cli.

This file exists to disable reporting in clusters that are being
upgraded from a previous version of DC/OS where the environment variable
was not present.

This file can be removed in the next version of DC/OS as clusters
running an older 1.10 release will have to upgrade to the release
containing this upgrade step before proceeding to upgrade beyond it
to newer versions. Clusters upgrading from 1.9 will upgrade straight
to a cluster where the afore-mentioned environment variable ensures
that diagnostics are disabled when the CockroachDB cluster is first
initialized.

See
https://jira.mesosphere.com/browse/DCOS-18405
https://jira.mesosphere.com/browse/DCOS-18832
https://jira.mesosphere.com/browse/DCOS-18833
"""

import logging
import subprocess

from dcos_internal_utils import utils


log = logging.getLogger(__name__)


# TODO(gpaul): Remove this file after it ships in a release.
# See https://jira.mesosphere.com/browse/DCOS-18833


def _disable_diagnostics_reporting(ip):
    cockroach_args = [
        '/opt/mesosphere/active/cockroach/bin/cockroach',
        'sql',
        '--certs-dir=/run/dcos/pki/cockroach',
        '--host={}'.format(ip),
        '-e',
        'SET CLUSTER SETTING diagnostics.reporting.enabled = false;',
        ]
    log.info("Disabling diagnostic reporting: {}".format(' '.join(cockroach_args)))
    subprocess.check_call(cockroach_args)
    log.info("Disabled diagnostic reporting.")


def main():
    logging.basicConfig(format='[%(levelname)s] %(message)s', level='INFO')

    # Determine our internal IP.
    my_ip = utils.detect_ip()
    log.info("My IP is `{}`".format(my_ip))

    # Disable diagnostics reporting
    _disable_diagnostics_reporting(my_ip)


if __name__ == '__main__':
    main()
