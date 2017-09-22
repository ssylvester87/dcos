"""
Test CockroachDB.
"""


import subprocess

from dcos_internal_utils.utils import detect_ip


def _master_count():
    with open("/opt/mesosphere/etc/master_count", encoding='utf-8') as f:
        return int(f.read())


class TestCockroach:

    def test_admin_ui_superuser(self, superuser_api_session):
        r = superuser_api_session.get("/cockroachdb/", allow_redirects=False)
        assert r.status_code == 200

    def test_admin_ui_peteruser(self, peter_api_session):
        r = peter_api_session.get("/cockroachdb/", allow_redirects=False)
        assert r.status_code == 403

    def test_admin_ui_noauth(self, noauth_api_session):
        r = noauth_api_session.get("/cockroachdb/", allow_redirects=False)
        assert r.status_code == 401

    def test_cluster_ensemble(self):
        """Test that all the CockroachDB instances have joined the cluster.

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

    def test_diagnostics_disabled(self):
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
