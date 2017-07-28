"""
Tests for Exhibitor.
"""

import uuid
from pathlib import Path

import requests
from dcos_e2e.backends import ClusterBackend
from dcos_e2e.cluster import Cluster
from passlib.hash import sha512_crypt


class TestExhibitorAuth:
    """
    Tests for Exhibitor authentication.
    """

    def test_ui(
        self,
        dcos_docker_backend: ClusterBackend,
        artifact_path: Path,
    ):
        """
        Access to Exhibitor UI is authenticated.
        """

        superuser_username = str(uuid.uuid4())
        superuser_password = str(uuid.uuid4())
        exhibitor_admin_password = str(uuid.uuid4())
        config = {
            'superuser_username': superuser_username,
            # We can hash the password with any `passlib`-based method here.
            # We choose `sha512_crypt` arbitrarily.
            'superuser_password_hash': sha512_crypt.hash(superuser_password),
            'security': 'strict',
            'exhibitor_admin_password': exhibitor_admin_password,
        }

        with Cluster(
            log_output_live=True,
            extra_config=config,
            cluster_backend=dcos_docker_backend,
            generate_config_path=artifact_path,
        ) as cluster:
            cluster.wait_for_dcos()
            # Select single master as an endpoint for HTTP requests.
            master = next(iter(cluster.masters))
            exhibitor_base_url = 'http://' + str(master.ip_address) + ":8181"
            exhibitor_path = '/exhibitor/v1/ui/index.html'
            expected_ui_url = exhibitor_base_url + exhibitor_path

            auth_resp = requests.get(exhibitor_base_url, auth=('admin', exhibitor_admin_password))
            assert auth_resp.status_code == 200
            assert auth_resp.url == expected_ui_url

            noauth_resp = requests.get(exhibitor_base_url)
            assert noauth_resp.status_code == 401
            assert noauth_resp.headers['WWW-Authenticate'] == 'Basic realm="DCOS"'
