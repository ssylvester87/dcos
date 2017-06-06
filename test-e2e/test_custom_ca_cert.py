import time
from pathlib import Path
from typing import List
from urllib.parse import urljoin

import pytest
import requests

from dcos_e2e.backends import ClusterBackend
from dcos_e2e.cluster import Cluster


class TestCustomCACert:
    """
    Tests for using custom CA certificates.
    """

    @pytest.fixture()
    def test_filenames(self) -> List[str]:
        """
        We run various integration test files.
        We run only tests that are related to custom CA certificates.

        Return a list of these filenames.
        """
        return [
            'test_tls.py',
            'test_permissions.py',
            'test_iam.py',
            # TODO: Enable when DCOS-15720 and DCOS-15649 are resolved.
            # 'test_dcoscli_enterprise.py',
            'test_clusterstate.py',
            'test_ca.py',
            # TODO: Enable MARATHON_EE-1489
            # 'test_authentication.py',
            'test_adminrouter.py',
        ]

    @pytest.mark.parametrize(
        'fixture_dir',
        [
            # TODO: Eliptic curve doesn't work yet (DCOS-15749)
            # When it does, add `ec` directories here.
            'rsa_intermediate',
            'rsa_root',
        ])
    def test_custom_ca_cert(
            self,
            fixture_dir: str,
            test_filenames: List[str],
            dcos_docker_backend: ClusterBackend,
    ) -> None:
        """
        It is possible to install cluster with custom CA certificate.

        This test performs various checks with various CA certificate / key /
        chain combinations to confirm that the custom CA certificate files are
        being used.

        To add new custom CA certificate test, create a directory in
        the `fixtures` directory. This must contain the following two files:
            * `dcos-ca-certificate.crt`
            * `dcos-ca-certificate-key.key`
        It can optionally include `dcos-ca-certificate-chain.crt`.
        Then add the name of this directory to the test parameters.

        The files in the fixture directory come from
        https://github.com/mesosphere/dcos-custom-ca-cert-configs.
        See that repository for details about the fixtures.
        """
        fixture_root = Path('fixtures')
        cert_dir_on_host = fixture_root / fixture_dir

        cert_filename = 'dcos-ca-certificate.crt'
        key_filename = 'dcos-ca-certificate-key.key'
        chain_filename = 'dcos-ca-certificate-chain.crt'

        cert_path = cert_dir_on_host / cert_filename
        ca_key_path = cert_dir_on_host / key_filename
        chain_path = cert_dir_on_host / chain_filename

        genconf = Path('/genconf')
        installer_cert_path = genconf / cert_filename
        installer_key_path = genconf / key_filename
        installer_chain_path = genconf / chain_filename

        # When the cluster configuration is generated / validated from the
        # configuration file, these paths will be checked for in the
        # installer container.
        config = {
            'security': 'strict',
            'ca_certificate_path': str(installer_cert_path),
            'ca_certificate_key_path': str(installer_key_path),
        }

        files_to_copy_to_installer = {
            cert_path: installer_cert_path,
            ca_key_path: installer_key_path,
        }
        if chain_path.exists():
            config['ca_certificate_chain_path'] = str(installer_chain_path)
            files_to_copy_to_installer[chain_path] = installer_chain_path

        with Cluster(
                destroy_on_error=False,
                log_output_live=True,
                extra_config=config,
                custom_ca_key=ca_key_path.absolute(),
                files_to_copy_to_installer=files_to_copy_to_installer,
                cluster_backend=dcos_docker_backend,
        ) as cluster:
            # Make this arbitrary sleep and let agents boot properly
            # Wait 5 mins
            # TODO(mh): Be smarther here
            time.sleep(5 * 60)

            cluster.run_integration_tests(pytest_command=[
                'pytest', '-vvv', '-s', '-x', ' '.join(test_filenames)
            ])
            # Select single master as an endpoint for HTTP requests.
            master = next(iter(cluster.masters))

            # We then check that we can get HTTPS response, while using
            # root CA certificate for TLS verification.
            # This verifies that our custom CA certificate was used for signing
            # the server certificate presented by Admin Router.
            ca_bundle_path = chain_path if chain_path.exists() else cert_path
            master_url = 'https://' + str(master._ip_address)
            requests.get(master_url, verify=str(ca_bundle_path))

            # This tests that Admin Router is serving custom CA root certificate
            # provided during the cluster installation.
            # It shows that the certificate is installed in the expected location.
            cert_url = urljoin(master_url, '/ca/dcos-ca.crt')
            certificate = requests.get(cert_url, verify=str(ca_bundle_path))
            certificate.raise_for_status()
            with ca_bundle_path.open() as ca_bundle:
                assert certificate.text in ca_bundle.read()
