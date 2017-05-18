from pathlib import Path
from typing import List
from urllib.parse import urljoin

import pytest
import requests

from dcos_e2e.cluster import Cluster


class TestCustomCACert:
    """
    Tests for using custom CA certificates.
    """

    @pytest.fixture()
    def test_filenames(self) -> List[str]:
        """
        We run various integration test files.
        We only run the fastest files, and those specifically related to
        CA certificates.

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
            'test_authentication.py',
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
    def test_custom_ca_cert(self, fixture_dir: str,
                            test_filenames: List[str]) -> None:
        """
        It is possible to add a custom CA certificate to a cluster in strict
        mode.

        This test performs various checks with various CA certificate / key /
        chain combinations to confirm that the custom CA certificate files are
        being used.

        To add a parameter to this test, create a directory in the `fixtures`
        directory. This must contain the following two files:
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

        cert = cert_dir_on_host / cert_filename
        ca_key = cert_dir_on_host / key_filename
        chain = cert_dir_on_host / chain_filename

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
            cert: installer_cert_path,
            ca_key: installer_key_path,
        }
        if chain.exists():
            config['ca_certificate_chain_path'] = str(installer_chain_path)
            files_to_copy_to_installer[chain] = installer_chain_path

        with Cluster(
                destroy_on_error=False,
                log_output_live=True,
                extra_config=config,
                custom_ca_key=ca_key.absolute(),
                files_to_copy_to_installer=files_to_copy_to_installer,
        ) as cluster:
            cluster.run_integration_tests(pytest_command=[
                'pytest', '-vvv', '-s', '-x', ' '.join(test_filenames)
            ])

            # We then check that we can get a file over HTTPS, using the
            # custom certificate.
            # This verifies that our custom certificate is being used
            # correctly in DC/OS.
            ca_bundle_path = chain if chain.exists() else cert
            (master, ) = cluster.masters
            master_url = 'https://{ip_address}/'.format(
                ip_address=master.ip_address)
            requests.get(master_url, verify=str(ca_bundle_path))

            # This tests that Admin Router is serving the correct certificate.
            # It shows that the certificate is in the expected location.
            cert_url = urljoin(master_url, '/ca/dcos-ca.crt')
            certificate = requests.get(cert_url, verify=str(ca_bundle_path))
            certificate.raise_for_status()
            with ca_bundle_path.open() as ca_bundle:
                assert certificate.text in ca_bundle.read()
