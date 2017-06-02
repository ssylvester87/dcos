import os
from pathlib import Path

import pytest

from dcos_e2e.backends._dcos_docker import DCOS_Docker


@pytest.fixture(scope='session')
def dcos_docker_backend():
    """
    Creates common DCOS_Docker_Backend factory that works within pytest
    environment directory.
    """
    generate_config_path = Path(os.environ['DCOS_E2E_GENCONF_PATH'])
    assert generate_config_path.exists() and generate_config_path.is_file()

    dcos_docker_path = Path(os.environ['DCOS_E2E_DCOS_DOCKER_PATH'])
    assert dcos_docker_path.exists() and dcos_docker_path.is_dir()

    tmp_dir_path = Path(os.environ['DCOS_E2E_TMP_DIR_PATH'])
    assert tmp_dir_path.exists() and tmp_dir_path.is_dir()

    return DCOS_Docker(
        generate_config_path=generate_config_path,
        dcos_docker_path=dcos_docker_path,
        workspace_path=tmp_dir_path,
        )
