import os
from pathlib import Path

import pytest

from dcos_e2e.backends import DCOS_Docker


@pytest.fixture()
def dcos_docker_backend():
    """
    Creates a common DCOS_Docker configuration that works within the pytest
    environment directory.
    """
    tmp_dir_path = Path(os.environ['DCOS_E2E_TMP_DIR_PATH'])
    assert tmp_dir_path.exists() and tmp_dir_path.is_dir()

    return DCOS_Docker(workspace_dir=tmp_dir_path)


@pytest.fixture()
def artifact_path():
    """
    Return the path to an enterprise artifact to test against.
    """
    generate_config_path = Path(os.environ['DCOS_E2E_GENCONF_PATH'])
    return generate_config_path
