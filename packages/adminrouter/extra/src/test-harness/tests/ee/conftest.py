# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

"""This module provides fixtures that are specific to EE flavour."""

from collections import namedtuple
import json
import os
import textwrap

import pytest

# Example bootstrap config served by NGINX
BOOTSTRAP_CONFIG = json.dumps({
    "security": "strict",
    "ssl_enabled": True,
    })

# Represents a definition of a static file that is required by the NGINX
# configuration
_NginxStaticServedFile = namedtuple("NginxStaticServedFile", ["path", "content"])


def NginxStaticServedFile(path, content=None):
    return _NginxStaticServedFile(path=path, content=content)


EEStaticFiles = [
    NginxStaticServedFile(
        "/opt/mesosphere/active/acl-schema/etc/acl-schema.json",
        content="{}",
        ),
    NginxStaticServedFile(
        "/opt/mesosphere/etc/bootstrap-config.json",
        content=BOOTSTRAP_CONFIG,
        ),
]


@pytest.fixture(scope="session")
def ee_static_files():
    """Creates static files with stub content that are required for NGINX"""
    for static_file in EEStaticFiles:
        os.makedirs(os.path.dirname(static_file.path), exist_ok=True)
        with open(static_file.path, 'w') as f:
            f.write(static_file.content)
        os.chmod(static_file.path, 0o777)

    yield

    # Remove all created files
    for static_file in EEStaticFiles:
        os.unlink(static_file.path)


@pytest.fixture()
def iam_deny_all(mocker):
    """Modifies IAM mock configuration to deny all policyquery requests"""
    mocker.send_command(
        endpoint_id='http://127.0.0.1:8101',
        func_name='deny_all_queries',
        )


@pytest.fixture()
def iam_permit_all(mocker):
    """Modifies IAM mock configuration to deny all policyquery requests"""
    mocker.send_command(
        endpoint_id='http://127.0.0.1:8101',
        func_name='permit_all_queries',
        )
