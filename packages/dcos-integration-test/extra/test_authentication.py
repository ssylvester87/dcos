# -*- coding: utf-8 -*-
# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
Test authentication behavior of various components.
"""


import logging

import pytest
import requests

from dcostests import Url, IAMUrl, dcos


log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.security,
    pytest.mark.skipif(
        not pytest.config.getoption('expect_strict_security'),
        reason=("Authentication tests skipped: currently adjusted to strict security mode")
        )
    ]

# Specify URLs that are expected to require authentication.
component_urls = [
    IAMUrl('/users'),
    Url(host=dcos.masters[0], port=8443, path="/v2/apps"),
    Url(host=dcos.masters[0], port=9443, path="/v1/jobs"),
    Url(host=dcos.masters[0], port=5050, path="/flags"),
    Url(host=dcos.agents[0], port=5051, path="/flags"),
    Url(host=dcos.agents[0], port=61002, path="/system/health/v1")
    ]


component_urls = [str(u) for u in component_urls]


@pytest.mark.parametrize("url", component_urls)
def test_component_auth_direct_no_auth(url):

    r = requests.get(url)
    assert r.status_code == 401
    assert r.headers['WWW-Authenticate'] == 'acsjwt'


@pytest.mark.parametrize("url", component_urls)
def test_component_auth_direct_forged_token(url, forged_superuser_authheader):

    r = requests.get(url, headers=forged_superuser_authheader)

    # Marathon is currently expected to return a 503.
    if '8443' in url:
        assert r.status_code == 503
        return

    assert r.status_code == 401
    assert r.headers['WWW-Authenticate'] == 'acsjwt'


@pytest.mark.parametrize("url", component_urls)
def test_component_auth_direct_peter(url, peter):

    r = requests.get(url, headers=peter.authheader)
    # Expect success or forbidden.
    try:
        r.raise_for_status()
    except:
        assert r.status_code == 403
