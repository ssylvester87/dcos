# -*- coding: utf-8 -*-
# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


"""
Test Cosmos.
"""


import logging

import pytest
import requests


from dcostests import Url


log = logging.getLogger(__name__)


# NOTE(jp): currently returns a 502
@pytest.mark.skip
def test_if_we_have_capabilities(peter):

    headers = peter.authheader.copy()
    headers.update({
        'Accept': 'application/vnd.dcos.capabilities+json;charset=utf-8;version=v1'
        })

    r = requests.get(
        Url('/capabilities'),
        headers=headers
        )
    assert r.status_code == 200
    assert {'name': 'PACKAGE_MANAGEMENT'} in r.json()['capabilities']
