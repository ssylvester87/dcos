# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

import logging

import pytest
import requests

from util import GuardedSubprocess, LineBufferFilter, SearchCriteria

log = logging.getLogger(__name__)


class TestAuthModuleDisablingAgent:
    # Basically the same as TestAuthModuleDisablingMaster, but testing if agent
    # auth is also disabled.
    @pytest.mark.parametrize(
        "enable_keyword",
        ["enabled", "true", "yes", "of_course", "make it so!",
         "disabled", "no", "no way", "please no"])
    def test_if_auth_module_is_enabled_by_unless_false_str_is_provided(
            self, nginx_class, mocker, enable_keyword):
        filter_regexp = {
            'Activate authentication module.': SearchCriteria(1, True),
        }
        ar = nginx_class(auth_enabled=enable_keyword, role='agent')
        url = ar.make_url_from_path('/system/health/v1/foo/bar')

        with GuardedSubprocess(ar):
            lbf = LineBufferFilter(filter_regexp,
                                   line_buffer=ar.stderr_line_buffer)

            resp = requests.get(url,
                                allow_redirects=False)

            assert resp.status_code == 401
            lbf.scan_log_buffer()

        assert lbf.extra_matches == {}

    def test_if_auth_module_can_be_disabled(self, nginx_class, mocker):
        filter_regexp = {
            ("ADMINROUTER_ACTIVATE_AUTH_MODULE set to `false`. "
             "Deactivate authentication module."): SearchCriteria(1, True),
        }
        ar = nginx_class(auth_enabled='false', role='agent')
        url = ar.make_url_from_path('/system/health/v1/foo/bar')

        with GuardedSubprocess(ar):
            lbf = LineBufferFilter(filter_regexp,
                                   line_buffer=ar.stderr_line_buffer)

            resp = requests.get(url,
                                allow_redirects=False)

            assert resp.status_code == 200
            lbf.scan_log_buffer()

        assert lbf.extra_matches == {}
