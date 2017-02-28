# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

import pytest

from generic_test_code import (
    generic_correct_upstream_dest_test,
    generic_user_is_403_forbidden_test,
    generic_valid_user_is_permitted_test,
)
from util import LineBufferFilter, SearchCriteria

acl_endpoints = [
    ('/exhibitor', 'dcos:adminrouter:ops:exhibitor'),
    ('/system/health/v1', 'dcos:adminrouter:ops:system-health'),
    ('/system/v1/logs/v1', 'dcos:adminrouter:ops:system-logs'),
    ('/system/v1/metrics', 'dcos:adminrouter:ops:system-metrics'),
]

authed_endpoints = [
    ('/secrets/v1', 'dcos:adminrouter:secrets'),
    ('/capabilities', 'dcos:adminrouter:capabilities'),
    ('/navstar/lashup/key', 'dcos:adminrouter:navstar-lashup-key'),
    ('/system/v1/agent/de1baf83-c36c-4d23-9cb0-f89f596cd6ab-S1/logs/v1',
     'dcos:adminrouter:system:agent'),
    ('/system/v1/agent/de1baf83-c36c-4d23-9cb0-f89f596cd6ab-S1/metrics/v0',
     'dcos:adminrouter:system:agent'),
    ('/system/v1/leader/marathon',
     'dcos:adminrouter:system:leader:marathon'),
    ('/system/v1/leader/mesos',
     'dcos:adminrouter:system:leader:mesos'),
]


class TestAuthEnforcementEE():
    @pytest.mark.parametrize("path,rid", acl_endpoints)
    def test_if_unknown_user_is_forbidden_access(self,
                                                 master_ar_process,
                                                 invalid_user_header,
                                                 path,
                                                 rid):
        test_path = path + "/foo/bar"
        filter_regexp = {
            'UID from valid JWT: `foobar`': SearchCriteria(1, True),
            'type=audit .*' +
            'object={} .*'.format(rid) +
            'result=deny .*' +
            'reason="Bouncer PQ response" .*' +
            'request_uri=' + test_path: SearchCriteria(1, True),
            }
        lbf = LineBufferFilter(
            filter_regexp,
            line_buffer=master_ar_process.stderr_line_buffer
        )
        with lbf:
            generic_user_is_403_forbidden_test(master_ar_process,
                                               invalid_user_header,
                                               test_path)
        assert lbf.extra_matches == {}

    @pytest.mark.parametrize("path,rid", acl_endpoints)
    def test_if_granting_rid_grants_access(self,
                                           master_ar_process,
                                           valid_user_header,
                                           path,
                                           rid,
                                           mocker):
        test_path = path + "/foo/bar"
        filter_regexp = {
            'UID from valid JWT: `bozydar`': SearchCriteria(1, True),
            'type=audit .*' +
            'object={} .*'.format(rid) +
            'result=deny .*' +
            'reason="Bouncer PQ response" .*' +
            'request_uri=' + test_path: SearchCriteria(1, True),
            }
        lbf = LineBufferFilter(
            filter_regexp,
            line_buffer=master_ar_process.stderr_line_buffer
        )
        with lbf:
            generic_user_is_403_forbidden_test(master_ar_process,
                                               valid_user_header,
                                               test_path)

        assert lbf.extra_matches == {}

        perm_info = {"uid": "bozydar",
                     "rid": rid,
                     "action": "full",
                     }

        mocker.send_command(endpoint_id='http://127.0.0.1:8101',
                            func_name='grant_permission',
                            aux_data=perm_info)

        filter_regexp = {
            'UID from valid JWT: `bozydar`': SearchCriteria(1, True),
            'type=audit .*' +
            'object={} .*'.format(rid) +
            'result=allow .*' +
            'reason="Bouncer PQ response" .*' +
            'request_uri=' + test_path: SearchCriteria(1, True),
            }
        lbf = LineBufferFilter(
            filter_regexp,
            line_buffer=master_ar_process.stderr_line_buffer
        )
        with lbf:
            generic_valid_user_is_permitted_test(master_ar_process,
                                                 valid_user_header,
                                                 test_path)

        assert lbf.extra_matches == {}

    @pytest.mark.parametrize("path,rid", authed_endpoints)
    def test_if_known_user_is_permitted_access(self,
                                               master_ar_process,
                                               valid_user_header,
                                               path,
                                               rid):
        test_path = path + "/foo/bar"
        filter_regexp = {
            'UID from valid JWT: `bozydar`': SearchCriteria(1, True),
            'type=audit .*' +
            'object={} .*'.format(rid) +
            'result=allow .*' +
            'reason="authenticated \(all users are allowed to access\)" .*' +
            'request_uri=' + test_path: SearchCriteria(1, True),
            }
        lbf = LineBufferFilter(
            filter_regexp,
            line_buffer=master_ar_process.stderr_line_buffer
        )
        with lbf:
            generic_valid_user_is_permitted_test(master_ar_process,
                                                 valid_user_header,
                                                 test_path)

        assert lbf.extra_matches == {}


class TestHealthEndpointEE():
    def test_if_request_is_sent_to_correct_upstream(self,
                                                    master_ar_process,
                                                    superuser_user_header):

        generic_correct_upstream_dest_test(master_ar_process,
                                           superuser_user_header,
                                           '/system/health/v1/foo/bar',
                                           'http:///run/dcos/3dt.sock',
                                           )
