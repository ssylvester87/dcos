# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

import copy
import pytest
import requests

from generic_test_code import (
    assert_endpoint_response,
    assert_iam_queried_for_uid_and_rid,
    generic_upstream_headers_verify_test,
    verify_header,
)
from util import LineBufferFilter, SearchCriteria


acl_endpoints = [
    ('/system/health/v1/foo/bar', 'dcos:adminrouter:ops:system-health'),
    ('/system/v1/metrics/foo/bar', 'dcos:adminrouter:ops:system-metrics'),
    ('/system/v1/logs/v1/foo/bar', 'dcos:adminrouter:ops:system-logs'),
]


class TestLogsEndpointEE:

    def test_logs_authn_endpoint(
            self, agent_ar_process, valid_user_header):
        """Tests endpoint that skips ACL validation and grants access to any
           authenticated user to a specific `stream` or `range` requests
        """

        # Configuration should pass "X-Accel-Buffering" header to logs upstream
        accel_buff_header = {"X-Accel-Buffering": "TEST"}

        req_headers = copy.deepcopy(valid_user_header)
        req_headers.update(accel_buff_header)

        url = (
            '/system/v1/logs/v1'
            '/stream/framework/test/executor/test/container/test'
            )

        # We're asserting for a valid HTTP and also for specific auditlog
        # message that is produced if request hits a authn only NGINX location
        # configuration that forwards request to the logs upstream.
        filter_regexp = {
            'type=audit .*' +
            'object=dcos:adminrouter:ops:system-logs .*' +
            'result=allow .*' +
            'reason="authenticated \(all users are allowed to access\)" .*' +
            'request_uri=' + url: SearchCriteria(1, True),
            }
        lbf = LineBufferFilter(
            filter_regexp,
            line_buffer=agent_ar_process.stderr_line_buffer
            )

        with lbf:
            generic_upstream_headers_verify_test(
                agent_ar_process,
                req_headers,
                url,
                assert_headers=accel_buff_header,
                )

        assert lbf.extra_matches == {}


class TestAuthEnforcementEE:

    @pytest.mark.parametrize("path,rid", acl_endpoints)
    def test_if_unauthn_user_is_forbidden_access(
            self,
            mocker,
            agent_ar_process,
            path,
            rid,
            ):
        log_messages = {
            'type=audit .*' +
            'object={} .*'.format(rid) +
            'result=deny .*' +
            'reason="not authenticated" .*' +
            'request_uri=' + path: SearchCriteria(1, True),
            }

        assert_endpoint_response(
            agent_ar_process, path, 401, assert_stderr=log_messages)

    @pytest.mark.parametrize("path,rid", acl_endpoints)
    def test_if_authorized_user_is_allowed_for_location(
            self,
            agent_ar_process,
            valid_user_header,
            path,
            rid,
            mocker,
            ee_static_files):

        log_messages = {
            'UID from valid JWT: `bozydar`': SearchCriteria(1, True),
            'type=audit .*' +
            'object={} .*'.format(rid) +
            'result=allow .*' +
            'reason="Bouncer PQ response" .*' +
            'request_uri=' + path: SearchCriteria(1, True),
            }

        with assert_iam_queried_for_uid_and_rid(mocker, 'bozydar', rid):
            assert_endpoint_response(
                agent_ar_process,
                path,
                200,
                assert_stderr=log_messages,
                headers=valid_user_header
                )

    @pytest.mark.parametrize("path,rid", acl_endpoints)
    def test_if_unauthorized_user_is_forbidden_access(self,
                                                      agent_ar_process,
                                                      valid_user_header,
                                                      path,
                                                      rid,
                                                      mocker,
                                                      ee_static_files,
                                                      iam_deny_all):
        log_messages = {
            'UID from valid JWT: `bozydar`': SearchCriteria(1, True),
            'type=audit .*' +
            'object={} .*'.format(rid) +
            'result=deny .*' +
            'reason="Bouncer PQ response" .*' +
            'request_uri=' + path: SearchCriteria(1, True),
            }

        with assert_iam_queried_for_uid_and_rid(mocker, 'bozydar', rid):
            assert_endpoint_response(
                agent_ar_process,
                path,
                403,
                assert_stderr=log_messages,
                headers=valid_user_header
                )

    @pytest.mark.parametrize("path,rid", acl_endpoints)
    def test_if_internal_policyquery_sends_service_auth_token_to_upstream(
            self,
            agent_ar_process,
            valid_user_header,
            path,
            rid,
            mocker,
            ):
        mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='record_requests',
            )

        requests.get(
            agent_ar_process.make_url_from_path(path),
            headers=valid_user_header
            )

        last_request = mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='get_recorded_requests',
            )[-1]

        # Check that service token has been passed to upstream instead of
        # valid_user_header auth token
        verify_header(
            last_request["headers"], "Authorization", "token={}".format(
                agent_ar_process.env["SERVICE_AUTH_TOKEN"]
                )
            )

    @pytest.mark.parametrize("path,rid", acl_endpoints)
    def test_if_internal_policyquery_doesnt_send_custom_headers_to_upstream(
            self,
            agent_ar_process,
            valid_user_header,
            path,
            rid,
            mocker,
            ):
        mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='record_requests',
            )

        # Create headers that contain valid authorization token and custom
        # header
        headers = {"CUSTOM_HEADER": "CUSTOM_VALUE"}
        headers.update(valid_user_header)
        requests.get(
            agent_ar_process.make_url_from_path(path),
            headers=headers
            )

        last_request = mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='get_recorded_requests',
            )[-1]

        header_names = set(map(lambda h: h[0], last_request["headers"]))
        assert "CUSTOM_HEADER" not in header_names
