# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

import pytest
import requests

from generic_test_code.common import (
    assert_endpoint_response,
    generic_response_headers_verify_test,
    generic_upstream_headers_verify_test,
    verify_header,
)
from generic_test_code.ee import assert_iam_queried_for_uid_and_rid
from util import LineBufferFilter, SearchCriteria, iam_denies_all_requests

acl_endpoints = [
    ('/system/health/v1/foo/bar', 'dcos:adminrouter:ops:system-health'),
    ('/system/v1/metrics/foo/bar', 'dcos:adminrouter:ops:system-metrics'),
    ('/system/v1/logs/foo/bar', 'dcos:adminrouter:ops:system-logs'),
    ('/pkgpanda/foo/bar', 'dcos:adminrouter:ops:pkgpanda'),
]


class TestLogsEndpointEE:
    url = (
        '/system/v1/logs/v1'
        '/stream/framework/test/executor/test/container/test'
        )

    def test_logs_authn_endpoint(
            self, agent_ar_process, valid_user_header):
        """Tests endpoint that skips ACL validation and grants access to any
           authenticated user to a specific `stream` or `range` requests
        """

        # We're asserting for a valid HTTP and also for specific auditlog
        # message that is produced if request hits a authn only NGINX location
        # configuration that forwards request to the logs upstream.
        filter_regexp = {
            'type=audit .*' +
            'object=dcos:adminrouter:ops:system-logs .*' +
            'result=allow .*' +
            'reason="authenticated \(all users are allowed to access\)" .*' +
            'request_uri=' + self.url: SearchCriteria(1, True),
            }
        lbf = LineBufferFilter(
            filter_regexp,
            line_buffer=agent_ar_process.stderr_line_buffer
            )

        with lbf:
            generic_upstream_headers_verify_test(
                agent_ar_process,
                valid_user_header,
                self.url,
                )

        assert lbf.extra_matches == {}

    def test_if_xaccel_header_is_passed_to_client(
            self,
            agent_ar_process,
            valid_user_header,
            mocker):

        accel_buff_header = {"X-Accel-Buffering": "TEST"}

        mocker.send_command(
            endpoint_id='http:///run/dcos/dcos-log.sock',
            func_name='set_response_headers',
            aux_data=accel_buff_header,
        )

        generic_response_headers_verify_test(
            agent_ar_process,
            valid_user_header,
            self.url,
            assert_headers=accel_buff_header,
            )


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
            mocker):

        log_messages = {
            'UID from valid JWT: `bozydar`': SearchCriteria(1, True),
            'type=audit .*' +
            'object={} .*'.format(rid) +
            'result=allow .*' +
            'reason="IAM PQ response" .*' +
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
    def test_if_unauthorized_user_is_forbidden_access(
            self,
            agent_ar_process,
            valid_user_header,
            path,
            rid,
            mocker):
        log_messages = {
            'UID from valid JWT: `bozydar`': SearchCriteria(1, True),
            'type=audit .*' +
            'object={} .*'.format(rid) +
            'result=deny .*' +
            'reason="IAM PQ response" .*' +
            'request_uri=' + path: SearchCriteria(1, True),
            }

        with iam_denies_all_requests(mocker):
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

    @pytest.mark.parametrize("path,rid", acl_endpoints)
    def test_if_policyquery_request_is_correct(
            self,
            agent_ar_process,
            valid_user_header,
            mocker,
            path,
            rid,
            ):
        mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='record_requests',
            )

        assert_endpoint_response(
            agent_ar_process,
            path,
            200,
            headers=valid_user_header,
            )

        requests = mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='get_recorded_requests',
            )

        assert len(requests) == 1
        r_data = requests[0]

        correct_path = '/acs/api/v1/internal/policyquery?rid={}&uid=bozydar&action=full'
        assert r_data['path'] == correct_path.format(rid)
        verify_header(r_data['headers'], 'X-Forwarded-For', '127.0.0.1')
        verify_header(r_data['headers'], 'X-Forwarded-Proto', 'http')
        verify_header(r_data['headers'], 'X-Real-IP', '127.0.0.1')
