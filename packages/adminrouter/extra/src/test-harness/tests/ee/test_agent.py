# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

import copy
import logging
import pytest

from generic_test_code import (
    generic_upstream_headers_verify_test
)
from util import LineBufferFilter, SearchCriteria

log = logging.getLogger(__name__)
pytestmark = pytest.mark.usefixtures("agent_ar_process")


class TestLogsEndpointEE():

    def test_logs_authn_endpoint(self,
                                 agent_ar_process,
                                 superuser_user_header):
        """Tests endpoint that skips ACL validation and grants access to any
           authenticated user to a specific `stream` or `range` requests
        """

        # Configuration should pass "X-Accel-Buffering" header to logs upstream
        accel_buff_header = {"X-Accel-Buffering": "TEST"}

        req_headers = copy.deepcopy(superuser_user_header)
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
