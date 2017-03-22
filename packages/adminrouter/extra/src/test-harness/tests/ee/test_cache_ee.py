# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

import logging

from generic_test_code import ping_mesos_agent, verify_header
from util import LineBufferFilter, SearchCriteria, GuardedSubprocess

log = logging.getLogger(__name__)


class TestCacheEE:
    def test_if_service_auth_token_is_sent_to_cache_upstreams(
            self, nginx_class, mocker, superuser_user_header):
        service_t_expected = 'CeupyavLegmijFlewd8' * 40
        filter_regexp = {
            'Picked up service authentication token from env.': SearchCriteria(1, False),
            }
        # Enable recording for marathon
        mocker.send_command(endpoint_id='http://127.0.0.1:8080',
                            func_name='record_requests')
        # Enable recording for Mesos
        mocker.send_command(endpoint_id='http://127.0.0.2:5050',
                            func_name='record_requests')

        ar = nginx_class(service_auth_token=service_t_expected)

        with GuardedSubprocess(ar):
            lbf = LineBufferFilter(filter_regexp,
                                   line_buffer=ar.stderr_line_buffer)
            ping_mesos_agent(ar, superuser_user_header)
            lbf.scan_log_buffer()

        assert lbf.extra_matches == {}

        mesos_requests = mocker.send_command(endpoint_id='http://127.0.0.2:5050',
                                             func_name='get_recorded_requests')
        marathon_requests = mocker.send_command(endpoint_id='http://127.0.0.1:8080',
                                                func_name='get_recorded_requests')
        assert len(mesos_requests) == 1
        assert len(marathon_requests) == 2
        for req in mesos_requests + marathon_requests:
            verify_header(req['headers'], 'Authorization', 'token=' + service_t_expected)
