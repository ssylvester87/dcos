# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

import time

import requests

from util import GuardedSubprocess


class TestNginxResolverEE:

    # In order to test that TTL of the DNS entry is indeed ignored/overriden,
    # we set this to a very high value. If `valid` argument has been properly
    # set for the resolver config option, then tests will pass
    LONG_TTL = 120

    def test_upstream_iam_reresolve_in_proxy_pass(
            self,
            nginx_class,
            valid_user_header,
            dns_server_mock,
            mocker,
            ):
        # Change the TTL of `master.mesos.` entry
        dns_server_mock.set_dns_entry(
            'master.mesos.', ip='127.0.0.1', ttl=self.LONG_TTL)
        # Start recording requests for both IAM
        mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='record_requests',
            )
        mocker.send_command(
            endpoint_id='http://127.0.0.2:8101',
            func_name='record_requests',
            )

        ar = nginx_class(role='agent')
        url = ar.make_url_from_path('/system/health/v1/foo/bar')

        with GuardedSubprocess(ar):
            resp = requests.get(url,
                                allow_redirects=False,
                                headers=valid_user_header)
            assert resp.status_code == 200

            # Verify that the request went to correct upstream
            iam_1_requests = mocker.send_command(
                endpoint_id='http://127.0.0.1:8101',
                func_name='get_recorded_requests',
                )
            iam_2_requests = mocker.send_command(
                endpoint_id='http://127.0.0.2:8101',
                func_name='get_recorded_requests',
                )
            assert len(iam_1_requests) == 1
            assert len(iam_2_requests) == 0
            mocker.send_command(
                endpoint_id='http://127.0.0.1:8101',
                func_name='erase_recorded_requests',
                )

            # Change the value of `master.mesos.` entry
            dns_server_mock.set_dns_entry(
                'master.mesos.', ip='127.0.0.2', ttl=self.LONG_TTL)
            # This should be equal to 1.5 times the value of `valid=` DNS TTL
            # override in `resolver` config option -> 5s * 1.5 = 7.5s
            time.sleep(5 * 1.5)

            resp = requests.get(url,
                                allow_redirects=False,
                                headers=valid_user_header)
            assert resp.status_code == 200

            # Verify that the request went to correct upstream
            iam_1_requests = mocker.send_command(
                endpoint_id='http://127.0.0.1:8101',
                func_name='get_recorded_requests',
                )
            iam_2_requests = mocker.send_command(
                endpoint_id='http://127.0.0.2:8101',
                func_name='get_recorded_requests',
                )

            assert len(iam_1_requests) == 0
            assert len(iam_2_requests) == 1
