# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

import requests
import os

from generic_test_code.common import assert_endpoint_response
from util import SearchCriteria, iam_denies_all_requests

EXHIBITOR_PATH = "/exhibitor/foo/bar"


class TestAuthzIAMQuery:
    def test_if_iam_non200_resp_code_is_handled(
            self,
            master_ar_process,
            valid_user_header,
            mocker,
            ):
        mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='always_bork',
            aux_data=True,
            )

        log_messages = {
            'UID from valid JWT: `bozydar`': SearchCriteria(1, True),
            "Unexpected policyquery response status \(JSONized\): ":
                SearchCriteria(1, True),
            }
        assert_endpoint_response(
            master_ar_process,
            EXHIBITOR_PATH,
            500,
            assert_stderr=log_messages,
            headers=valid_user_header,
            )

    def test_if_iam_invalid_json_reply_is_handled(
            self,
            master_ar_process,
            valid_user_header,
            mocker,
            ):
        mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='set_encoded_response',
            aux_data=b"NOT_REAL_JSON",
            )

        log_messages = {
            'UID from valid JWT: `bozydar`': SearchCriteria(1, True),
            'JSONdecode failed. Response: ': SearchCriteria(1, True),
            'NOT_REAL_JSON': SearchCriteria(1, True),
            }
        assert_endpoint_response(
            master_ar_process,
            EXHIBITOR_PATH,
            500,
            assert_stderr=log_messages,
            headers=valid_user_header,
            )

    def test_if_iam_empty_json_reply_is_handled(
            self,
            master_ar_process,
            valid_user_header,
            mocker,
            ):
        mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='set_encoded_response',
            aux_data=b"{}",
            )

        log_messages = {
            'UID from valid JWT: `bozydar`': SearchCriteria(1, True),
            '`allowed` not in JSONdecoded response:': SearchCriteria(1, True),
            }
        assert_endpoint_response(
            master_ar_process,
            EXHIBITOR_PATH,
            500,
            assert_stderr=log_messages,
            headers=valid_user_header,
            )


class TestAuthCustomErrorPagesEE:
    def test_correct_403_page_content(
            self, master_ar_process, valid_user_header, mocker):
        url = master_ar_process.make_url_from_path(EXHIBITOR_PATH)

        with iam_denies_all_requests(mocker):
            resp = requests.get(url, headers=valid_user_header)

        assert resp.status_code == 403
        assert resp.headers["Content-Type"] == "text/html; charset=UTF-8"

        path_403 = os.environ.get('AUTH_ERROR_PAGE_DIR_PATH') + "/403.html"
        with open(path_403, 'rb') as f:
            resp_content = resp.content.decode('utf-8').strip()
            file_content = f.read().decode('utf-8').strip()
            assert resp_content == file_content


class TestAuthnJWTValidatorEE:
    def test_forged_auth_token(
            self,
            master_ar_process,
            forged_user_header,
            ):
        # Different validators emit different log messages, so we create two
        # tests - one for open, one for EE, each one having different log
        # message.
        log_messages = {
            "Invalid token. Reason: Verification failed":
                SearchCriteria(1, True),
            }

        assert_endpoint_response(
            master_ar_process,
            EXHIBITOR_PATH,
            401,
            assert_stderr=log_messages,
            headers=forged_user_header,
            )
