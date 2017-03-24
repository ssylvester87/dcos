# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

import os
import requests

from generic_test_code import assert_endpoint_response
from util import SearchCriteria, GuardedSubprocess

EXHIBITOR_PATH = "/exhibitor/foo/bar"


class TestAuthnJWTValidator:
    """Tests scenarios where authentication token isn't provided or is provided
    in different supported places (cookie, header)"""

    def test_auth_token_not_provided(self, nginx_class):
        log_messages = {
            "No auth token in request.": SearchCriteria(1, True),
            }

        _start_ar_and_assert_exhibitor_response(
            nginx_class(), 401, assert_stderr=log_messages)

    def test_invalid_auth_token_in_cookie(self, nginx_class):
        log_messages = {
            "No auth token in request.": SearchCriteria(0, True),
            "Invalid token. Reason: invalid jwt string":
                SearchCriteria(1, True),
            }

        _start_ar_and_assert_exhibitor_response(
            nginx_class(),
            401,
            assert_stderr=log_messages,
            cookies={"dcos-acs-auth-cookie": "invalid"},
            )

    def test_missmatched_auth_token_algo_in_cookie(
            self,
            nginx_class,
            mismatch_alg_jwt_generator,
            ):
        log_messages = {
            "Invalid token. Reason: whitelist unsupported alg: HS256":
                SearchCriteria(1, True),
            }

        token = mismatch_alg_jwt_generator(uid='user')
        _start_ar_and_assert_exhibitor_response(
            nginx_class(),
            401,
            assert_stderr=log_messages,
            cookies={"dcos-acs-auth-cookie": token},
            )

    def test_valid_auth_token_in_cookie_without_uid(
            self,
            nginx_class,
            valid_jwt_generator,
            ):
        log_messages = {
            "No auth token in request.": SearchCriteria(0, True),
            "Invalid token. Reason: invalid jwt string":
                SearchCriteria(0, True),
            "Unexpected token payload: missing uid.":
                SearchCriteria(1, True),
            }

        token = valid_jwt_generator(uid=None)
        _start_ar_and_assert_exhibitor_response(
            nginx_class(),
            401,
            assert_stderr=log_messages,
            cookies={"dcos-acs-auth-cookie": token},
            )

    def test_valid_auth_token_in_cookie(self, nginx_class, valid_jwt_generator):
        log_messages = {
            "No auth token in request.": SearchCriteria(0, True),
            "Invalid token. Reason: invalid jwt string":
                SearchCriteria(0, True),
            "UID from valid JWT: `test`": SearchCriteria(1, True),
            }

        token = valid_jwt_generator(uid='test')
        _start_ar_and_assert_exhibitor_response(
            nginx_class(),
            200,
            assert_stderr=log_messages,
            cookies={"dcos-acs-auth-cookie": token},
            )

    def test_valid_auth_token(self, nginx_class, valid_user_header):
        log_messages = {
            "UID from valid JWT: `bozydar`": SearchCriteria(1, True),
            }
        _start_ar_and_assert_exhibitor_response(
            nginx_class(),
            200,
            assert_stderr=log_messages,
            headers=valid_user_header,
            )

    def test_valid_auth_token_priority(
            self,
            nginx_class,
            valid_user_header,
            valid_jwt_generator,
            ):
        log_messages = {
            "UID from valid JWT: `bozydar`": SearchCriteria(1, True),
            "UID from valid JWT: `test`": SearchCriteria(0, True),
            }

        token = valid_jwt_generator(uid='test')
        _start_ar_and_assert_exhibitor_response(
            nginx_class(),
            200,
            assert_stderr=log_messages,
            headers=valid_user_header,
            cookies={"dcos-acs-auth-cookie": token},
            )


class TestAuthzBouncerPolicyQuery:

    def test_if_bouncer_non200_resp_code_is_handled(
            self,
            nginx_class,
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
        _start_ar_and_assert_exhibitor_response(
            nginx_class(),
            500,
            assert_stderr=log_messages,
            headers=valid_user_header,
            )

    def test_if_bouncer_invalid_json_reply_is_handled(
            self,
            nginx_class,
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
            'JSONdecode failed. Response: ':
                SearchCriteria(1, True),
            'NOT_REAL_JSON': SearchCriteria(1, True),
            }
        _start_ar_and_assert_exhibitor_response(
            nginx_class(),
            500,
            assert_stderr=log_messages,
            headers=valid_user_header,
            )

    def test_if_bouncer_empty_json_reply_is_handled(
            self,
            nginx_class,
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
            '`allowed` not in JSONdecoded response:':
                SearchCriteria(1, True),
            }
        _start_ar_and_assert_exhibitor_response(
            nginx_class(),
            500,
            assert_stderr=log_messages,
            headers=valid_user_header,
            )


class TestAuthCustomErrorPages:

    def test_correct_401_page_content(
            self,
            master_ar_process,
            ):
        url = master_ar_process.make_url_from_path(EXHIBITOR_PATH)
        resp = requests.get(url)

        assert resp.status_code == 401
        assert resp.headers["Content-Type"] == "text/html; charset=UTF-8"
        assert resp.headers["WWW-Authenticate"] == "acsjwt"

        path_401 = os.environ.get('AUTH_ERROR_PAGE_DIR_PATH') + "/401.html"
        with open(path_401, 'rb') as f:
            resp_content = resp.content.decode('utf-8').strip()
            file_content = f.read().decode('utf-8').strip()
            assert resp_content == file_content

    def test_correct_403_page_content(
            self,
            master_ar_process,
            valid_user_header,
            mocker,
            ):
        mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='deny_all_queries',
            )

        url = master_ar_process.make_url_from_path(EXHIBITOR_PATH)
        resp = requests.get(url, headers=valid_user_header)
        assert resp.status_code == 403
        assert resp.headers["Content-Type"] == "text/html; charset=UTF-8"

        path_403 = os.environ.get('AUTH_ERROR_PAGE_DIR_PATH') + "/403.html"
        with open(path_403, 'rb') as f:
            resp_content = resp.content.decode('utf-8').strip()
            file_content = f.read().decode('utf-8').strip()
            assert resp_content == file_content


def _start_ar_and_assert_exhibitor_response(
        ar,
        code,
        assert_stderr=None,
        headers=None,
        cookies=None,
        ):
    """Asserts response code and log messages in Admin Router stderr for
    request against EXHIBITOR_PATH.

    This assertion helper also starts provided `ar`.

    Arguments:
        ar (Nginx): Instance of AR definition
        code (int): Expected response code
        assert_stderr (dict): Messages to assert definition
        cookies (dict): Optionally provide request cookies
        headers (dict): Optionally provide request headers
    """
    with GuardedSubprocess(ar):
        assert_endpoint_response(
            ar,
            EXHIBITOR_PATH,
            code,
            assert_stderr=assert_stderr,
            headers=headers,
            cookies=cookies,
        )
