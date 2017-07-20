# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

import pytest
import requests

from generic_test_code.common import (
    assert_endpoint_response,
    overriden_file_content,
    verify_header,
)
from generic_test_code.ee import assert_iam_queried_for_uid_and_rid
from util import SearchCriteria, iam_denies_all_requests

acl_endpoints = [
    ('/acs/acl-schema.json', 'dcos:adminrouter:acs'),
    ('/acs/api/v1/reflect/me', 'dcos:adminrouter:acs'),
    ('/agent/de1baf83-c36c-4d23-9cb0-f89f596cd6ab-S1', 'dcos:adminrouter:ops:slave'),
    ('/ca/api/v2/bundle', 'dcos:adminrouter:ops:ca:ro'),
    ('/ca/api/v2/certificates', 'dcos:adminrouter:ops:ca:ro'),
    ('/ca/api/v2/newcert', 'dcos:adminrouter:ops:ca:rw'),
    ('/ca/api/v2/newkey', 'dcos:adminrouter:ops:ca:rw'),
    ('/ca/api/v2/sign', 'dcos:adminrouter:ops:ca:rw'),
    ('/cosmos/service/foo/bar', 'dcos:adminrouter:package'),
    ('/dcos-history-service/foo/bar', 'dcos:adminrouter:ops:historyservice'),
    ('/dcos-metadata/bootstrap-config.json', "dcos:adminrouter:ops:metadata"),
    ('/exhibitor/foo/bar', 'dcos:adminrouter:ops:exhibitor'),
    ('/mesos/master/state-summary', 'dcos:adminrouter:ops:mesos'),
    ('/mesos_dns/v1/services/_scheduler-alwaysthere._tcp.marathon.mesos',
     'dcos:adminrouter:ops:mesos-dns'),
    ('/metadata', "dcos:adminrouter:ops:metadata"),
    ('/networking/api/v1/foo/bar', 'dcos:adminrouter:ops:networking'),
    ('/package/foo/bar', 'dcos:adminrouter:package'),
    ('/pkgpanda/foo/bar', "dcos:adminrouter:ops:pkgpanda"),
    ('/pkgpanda/active.buildinfo.full.json', "dcos:adminrouter:ops:metadata"),
    ('/service/scheduler-alwaysthere/foo/bar',
        'dcos:adminrouter:service:scheduler-alwaysthere'),
    ('/service/nest1/scheduler-alwaysthere/foo/bar',
        'dcos:adminrouter:service:nest1/scheduler-alwaysthere'),
    ('/service/nest2/nest1/scheduler-alwaysthere/foo/bar',
        'dcos:adminrouter:service:nest2/nest1/scheduler-alwaysthere'),
    ('/slave/de1baf83-c36c-4d23-9cb0-f89f596cd6ab-S1', 'dcos:adminrouter:ops:slave'),
    ('/system/health/v1/foo/bar', 'dcos:adminrouter:ops:system-health'),
    ('/system/v1/logs/v1/foo/bar', 'dcos:adminrouter:ops:system-logs'),
    ('/system/v1/metrics/foo/bar', 'dcos:adminrouter:ops:system-metrics'),
    ('/system/v1/backup/foo/bar', 'dcos:adminrouter:ops:system-backup'),
]

authed_endpoints = [
    ('/capabilities', 'dcos:adminrouter:capabilities'),
    ('/navstar/lashup/key', 'dcos:adminrouter:navstar-lashup-key'),
    ('/secrets/v1', 'dcos:adminrouter:secrets'),
    ('/system/v1/agent/de1baf83-c36c-4d23-9cb0-f89f596cd6ab-S1/logs/v1',
        'dcos:adminrouter:system:agent'),
    ('/system/v1/agent/de1baf83-c36c-4d23-9cb0-f89f596cd6ab-S1/metrics/v0',
        'dcos:adminrouter:system:agent'),
    ('/system/v1/leader/marathon', 'dcos:adminrouter:system:leader:marathon'),
    ('/system/v1/leader/mesos', 'dcos:adminrouter:system:leader:mesos'),
]


class TestAuthEnforcementEE:
    """Tests full request cycle and all components involved in authentication
    authorization for each all protected paths"""

    @pytest.mark.parametrize("path,rid", acl_endpoints)
    def test_if_unauthn_user_is_forbidden_access(self,
                                                 mocker,
                                                 master_ar_process,
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
            master_ar_process, path, 401, assert_stderr=log_messages)

    @pytest.mark.parametrize("path,rid", acl_endpoints)
    def test_if_authorized_user_is_allowed(self,
                                           master_ar_process,
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

        is_auth_location = path.startswith("/acs/api/v1")
        with assert_iam_queried_for_uid_and_rid(
                mocker,
                'bozydar',
                rid,
                expect_two_iam_calls=is_auth_location):
            assert_endpoint_response(
                master_ar_process,
                path,
                200,
                assert_stderr=log_messages,
                headers=valid_user_header
                )

    @pytest.mark.parametrize("path,rid", acl_endpoints)
    def test_if_unauthorized_user_is_forbidden_access(
            self,
            master_ar_process,
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
                    master_ar_process,
                    path,
                    403,
                    assert_stderr=log_messages,
                    headers=valid_user_header
                    )

    @pytest.mark.parametrize("path,rid", authed_endpoints)
    def test_if_known_user_is_permitted_access(self,
                                               master_ar_process,
                                               valid_user_header,
                                               path,
                                               rid,
                                               mocker):
        mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='record_requests',
            )

        test_path = path + "/foo/bar"
        log_messages = {
            'UID from valid JWT: `bozydar`': SearchCriteria(1, True),
            'type=audit .*' +
            'object={} .*'.format(rid) +
            'result=allow .*' +
            'reason="authenticated \(all users are allowed to access\)" .*' +
            'request_uri=' + test_path: SearchCriteria(1, True),
            }

        assert_endpoint_response(
            master_ar_process,
            test_path,
            200,
            assert_stderr=log_messages,
            headers=valid_user_header
            )

        upstream_requests = mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='get_recorded_requests',
            )
        assert len(upstream_requests) == 0

    def test_if_user_is_allowed_to_get_own_permisions(self,
                                                      master_ar_process,
                                                      valid_user_header,
                                                      mocker):
        log_messages = {
            'UID from valid JWT: `bozydar`': SearchCriteria(1, True),
            'type=audit .*' +
            'object=dcos:iam:users:bozydar:permissions .*' +
            'result=allow .*' +
            'reason="user requests his/her own permissions" .*':
                SearchCriteria(1, True),
            }

        with iam_denies_all_requests(mocker):
            assert_endpoint_response(
                master_ar_process,
                '/acs/api/v1/users/bozydar/permissions',
                200,
                assert_stderr=log_messages,
                headers=valid_user_header,
                assertions=[
                    lambda r: r.json()['user'] == 'bozydar',
                    lambda r: r.json()['permissions'],
                    ]
                )

    def test_if_getting_different_user_permissions_is_authorized(self,
                                                                 master_ar_process,
                                                                 valid_user_header,
                                                                 mocker,
                                                                 ):
        log_messages = {
            'UID from valid JWT: `bozydar`': SearchCriteria(1, True),
            'type=audit .*' +
            'object=dcos:adminrouter:acs .*' +
            'result=allow .*' +
            'reason="IAM PQ response" .*':
                SearchCriteria(1, True),
            }
        with assert_iam_queried_for_uid_and_rid(
                mocker,
                'bozydar',
                'dcos:adminrouter:acs',
                expect_two_iam_calls=True):
            assert_endpoint_response(
                master_ar_process,
                '/acs/api/v1/users/root/permissions',
                200,
                assert_stderr=log_messages,
                headers=valid_user_header,
                assertions=[
                    lambda r: r.json()['user'] == 'root',
                    lambda r: r.json()['permissions'],
                    ]
                )

    def test_if_getting_different_user_permissions_is_denied(self,
                                                             master_ar_process,
                                                             valid_user_header,
                                                             mocker):
        log_messages = {
            'UID from valid JWT: `bozydar`': SearchCriteria(1, True),
            'type=audit .*' +
            'object=dcos:adminrouter:acs .*' +
            'result=deny .*' +
            'reason="IAM PQ response" .*':
                SearchCriteria(1, True),
            }

        with iam_denies_all_requests(mocker):
            with assert_iam_queried_for_uid_and_rid(
                    mocker,
                    'bozydar',
                    'dcos:adminrouter:acs'):
                assert_endpoint_response(
                    master_ar_process,
                    '/acs/api/v1/users/root/permissions',
                    403,
                    assert_stderr=log_messages,
                    headers=valid_user_header,
                    )

    def test_if_exhibitor_basic_auth_is_passed_to_upstream(self,
                                                           master_ar_process,
                                                           valid_user_header
                                                           ):
        r = requests.get(
            master_ar_process.make_url_from_path('/exhibitor/foo/bar'),
            headers=valid_user_header)

        assert r.status_code == 200

        headers = r.json()['headers']
        verify_header(headers, 'Authorization', 'Basic {}'.format(
            master_ar_process.env['EXHIBITOR_ADMIN_HTTPBASICAUTH_CREDS']
            ))

    @pytest.mark.parametrize("path,rid", acl_endpoints)
    def test_if_acl_validation_doesnt_pass_headers_to_iam(
            self,
            master_ar_process,
            valid_user_header,
            path,
            rid,
            mocker,
            ):
        mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='record_requests',
            )

        headers = {"CUSTOM_HEADER": "CUSTOM_VALUE"}
        headers.update(valid_user_header)
        assert_endpoint_response(
            master_ar_process,
            path,
            200,
            headers=headers,
            )

        requests = mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='get_recorded_requests',
            )

        last_request = requests[-1]
        # In case of /acs/api/v1 two requests will be sent to the iam mock
        # endpoint so work with first request that was issued by auth.lua
        if path.startswith('/acs/api/v1/'):
            last_request = requests[-2]

        header_names = set(map(lambda h: h[0], last_request["headers"]))
        assert "CUSTOM_HEADER" not in header_names
        assert "Authorization" not in header_names

    @pytest.mark.parametrize("path,rid", acl_endpoints)
    def test_if_policyquery_request_is_correct(
            self,
            master_ar_process,
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
            master_ar_process,
            path,
            200,
            headers=valid_user_header,
            )

        requests = mocker.send_command(
            endpoint_id='http://127.0.0.1:8101',
            func_name='get_recorded_requests',
            )

        if path.startswith("/acs/api/v1/"):
            assert len(requests) == 2
        else:
            assert len(requests) == 1
        r_data = requests[0]

        correct_path = '/acs/api/v1/internal/policyquery?rid={}&uid=bozydar&action=full'
        assert r_data['path'] == correct_path.format(rid)
        verify_header(r_data['headers'], 'X-Forwarded-For', '127.0.0.1')
        verify_header(r_data['headers'], 'X-Forwarded-Proto', 'http')
        verify_header(r_data['headers'], 'X-Real-IP', '127.0.0.1')


class TestMisc:
    @pytest.mark.parametrize("content", ["{'data': '1234'}", "{'data': 'abcd'}"])
    def test_if_acl_schema_is_served(
            self, master_ar_process, valid_user_header, content):
        url = master_ar_process.make_url_from_path('/acs/acl-schema.json')

        with overriden_file_content(
                '/opt/mesosphere/active/acl-schema/etc/acl-schema.json',
                content):
            resp = requests.get(
                url,
                allow_redirects=False,
                headers=valid_user_header
                )

        assert resp.status_code == 200
        assert resp.text == content

    @pytest.mark.parametrize("content", ["{'data': '1234'}", "{'data': 'abcd'}"])
    def test_if_ui_config_is_served(
            self, master_ar_process, valid_user_header, content):
        url = master_ar_process.make_url_from_path('/dcos-metadata/ui-config.json')

        with overriden_file_content(
                '/opt/mesosphere/etc/ui-config.json',
                content):
            resp = requests.get(
                url,
                allow_redirects=False,
                headers=valid_user_header
                )

        assert resp.status_code == 200
        assert resp.text == content

    @pytest.mark.parametrize("content", ["{'data': '1234'}", "{'data': 'abcd'}"])
    def test_if_bootstrap_config_is_served(
            self, master_ar_process, valid_user_header, content):
        url = master_ar_process.make_url_from_path('/dcos-metadata/bootstrap-config.json')

        with overriden_file_content(
                '/opt/mesosphere/etc/bootstrap-config.json',
                content):
            resp = requests.get(
                url,
                allow_redirects=False,
                headers=valid_user_header
                )

        assert resp.status_code == 200
        assert resp.text == content

    def test_if_ca_cert_is_served(self, master_ar_process):
        url = master_ar_process.make_url_from_path('/ca/dcos-ca.crt')

        with open("/run/dcos/pki/CA/ca-bundle.crt", 'r') as fh:
            cert_data = fh.read()

        resp = requests.get(url, allow_redirects=False)
        assert resp.status_code == 200
        assert resp.text == cert_data

    def test_if_jks_is_served(self, master_ar_process):
        url = master_ar_process.make_url_from_path('/ca/cacerts.jks')

        with open("/run/dcos/pki/CA/certs/cacerts.jks", 'r') as fh:
            data = fh.read()

        resp = requests.get(url, allow_redirects=False)
        assert resp.status_code == 200
        assert resp.text == data
        verify_header(resp.headers.items(), 'Content-Type', 'application/x-java-keystore')
