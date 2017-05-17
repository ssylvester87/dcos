import json

import pytest
import requests_mock

from dcos_internal_utils.iam import IAMClient


class TestEntryExists:

    def test_200(self):
        base_url = "http://example.com"
        client = IAMClient(base_url=base_url)
        url = "/foo"
        exists_code = "DOES_NOT_MATTER"
        with requests_mock.Mocker() as mock:
            mock.get(base_url + url, status_code=200)
            result = client._entry_exists(
                url=url,
                exists_code=exists_code)
            assert result is True

    def test_no_text_in_response(self):
        base_url = "http://example.com"
        client = IAMClient(base_url=base_url)
        url = "/foo"
        exists_code = "DOES_NOT_MATTER"
        with requests_mock.Mocker() as mock:
            mock.get(base_url + url, status_code=500)
            with pytest.raises(Exception) as exc:
                client._entry_exists(
                    url=url,
                    exists_code=exists_code)
            # TODO(gpaul): use custom exception
            assert 'status 500' in str(exc.value)

    def test_bouncer_error_matches_exists_code(self):
        base_url = "http://example.com"
        client = IAMClient(base_url=base_url)
        url = "/foo"
        exists_code = "ERR_UNKNOWN_RESOURCE_ID"
        text = json.dumps({
            'code': exists_code,
            'description': 'some description',
        })
        with requests_mock.Mocker() as mock:
            mock.get(base_url + url, status_code=409, text=text)
            result = client._entry_exists(
                url=url,
                exists_code=exists_code)
            assert result is False

    def test_bouncer_error_does_not_match_exists_code(self):
        base_url = "http://example.com"
        client = IAMClient(base_url=base_url)
        url = "/foo"
        exists_code = "ERR_UNKNOWN_RESOURCE_ID"
        text = json.dumps({
            'code': "BAD_EXISTS_CODE",
            'description': 'some description',
        })
        with requests_mock.Mocker() as mock:
            mock.get(base_url + url, status_code=409, text=text)
            with pytest.raises(Exception) as exc:
                client._entry_exists(
                    url=url,
                    exists_code=exists_code)
            assert 'Cannot determine whether entry at `/foo` exists:' in str(exc.value)
            assert 'some description (BAD_EXISTS_CODE)' in str(exc.value)
