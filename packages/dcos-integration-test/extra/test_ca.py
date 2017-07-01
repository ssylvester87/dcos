"""
Test if nginx endpoints are serving, either static or dynamic.

Test subtle details of nginx configuration.

Tests should not modify cluster state.
"""
import pytest


@pytest.fixture()
def sign_request():
    """
    Provides example valid CSR that can be sent to /sign endpoint.
    """
    return {"certificate_request": """-----BEGIN CERTIFICATE REQUEST-----
MIICqjCCAZICAQAwZTEXMBUGA1UEAwwOd3d3LnBvdGF0by5jb20xFTATBgNVBAoM
DFBvdGF0bywgSW5jLjELMAkGA1UEBhMCREUxEzARBgNVBAgMClBvdGF0b2xhbmQx
ETAPBgNVBAcMCFBvdGF0b2xhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEA3DwEOmSGu8bInl9GJenzhvwqahHNAFIndRDd78yYpwtf8kwzrzOlp+gZWjvo
D8kPVDjDz3puSbzTI8W8+IsogTAKDZj2rJKdyHyR4tL4SS+RS0iN1lmKSMK4NAI/
JqRwdvLTAPlIyVc4a1ovS6w16qk1opQL5rKBl9sllwxCjz6jvt5tT3RlVfKw7k53
cqwOsLScg/0VzTwhnhPqgHUDmWOEtasrGeROae3OHIwef/AbvbnueZWMtU3leOXG
PkIF9WD/gsP7NNk2KlW+HXJX/p//G/RltoAxdVtCg578jlg4HVA50XIMananOlQ2
n3zAIgvcumNBQG+3t2tbcfdP6QIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBADHi
IiCYuQGAOjL+QZn9BCQz2mSfXT7QYC0XXIlvth9RFEGN+JUNEKkFBiA7cG3kb0G/
OD5SW9w5KJlTOJcHZpc7DZTSSf8AVBBPBmq+7XPtaiNlih7e6HzFOMPt1smNFC8g
muklWi587dynmbhWwtNGpXv7WQwRmBdTJU9DYvu4/WHObnfZ1kvM5ZlNn57QO+N5
DFq6rT4iAJeID4uwUYsnzo/huBed9SYpOkRz5It8gYyWdn9tGJTQUyzDXvTvIj5o
hDYADyMXhDO/Lm9rEnYd6yXUnIzYQryV9lVAnvFwcPYDRHizA1iPJ3ZuQBd4ODce
589l09lMVrZoOL8uF3k=
-----END CERTIFICATE REQUEST-----"""}


def test_if_CA_cert_was_loaded(noauth_api_session):

    # Endpoint is expected to available for unauthenticated users.
    r = noauth_api_session.ca.post('/info', json={"label": "primary"})
    assert r.status_code == 200

    data = r.json()
    assert data['success'] is True
    assert data['errors'] == []
    assert data['messages'] == []
    assert 'signing' in data['result']['usages']
    assert 'BEGIN CERTIFICATE' in data['result']['certificate']


@pytest.mark.skip(reason="Disabled till DCOS-8889 is addressed")
def test_if_CA_can_list_issued_certs(superuser_api_session):
    data = {
        "request": {
            "hosts": ["www.example.com"],
            "names": [{"C": "US", "ST": "foo", "L": "bar", "O": "byzz"}],
            "CN": "www.example.com"
            }
        }
    r = superuser_api_session.ca.post('/newcert', json=data)
    assert r.status_code == 200

    r = superuser_api_session.ca.post(
        '/certificates',
        json={"authority_key_id": "", "serial": "", "expired_ok": False})
    assert r.status_code == 200

    data = r.json()
    assert data['success'] is True
    assert data['errors'] == []
    assert data['messages'] == []
    assert isinstance(data['result'], list)
    assert len(data['result']) > 1
    # FIXME(prozlach): Would be nice to exted this test to actually testing if
    # returned certificate is the one that was signed by CA just a moment ago.


def test_if_CA_can_create_cert(superuser_api_session):
    p = {"request": {"hosts": ["www.example.com"],
                     "names": [{"C": "US",
                                "ST": "California",
                                "L": "San Francisco",
                                "O": "example.com"},
                               ],
                     "CN": "www.example.com"}}
    r = superuser_api_session.ca.post('/newcert', json=p)
    assert r.status_code == 200

    data = r.json()
    assert data['success'] is True
    assert data['errors'] == []
    assert data['messages'] == []
    assert 'BEGIN CERTIFICATE' in data['result']['certificate']
    assert 'PRIVATE KEY' in data['result']['private_key']


def test_if_CA_can_create_csr(superuser_api_session, noauth_api_session):
    p = {"request": {"hosts": ["www.example.com"],
                     "names": [{"C": "US",
                                "ST": "California",
                                "L": "San Francisco",
                                "O": "example.com"},
                               ],
                     "CN": "www.example.com"}}
    r = noauth_api_session.ca.post('/newkey', json=p)
    assert r.status_code == 401
    r = superuser_api_session.ca.post('/newkey', json=p)
    assert r.status_code == 200

    data = r.json()
    assert data['success'] is True
    assert data['errors'] == []
    assert data['messages'] == []
    assert 'certificate' not in data['result']
    assert 'BEGIN CERTIFICATE REQUEST' in data['result']['certificate_request']
    assert 'PRIVATE KEY' in data['result']['private_key']


def test_if_CA_can_create_cert_from_csr(
        superuser_api_session, noauth_api_session, sign_request):
    r = noauth_api_session.ca.post('/sign', json=sign_request)
    assert r.status_code == 401
    r = superuser_api_session.ca.post('/sign', json=sign_request)
    assert r.status_code == 200

    data = r.json()
    assert data['success'] is True
    assert data['errors'] == []
    assert data['messages'] == []
    assert 'BEGIN CERTIFICATE' in data['result']['certificate']
    assert 'private_key' not in data['result']


def test_if_CA_can_bundle_cert_without_exposing_private_key(
        superuser_api_session, sign_request):
    # Generate an end-entity certificate signed by the DC/OS CA (based
    # on our certificate signing request).
    r = superuser_api_session.ca.post('/sign', json=sign_request)
    assert r.status_code == 200
    data = r.json()
    cert_pem = data['result']['certificate']

    # Send end-entity certificate to the DC/OS CA and request the
    # corresponding certificate chain via cfssl's `/bundle` endpoint.
    req = {"certificate": cert_pem}
    r = superuser_api_session.ca.post('/bundle', json=req)
    assert r.status_code == 200
    data = r.json()

    # Verify that the response data contains no key (sensitive data)
    # and indeed contains the expected "bundle" key (which carries the
    # certificate chain including the end-entity cert but not including
    # the root CA cert) and "root" key (which carries the corresponding
    # root CA certificate).
    assert data['result']['key'] == ''
    assert 'bundle' in data['result']
    assert 'root' in data['result']


@pytest.mark.parametrize(
    'endpoint', ['/certinfo', '/init_ca', '/scan', '/scaninfo'])
def test_if_unused_CA_endpoints_are_protected(noauth_api_session, endpoint):
    r = noauth_api_session.ca.post(endpoint, json={})
    # TODO(jp): see ticket DCOS-7874
    assert r.status_code == 404
