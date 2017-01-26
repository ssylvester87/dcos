"""
Test Secrets functionality
"""
import logging

import pytest

pytestmark = [pytest.mark.usefixtures('secrets_verify_and_reset')]
log = logging.getLogger(__name__)


def test_if_secrets_ping(superuser_api_session):
    r = superuser_api_session.secrets.get('/ping')
    assert r.status_code == 200
    data = r.text
    assert data == "pong"


def test_if_secrets_can_get_stores(superuser_api_session):
    r = superuser_api_session.secrets.get('/store')
    assert r.status_code == 200
    data = r.json()
    assert data['array'][0]['initialized']


def test_if_secrets_can_get_default_store(superuser_api_session):
    r = superuser_api_session.secrets.get('/store/default')
    assert r.status_code == 200
    data = r.json()
    assert data['initialized']


def test_if_secrets_unauthorized_get_store(superuser_api_session):
    r = superuser_api_session.get_user_session(None).secrets.get('/store')
    assert r.status_code == 401


def test_if_secrets_CRD_store(superuser_api_session):
    data = {
        "name": "testStore",
        "driver": "vault",
        "addr": "http://127.0.0.1:8200"}
    r = superuser_api_session.secrets.put('/store/testStore', json=data)
    assert r.status_code == 201

    r = superuser_api_session.secrets.get('/store/testStore')
    assert r.status_code == 200

    r = superuser_api_session.secrets.delete('/store/testStore')
    assert r.status_code == 204


def test_if_secrets_init_status(superuser_api_session):
    r = superuser_api_session.secrets.get('/init/default')
    assert r.status_code == 200

    # Secrets are initialized
    data = r.json()
    assert data['initialized']


def test_if_secrets_get_seal_status(superuser_api_session):
    r = superuser_api_session.secrets.get('/seal-status/default')
    assert r.status_code == 200
    data = r.json()
    assert not data["sealed"]


def test_if_secrets_unseal_wrongkey(superuser_api_session):
    data = {"key": "wrongkey"}
    r = superuser_api_session.secrets.put('/unseal/default', json=data)
    assert r.status_code == 500


def test_if_secrets_get_wrongsecret(superuser_api_session):
    r = superuser_api_session.secrets.get('/secret/default/wrongsecret')
    assert r.status_code == 404


def test_if_secrets_CRUD_secret(superuser_api_session):
    # Creating secret
    r = superuser_api_session.secrets.put('/secret/default/anewpath', json={'value': 'anewsecret'})
    assert r.status_code == 201

    # Reading secret
    r = superuser_api_session.secrets.get('/secret/default/anewpath')
    assert r.status_code == 200
    data = r.json()
    assert data['value'] == 'anewsecret'

    # Listing secrets
    r = superuser_api_session.secrets.get('/secret/default/?list=true')
    assert r.status_code == 200
    data = r.json()
    assert data['array']
    assert isinstance(data['array'], list)
    assert len(data['array']) > 0

    # Trying to create Existing secret
    r = superuser_api_session.secrets.put('/secret/default/anewpath', json={'value': 'anewsecret'})
    assert r.status_code == 409

    # Updating secret
    r = superuser_api_session.secrets.patch('/secret/default/anewpath', json={'value': 'updatedsecret'})
    assert r.status_code == 204

    # Deleting secret
    r = superuser_api_session.secrets.delete('/secret/default/anewpath')
    assert r.status_code == 204


def test_if_secrets_delete_wrongsecret(superuser_api_session):
    r = superuser_api_session.secrets.delete('/secret/default/wrongpath')
    assert r.status_code == 404


def test_if_secrets_delete_wrongstore(superuser_api_session):
    r = superuser_api_session.secrets.delete('/store/wrongStore')
    assert r.status_code == 404


def test_if_secrets_seal_and_auto_unseal(superuser_api_session):
    # Seal store
    r = superuser_api_session.secrets.put('/seal/default')
    assert r.status_code == 204

    # Store should be sealed
    r = superuser_api_session.secrets.get('/seal-status/default')
    assert r.status_code == 200

    data = r.json()
    assert data["sealed"]

    # Get Unseal keys from the init endpoint
    r = superuser_api_session.secrets.get('/init/default')
    assert r.status_code == 200

    # Secrets are initialized and unseal keys are provided
    resp = r.json()
    assert resp['initialized']
    assert len(resp['keys']) > 0

    # Unseal store with superuser privileges by just passing
    # still encrypted unseal key to auto-unseal endpoint
    r = superuser_api_session.secrets.put('/auto-unseal/default', json={'key': resp['keys'][0]})
    assert r.status_code == 200

    # Store should not be sealed
    r = superuser_api_session.secrets.get('/seal-status/default')
    assert r.status_code == 200

    data = r.json()
    assert not data["sealed"]
