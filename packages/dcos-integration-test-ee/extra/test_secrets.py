"""
Test Secrets functionality
"""
import logging

log = logging.getLogger(__name__)


def test_if_secrets_ping(cluster):
    r = cluster.secrets.get('/ping')
    assert r.status_code == 200
    data = r.text
    assert data == "pong"


def test_if_secrets_can_get_stores(cluster):
    r = cluster.secrets.get('/store')
    assert r.status_code == 200
    data = r.json()
    assert data['array'][0]['initialized']


def test_if_secrets_can_get_store(cluster):
    r = cluster.secrets.get('/store/default')
    assert r.status_code == 200
    data = r.json()
    assert data['initialized']


def test_if_secrets_unauthorized_get_store(cluster):
    r = cluster.get_user_session(None).secrets.get('/store')
    assert r.status_code == 401


def test_if_secrets_put_store(cluster):
    # FIXME: this test leaves state in the cluster and will fail on re-run
    data = {
        "name": "testStore",
        "driver": "vault",
        "addr": "http://127.0.0.1:8200"}
    r = cluster.secrets.put('/store/testStore', json=data)
    assert r.status_code == 201


def test_if_secrets_init_status(cluster):
    r = cluster.secrets.get('/init/default')
    assert r.status_code == 200

    # Secrets are initialized
    data = r.json()
    assert data['initialized']


def test_if_secrets_get_seal_status(cluster):
    r = cluster.secrets.get('/seal-status/default')
    assert r.status_code == 200
    data = r.json()
    assert not data["sealed"]


def test_if_secrets_unseal_wrongkey(cluster):
    data = {"key": "wrongkey"}
    r = cluster.secrets.put('/unseal/default', json=data)
    assert r.status_code == 500


def test_if_secrets_get_wrongsecret(cluster):
    r = cluster.secrets.get('/secret/default/wrongsecret')
    assert r.status_code == 404


def test_if_secrets_put_secret(cluster):
    # FIXME: this test leaves state behind and fails on rerun
    data = {"value": "anewsecret"}
    r = cluster.secrets.put('/secret/default/anewpath', json=data)
    assert r.status_code == 201


def test_if_secrets_get_secret(cluster):
    # FIXME: this state relies on the previous test. Please never do that.
    r = cluster.secrets.get('/secret/default/anewpath')
    assert r.status_code == 200
    data = r.json()
    assert data['value'] == 'anewsecret'


def test_if_secrets_list_secret(cluster):
    r = cluster.secrets.get('/secret/default/?list=true')
    assert r.status_code == 200
    data = r.json()
    assert data['array']
    assert isinstance(data['array'], list)
    assert len(data['array']) > 0


def test_if_secrets_put_secret_exists(cluster):
    # FIXME: test relies on previous test: NO
    data = {"value": "anewsecret"}
    r = cluster.secrets.put('/secret/default/anewpath', json=data)
    assert r.status_code == 409


def test_if_secrets_delete_secret(cluster):
    # FIXME: test relies on previous test: NO
    r = cluster.secrets.delete('/secret/default/anewpath')
    assert r.status_code == 204


def test_if_secrets_delete_wrongsecret(cluster):
    r = cluster.secrets.delete('/secret/default/wrongpath')
    assert r.status_code == 404


def test_if_secrets_delete_store(cluster):
    # FIXME: test relies on previous test: NO
    r = cluster.secrets.delete('/store/testStore')
    assert r.status_code == 204


def test_if_secrets_delete_wrongstore(cluster):
    r = cluster.secrets.delete('/store/wrongStore')
    assert r.status_code == 404


def test_if_secrets_seal_and_auto_unseal(cluster):
    # Seal store
    r = cluster.secrets.put('/seal/default')
    assert r.status_code == 204

    # Store should be sealed
    r = cluster.secrets.get('/seal-status/default')
    assert r.status_code == 200

    data = r.json()
    assert data["sealed"]

    # Get Unseal keys from the init endpoint
    r = cluster.secrets.get('/init/default')
    assert r.status_code == 200

    # Secrets are initialized and unseal keys are provided
    resp = r.json()
    assert resp['initialized']
    assert len(resp['keys']) > 0

    # Unseal store with superuser privileges by just passing
    # still encrypted unseal key to auto-unseal endpoint
    data = {'key': resp['keys'][0]}
    r = cluster.secrets.put('/auto-unseal/default', json=data)
    assert r.status_code == 200

    # Store should not be sealed
    r = cluster.secrets.get('/seal-status/default')
    assert r.status_code == 200

    data = r.json()
    assert not data["sealed"]
