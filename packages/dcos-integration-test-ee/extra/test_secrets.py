"""
Test Secrets functionality
"""


import logging

import requests


from dcostests import SecretsUrl


log = logging.getLogger(__name__)


def test_if_secrets_ping(superuser):
    r = requests.get(
        SecretsUrl('/ping'),
        headers=superuser.authheader
    )
    assert r.status_code == 200

    data = r.text
    assert data == "pong"


def test_if_secrets_can_get_stores(superuser):
    r = requests.get(
        SecretsUrl('/store'),
        headers=superuser.authheader
        )
    assert r.status_code == 200

    data = r.json()
    assert data['array'][0]['initialized']


def test_if_secrets_can_get_store(superuser):
    r = requests.get(
        SecretsUrl('/store/default'),
        headers=superuser.authheader
        )
    assert r.status_code == 200

    data = r.json()
    assert data['initialized']


def test_if_secrets_unauthorized_get_store():
    r = requests.get(
        SecretsUrl('/store')
        )
    assert r.status_code == 401


def test_if_secrets_put_store(superuser):
    data = {
        "name": "testStore",
        "driver": "vault",
        "addr": "http://127.0.0.1:8200"
        }

    r = requests.put(
        SecretsUrl('/store/testStore'),
        json=data,
        headers=superuser.authheader
    )
    assert r.status_code == 201


def test_if_secrets_init_status(superuser):
    r = requests.get(
        SecretsUrl('/init/default'),
        headers=superuser.authheader
    )
    assert r.status_code == 200

    # Secrets are initialized
    data = r.json()
    assert data['initialized']


def test_if_secrets_get_seal_status(superuser):
    r = requests.get(
        SecretsUrl('/seal-status/default'),
        headers=superuser.authheader
    )
    assert r.status_code == 200

    data = r.json()
    assert not data["sealed"]


def test_if_secrets_unseal_wrongkey(superuser):
    data = {
        "key": "wrongkey"
        }
    r = requests.put(
        SecretsUrl('/unseal/default'),
        json=data,
        headers=superuser.authheader
    )
    assert r.status_code == 500


def test_if_secrets_get_wrongsecret(superuser):
    r = requests.get(
        SecretsUrl('/secret/default/wrongsecret'),
        headers=superuser.authheader
    )
    assert r.status_code == 404


def test_if_secrets_put_secret(superuser):
    data = {
        "value": "anewsecret"
        }

    r = requests.put(
        SecretsUrl('/secret/default/anewpath'),
        json=data,
        headers=superuser.authheader
    )
    assert r.status_code == 201


def test_if_secrets_get_secret(superuser):
    r = requests.get(
        SecretsUrl('/secret/default/anewpath'),
        headers=superuser.authheader
    )
    assert r.status_code == 200

    data = r.json()
    assert data['value'] == 'anewsecret'


def test_if_secrets_list_secret(superuser):
    r = requests.get(
        SecretsUrl('/secret/default/?list=true'),
        headers=superuser.authheader
    )
    assert r.status_code == 200

    data = r.json()
    assert data['array']
    assert isinstance(data['array'], list)
    assert len(data['array']) > 0


def test_if_secrets_put_secret_exists(superuser):
    data = {
        "value": "anewsecret"
        }
    r = requests.put(
        SecretsUrl('/secret/default/anewpath'),
        json=data,
        headers=superuser.authheader
    )
    assert r.status_code == 409


def test_if_secrets_delete_secret(superuser):
    r = requests.delete(
        SecretsUrl('/secret/default/anewpath'),
        headers=superuser.authheader
    )
    assert r.status_code == 204


def test_if_secrets_delete_wrongsecret(superuser):
    r = requests.delete(
        SecretsUrl('/secret/default/wrongpath'),
        headers=superuser.authheader
    )
    assert r.status_code == 404


def test_if_secrets_delete_store(superuser):
    r = requests.delete(
        SecretsUrl('/store/testStore'),
        headers=superuser.authheader
    )
    assert r.status_code == 204


def test_if_secrets_delete_wrongstore(superuser):
    r = requests.delete(
        SecretsUrl('/store/wrongStore'),
        headers=superuser.authheader
    )
    assert r.status_code == 404
