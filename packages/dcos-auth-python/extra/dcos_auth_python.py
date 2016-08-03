import json
from datetime import datetime, timedelta

import jwt
import requests

IAM_CONFIG_PATH = '/run/dcos/etc/history-service/service_account.json'
AUTH_TOKEN = None
TOKEN_REFRESH = 60
TOKEN_REFRESH_TIME = None


def set_service_auth_token():
    with open(IAM_CONFIG_PATH, 'r') as fh:
        conf = json.load(fh)

    jwt_payload = {'uid': conf['uid'], 'exp': datetime.utcnow()+timedelta(seconds=300)}
    login_token = jwt.encode(jwt_payload, conf['private_key'], algorithm='RS256').decode()
    login_payload = json.dumps({'uid': conf['uid'], 'token': login_token})
    global AUTH_TOKEN
    AUTH_TOKEN = requests.post(conf['login_endpoint'],
                               headers={'content-type': 'application/json'},
                               data=login_payload).json()['token']
    global TOKEN_REFRESH_TIME
    TOKEN_REFRESH_TIME = datetime.utcnow() + timedelta(seconds=TOKEN_REFRESH)


def get_auth_headers():
    if not AUTH_TOKEN or datetime.utcnow() > TOKEN_REFRESH_TIME:
        set_service_auth_token()
    return {'Authorization': 'token='+AUTH_TOKEN}
