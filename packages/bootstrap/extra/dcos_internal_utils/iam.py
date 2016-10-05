import logging
import time


import jwt
import requests
import retrying


log = logging.getLogger(__name__)


class IAMClient:
    def __init__(self, base_url, CA_certificate_filename=None):
        self.base_url = base_url
        self.default_headers = {'Accept': 'application/json', 'Accept-Charset': 'utf-8'}
        self.CA_certificate_filename = CA_certificate_filename

    def request(self, method, path, **kwargs):
        url = self.base_url + path

        if 'headers' not in kwargs:
            kwargs['headers'] = self.default_headers.copy()
        if 'verify' not in kwargs:
            kwargs['verify'] = self.CA_certificate_filename

        if method == 'get':
            r = requests.get(url, **kwargs)
        elif method == 'post':
            r = requests.post(url, **kwargs)
        elif method == 'put':
            r = requests.put(url, **kwargs)
        elif method == 'delete':
            r = requests.delete(url, **kwargs)
        else:
            raise Exception('invalid HTTP method: ' + method)
        return r

    @retrying.retry(wait_fixed=100)
    def ping(self):
        r = self.request('get', '/acs/api/v1/auth/logout', timeout=0.1)
        if r.status_code == 200:
            return

    def create_service_account(self, id, secret=None, public_key=None, exist_ok=False):
        data = {
            'description': '{} service account'.format(id)
        }
        if secret:
            data['secret'] = secret
        elif public_key:
            data['public_key'] = public_key
        else:
            raise Exception('no credentials provided')
        r = self.request('put', '/acs/api/v1/users/' + id, json=data)
        log.info('status_code={}'.format(r.status_code))

        if r.status_code == 409 and exist_ok:
            log.info('Service account {} already exists'.format(id))
            # TODO retrieve public key so caller can compare
            return

        if r.status_code != 201:
            raise Exception('create service account failed: status {}'.format(r.status_code))

    def create_acls(self, rids_and_actions, username):
        for rid, action in rids_and_actions:
            url_root = '/acs/api/v1/acls/{}'.format(rid)
            data = {'description': 'ACL for rid {}'.format(rid)}
            self.request('put', url_root, json=data)
            self.request('put', '{}/users/{}/{}'.format(url_root, username, action))

    def password_login(self, id, password):
        data = {
            'uid': id,
            'password': password
        }
        r = self.request('post', '/acs/api/v1/auth/login', json=data)
        if r.status_code != 200:
            raise Exception('login failed with status {code}. Reason: {reason}. Output: {text}'.format(
                code=r.status_code,
                reason=r.reason,
                text=r.text))

        return r.cookies['dcos-acs-auth-cookie']

    def service_account_login(self, id, secret=None, private_key=None, exp=None):
        # exp here is for the login token
        payload = {'uid': id, 'exp': int(time.time()) + 3600}
        if secret:
            alg = 'HS256'
            key = secret
        elif private_key:
            alg = 'RS256'
            key = private_key
        else:
            raise Exception('no credentials provided')

        token = jwt.encode(payload, key, alg)

        data = {
            'uid': id,
            'token': token.decode('ascii')
        }
        # exp here is for the auth token
        if exp is not None:
            data['exp'] = exp

        r = self.request('post', '/acs/api/v1/auth/login', json=data)
        if r.status_code != 200:
            raise Exception('login failed with status {}'.format(r.status_code))
        return r.cookies['dcos-acs-auth-cookie']

    def create_group(self, id, description=None):
        if not description:
            description = id
        data = {
            'description': description
        }
        r = self.request('put', '/acs/api/v1/groups/' + id, json=data)
        if r.status_code != 201:
            raise Exception('create group failed with status {}'.format(r.status_code))

    def add_user_to_group(self, uid, gid, exist_ok=True):
        r = self.request('put', '/acs/api/v1/groups/' + gid + '/users/' + uid)
        if r.status_code == 409 and exist_ok:
            return
        if r.status_code == 204:
            return
        raise Exception('add user to group failed with status {}'.format(r.status_code))

    def jwks(self):
        r = self.request('get', '/acs/api/v1/auth/jwks')
        if r.status_code == 200:
            return r.json()
        raise Exception('jwks failed with status {}'.format(r.status_code))
