import json
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

    def _entry_exists(self, url, exists_code):
        """Check whether GET `url` returns 200 OK.

        If the response status code is not 200 OK, confirm that the IAM error
        code matches `exists_code`. If it does not match the expected IAM error
        code an exception is raised.

        Args:
            url (str): The URL to test.
            exists_code (str):
                The IAM error code indicating that the entry already exists.
                For example, 'ERR_UNKNOWN_RESOURCE_ID' in the case of an ACL.

        Returns:
            bool:
                True if the entry exists.
                False if it does not.

        Raises:
               Exception: If the answer cannot be determined.
        """
        def _error_from_response_or_raise(resp):
            try:
                data = json.loads(resp.text)
            except json.JSONDecodeError:
                raise Exception('Could not read error code from IAM: status {}'.format(resp.status_code))
            error_code = data['code']
            error_descr = data['description']
            return error_code, error_descr

        r = self.request('get', url)
        if r.status_code == 200:
            return True
        err_code, err_descr = _error_from_response_or_raise(r)
        if err_code == exists_code:
            return False
        raise Exception('Cannot determine whether entry at `{}` exists: {} ({})'.format(url, err_descr, err_code))

    def create_service_account(self, id, secret=None, public_key=None, exist_ok=False):
        if self._entry_exists('/acs/api/v1/users/{}'.format(id), 'ERR_UNKNOWN_USER_ID'):
            if exist_ok:
                log.info('Service account `{}` already exists'.format(id))
                return
            raise Exception('create service account failed: user `{}` already exists'.format(id))
        data = {
            'description': '{} service account'.format(id)
        }
        if secret:
            data['secret'] = secret
        elif public_key:
            data['public_key'] = public_key
        else:
            raise Exception('no credentials provided')
        r = self.request('put', '/acs/api/v1/users/{}'.format(id), json=data)
        log.info('status_code={}'.format(r.status_code))

        if r.status_code == 409 and exist_ok:
            log.info('Service account `{}` already exists'.format(id))
            # TODO retrieve public key so caller can compare
            return

        if r.status_code != 201:
            raise Exception('create service account failed: status {}'.format(r.status_code))

    def grant_permissions(self, rids_and_actions, uid):
        """
        Grant permissions for the identity with the given `uid`: for all (`rid`,
        `action`) pairs in `rids_and_actions`, allow to perform that given
        action on the resource represented by `rid`.
        """

        for rid, action in rids_and_actions:

            # Slashes in a `rid` must be encoded when a `rid` is being used in
            # a URL. That's part of the IAM HTTP API specification.
            encoded_rid = rid.replace('/', '%252F')
            acl_url = '/acs/api/v1/acls/{}'.format(encoded_rid)

            if not self._entry_exists(acl_url, 'ERR_UNKNOWN_RESOURCE_ID'):
                data = {'description': 'Created during bootstrap'}
                r = self.request('put', acl_url, json=data)
                # If we fail to create an ACL for the resource we crash and
                # retry when we boot again. This also guards against the case
                # where multiple processes run bootstrap at the same time and
                # race towards creating the resource. The first will succeed and
                # all others will fail if at that point the resource already
                # exists.
                r.raise_for_status()

            # Check whether the user has been assigned to the ACL and action.
            # The user and ACL are expected to exist. The user and the ACL are
            # both expected to exist. We expect true/false to be returned from
            # the server and any failure is unexpected and should lead to a
            # crash.
            action_url = '{}/users/{}/{}'.format(acl_url, uid, action)
            r = self.request('get', action_url)
            r.raise_for_status()

            data = r.json()
            assert isinstance(data['allowed'], bool)

            if data['allowed']:
                # The user is already permitted to perform the action on the resource.
                continue

            r = self.request('put', action_url)
            # If we are racing with another bootstrap process we may receive an
            # error here. In that case we simply crash and retry as the next
            # time we run the user will have been assigned to the ACL and we
            # won't enter this branch.
            r.raise_for_status()

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
        group_url = '/acs/api/v1/groups/{}'.format(id)
        if self._entry_exists(group_url, 'ERR_UNKNOWN_GROUP_ID'):
            return
        if not description:
            description = id
        data = {
            'description': description
        }
        r = self.request('put', group_url, json=data)
        if r.status_code != 201:
            raise Exception('create group failed with status {}'.format(r.status_code))

    def add_user_to_group(self, uid, gid, exist_ok=True):
        r = self.request('get', '/acs/api/v1/groups/{}/users?type=service'.format(gid))
        r.raise_for_status()
        uids = [el['user']['uid'] for el in json.loads(r.text)['array']]
        if uid in uids:
            if exist_ok:
                return
            raise Exception('add user to group failed: user `{}` already a member of group `{}`'.format(uid, gid))
        r = self.request('put', '/acs/api/v1/groups/{}/users/{}'.format(gid, uid))
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
