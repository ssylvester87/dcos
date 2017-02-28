import copy
import logging

from exceptions import EndpointException
from mocker.endpoints.recording import (
    RecordingHTTPRequestHandler,
    RecordingTcpIpEndpoint,
)

log = logging.getLogger(__name__)


class IamHTTPRequestHandler(RecordingHTTPRequestHandler):
    def _calculate_response(self, base_path, url_args, body_args=None):
        ctx = self.server.context

        with ctx.lock:
            users = ctx.data['users']

            if base_path != '/acs/api/v1/internal/policyquery':
                msg_fmt = "Path `{}` is not supported yet"
                raise EndpointException(msg_fmt.format(base_path))

            uid = url_args['uid'][0]

            if uid not in users:
                return self._convert_data_to_blob({'allowed': False})

            if users[uid]['is_superuser']:
                return self._convert_data_to_blob({'allowed': True})

            perms = users[uid]['perms']
            rid = url_args['rid'][0]

            if rid not in perms:
                return self._convert_data_to_blob({'allowed': False})

            action = url_args['action'][0]

            if action not in perms[rid] or 'full' not in perms[rid]:
                return self._convert_data_to_blob({'allowed': False})

        return self._convert_data_to_blob({'allowed': True})


class IamEndpoint(RecordingTcpIpEndpoint):
    _users = {"root": {"is_superuser": True,
                       "perms": {},
                       },
              "bozydar": {"is_superuser": False,
                          "perms": {},
                          },
              "jadwiga": {"is_superuser": False,
                          "perms": {"dcos:adminrouter:ops:exhibitor": ["full"],
                                    "dcos:adminrouter:ops:ca:ro": ["read"],
                                    },
                          },
              }

    def __init__(self, port, ip=''):
        super().__init__(port, ip, IamHTTPRequestHandler)
        self._context.data["users"] = copy.deepcopy(self._users)

    def grant_superuser(self, aux):
        uid = aux["uid"]
        with self._context.lock:
            users = self._context.data["users"]

            assert uid not in users, "User has not been defined yet"

            users[uid]["is_superuser"] = True

        log.debug("User `%s` has been granted superuser", uid)

        return None

    def revoke_superuser(self, aux):
        uid = aux["uid"]
        with self._context.lock:
            users = self._context.data["users"]

            assert uid not in users, "User has not been defined yet"

            users[uid]["is_superuser"] = False

        log.debug("User `%s` - superuser has been revoked", uid)

        return None

    def add_user(self, aux):
        uid = aux["uid"]
        with self._context.lock:
            users = self._context.data["users"]

            assert uid not in users, "User already defined"

            users[uid] = {"is_superuser": False,
                          "perms": {},
                          }

        log.debug("User `%s` has been added to IamEndpoint", uid)

        return None

    def del_user(self, aux):
        uid = aux["uid"]
        with self._context.lock:
            users = self._context.data["users"]

            assert uid in users, "User does not exist yet"

            del users[uid]

        log.debug("User `%s` has been removed from IamEndpoint", uid)

        return None

    def grant_permission(self, aux):
        uid = aux["uid"]
        rid = aux["rid"]
        action = aux["action"]

        with self._context.lock:
            users = self._context.data["users"]

            assert uid in users, "User does not exist"

            if rid not in users[uid]['perms']:
                users[uid]['perms'][rid] = [action]
            elif action not in users[uid]['perms'][rid]:
                users[uid]['perms'][rid].append(action)
            else:
                fmt = "Permission `%s` has already been granted"
                log.warning(fmt, str(aux))
                return None

        log.debug("Permission `%s` has been granted", str(aux))
        return None

    def get_permissions(self, aux):
        uid = aux["uid"]
        with self._context.lock:
            users = self._context.data["users"]

            assert uid in users, "User does not exist yet"

            perms = copy.deepcopy(users[uid]['perms'])

        return perms

    def revoke_permission(self, aux):
        uid = aux["uid"]
        rid = aux["rid"]
        action = aux["action"]

        with self._context.lock:
            users = self._context.data["users"]

            assert uid in users, "User does not exist"

            if rid not in users[uid]['perms']:
                fmt = "Permission `%s`/rid has not been granted yet"
                log.warning(fmt, str(aux))
                return None

            if action not in users[uid]['perms'][rid]:
                fmt = "Permission `%s`/action has not been granted yet"
                log.warning(fmt, str(aux))
                return None

            users[uid]['perms'][rid].remove(action)

        log.debug("Permission `%s` has been revoked", str(aux))
        return None
