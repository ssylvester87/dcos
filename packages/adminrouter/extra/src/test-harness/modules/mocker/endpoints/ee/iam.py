# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

import logging
import re

from exceptions import EndpointException
from mocker.endpoints.recording import (
    RecordingHTTPRequestHandler,
    RecordingTcpIpEndpoint,
)

log = logging.getLogger(__name__)


class IamHTTPRequestHandler(RecordingHTTPRequestHandler):

    USERS_PERMISSIONS_REGEXP = re.compile(
        '^/acs/api/v1/users/([^/]+)/permissions$')

    def _calculate_response(self, base_path, url_args, body_args=None):
        """Determine if the IAM request should be allow/deny.

           Please refer to the description of the BaseHTTPRequestHandler class
           for details on the arguments and return value of this method.
        """
        if base_path == '/acs/api/v1/internal/policyquery':
            return self.__internal_policy_query_request_handler()

        reflecting_paths = [
            '/acs/api/v1/reflect/me',
            '/dcos-metadata/ui-config.json',
            '/acs/api/v1/users/reflecting-user/permissions']
        if base_path in reflecting_paths or base_path.startswith('/acs/api/v1/auth/'):
            # A test URI that is used by tests. In some cases it is impossible
            # to reuse /acs/api/v1/users/.../permissions, and
            # /acs/api/v1/internal/policyquery is internal/not exposed.
            return self._reflect_request(base_path, url_args, body_args)

        match = self.USERS_PERMISSIONS_REGEXP.search(base_path)
        if match:
            return self.__users_permissions_request_handler(match.group(1))

        raise EndpointException(
            code=500,
            content="Path `{}` is not supported yet".format(
                base_path))

    def __users_permissions_request_handler(self, user):
        blob = self._convert_data_to_blob({
            'user': user,
            'permissions': True,
            })
        return 200, 'application/json', blob

    def __internal_policy_query_request_handler(self):
        ctx = self.server.context

        with ctx.lock:
            blob = self._convert_data_to_blob({'allowed': ctx.data['allowed']})

        return 200, 'application/json', blob


class IamEndpoint(RecordingTcpIpEndpoint):

    def __init__(self, port, ip=''):
        super().__init__(port, ip, IamHTTPRequestHandler)
        self.__context_init()

    def reset(self):
        with self._context.lock:
            super().reset()
            self.__context_init()

    def __context_init(self):
        """Helper function meant to initialize all the data relevant to this
           particular type of endpoint"""
        self._context.data["allowed"] = True

    def permit_all_queries(self, *_):
        self._context.data["allowed"] = True

    def deny_all_queries(self, *_):
        self._context.data["allowed"] = False