# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

"""
Module for managing test EE AR instances, against which all tests are run.
"""
import logging
import os

from runner.common import NginxBase

log = logging.getLogger(__name__)


class Nginx(NginxBase):

    def __init__(self,
                 jwt_algo="RS256",
                 service_auth_token=("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1Ni"
                                     "J9.eyJ1aWQiOiJkY29zX2FkbWlucm91dGV"
                                     "yIn0.kSvz7tAkt-h7PBALMSGWVKPaQg6jo"
                                     "sNjCGgsWSyzSgIAcls7zQEa5OBoczg6gSk"
                                     "U9ZrLNtK9AFoDR9pLmwpomHEItiAB9RFrK"
                                     "tWLQAz_RiizG6q8XSQ6oQ9OFFX178AuR9B"
                                     "PVVCcfBovNk8jP2N6eMyTomy_OqTbHgA2-"
                                     "otNhvTp713OCDd2mH0PQY_40t8X_ww-P36"
                                     "TRRDwlc62le9QfbAiceiqEi206r1kydde9"
                                     "L5OeqhxeOjH9IYxJy6miNMyfbC31ZPzHRg"
                                     "jiX2fFj_EHVyhJ0k0oHdKpoWDaUx2AEnVL"
                                     "R7SGECuYBS6K-vOgKMWfB-5E_Oi69OSHLS"
                                     "_Aq5gzw"
                                     ),
                 secret_key_file_path=os.environ.get("IAM_PUBKEY_FILE_PATH"),
                 # username:password - dcos:dcos
                 exhibitor_basic_auth="ZGNvczpkY29z",
                 **base_kwargs):

        NginxBase.__init__(self, **base_kwargs)

        self._env["JWT_ALG"] = jwt_algo
        self._env["SERVICE_AUTH_TOKEN"] = service_auth_token
        self._set_ar_env_from_val('SECRET_KEY_FILE_PATH', secret_key_file_path)
        self._set_ar_env_from_val(
            'EXHIBITOR_ADMIN_HTTPBASICAUTH_CREDS', exhibitor_basic_auth)
