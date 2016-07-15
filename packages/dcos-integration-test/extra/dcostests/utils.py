# -*- coding: utf-8 -*-
# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


import logging
import socket
from contextlib import closing

import requests

from dcostests.url import IAMUrl


log = logging.getLogger(__name__)


class AuthedUser:
    """A lightweight user representation."""
    pass


class SuperUser:

    def set_user_permission(self, rid, uid, action):

        rid = rid.replace('/', '%252F')

        # Create ACL if it does not yet exist.
        url = IAMUrl('/acls/%s' % rid)
        r = requests.put(
            url,
            json={'description': 'jope'},
            headers=self.authheader
            )
        assert r.status_code == 201 or r.status_code == 409

        # Set the permission triplet.
        url = IAMUrl('/acls/%s/users/%s/%s' % (
            rid, uid, action))
        r = requests.put(url, headers=self.authheader)
        r.raise_for_status()


def is_port_open(host, port):

    with closing(socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
        try:
            s.connect((host, port))
            return True
        except Exception as e:
            log.info("Exception during socket connect(): %s", str(e))
            return False
