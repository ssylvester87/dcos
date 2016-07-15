# -*- coding: utf-8 -*-
# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


from urllib.parse import urlunsplit

import pytest

from dcostests import dcos


class Url:
    """A powerful DC/OS cluster URL abstraction."""

    # Allow subclasses to set their own path prefix.
    _path_prefix = ''
    _default_scheme = 'http'
    _hostname = dcos.hostname

    def __init__(self, path, host=None, port=None, scheme=None):

        assert not self._path_prefix or self._path_prefix.startswith('/')
        assert not path or path.startswith('/')
        self.path = '%s%s' % (self._path_prefix, path)

        # In lockdown mode, override default scheme with HTTPS.
        if pytest.config.getoption('expect_strict_security'):
            self._default_scheme =  'https'

        self.scheme = scheme if scheme else self._default_scheme

        hostname = host if host else self._hostname

        if port:
            self.netloc = "%s:%s" % (hostname, port)
        else:
            self.netloc = hostname

    def _abs(self):
        return urlunsplit((
            self.scheme,
            self.netloc,
            self.path,
            "",
            ""))

    def rel(self):
        """Return just the path (no scheme, host)."""
        return self.path

    def __str__(self):
        """Make text representation be absolute URL."""
        return self._abs()


class IAMUrl(Url):
    _path_prefix = '/acs/api/v1'


class CAUrl(Url):
    _path_prefix = '/ca/api/v2'


class DDDTUrl(Url):
    _path_prefix = '/system/health/v1'


class MarathonUrl(Url):
    _path_prefix = '/service/marathon'
