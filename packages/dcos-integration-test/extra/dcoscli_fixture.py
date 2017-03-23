import logging
import os
import shutil
import stat
import subprocess
import tempfile

from contextlib import contextmanager

import requests

log = logging.getLogger(__name__)

DCOS_CLI_URL = "https://downloads.dcos.io/binaries/cli/linux/x86-64/latest/dcos"


def dcoscli_fixture(superuser_api_session):
    tmpdir = tempfile.mkdtemp()
    dcos_cli_path = os.path.join(tmpdir, "dcos")

    requests.packages.urllib3.disable_warnings()
    with open(dcos_cli_path, 'wb') as f:
        r = requests.get(DCOS_CLI_URL, stream=True, verify=True)
        for chunk in r.iter_content(1024):
            f.write(chunk)

    # make binary executable
    st = os.stat(dcos_cli_path)
    os.chmod(dcos_cli_path, st.st_mode | stat.S_IEXEC)

    return DCOSCLI(tmpdir, superuser_api_session)

    shutil.rmtree(os.path.expanduser("~/.dcos"))
    shutil.rmtree(tmpdir, ignore_errors=True)


class DCOSCLI():

    def __init__(self, directory, superuser_api_session):
        updated_env = os.environ.copy()
        updated_env.update({
            'PATH': "{}:{}".format(
                os.path.join(os.getcwd(), directory), os.environ['PATH']),
            'PYTHONIOENCODING': 'utf-8',
            'PYTHONUNBUFFERED': 'x'
        })
        self.env = updated_env
        self.url = superuser_api_session.default_url

        # Setup initial configuration
        self.config = Configuration(self)
        self.config["core.dcos_url"] = str(self.url)
        self.config["core.ssl_verify"] = "false"

    def exec_command(self, cmd, stdin=None):
        """Execute CLI command and processes result.

        This method expects that process won't block.

        :param cmd: Program and arguments
        :type cmd: [str]
        :param stdin: File to use for stdin
        :type stdin: file
        :returns: A tuple with stdout and stderr
        :rtype: (str, str)
        """

        log.info('CMD: {!r}'.format(cmd))

        process = subprocess.run(
            cmd,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.env,
            check=True)

        stdout, stderr = process.stdout.decode('utf-8'), process.stderr.decode('utf-8')

        log.info('STDOUT: {}'.format(stdout))
        log.info('STDERR: {}'.format(stderr))

        return (stdout, stderr)

    def start_command(self, cmd, **kwargs):
        """Starts a CLI command in a subprocess and returns it for futher
        interaction

        The caller is responsible for processing result of the process and
        making sure it finished correctly.

        Args:
            kwargs: Arbitrary arguments that are passed to subprocess.Popen()

        Return:
            subprocess.Popen
        """
        defaults = {
            'stdin': subprocess.PIPE,
            'stdout': subprocess.PIPE,
            'stderr': subprocess.PIPE,
            'env': self.env,
        }
        process = subprocess.Popen(cmd, **dict(defaults, **kwargs))
        return process

    def login(self):
        username = self.env.get("DCOS_LOGIN_UNAME")
        password = self.env.get("DCOS_LOGIN_PW")
        stdout, stderr = self.exec_command(
            ["dcos", "auth", "login", "--username={}".format(username), "--password={}".format(password)])
        assert stdout == 'Login successful!\n'
        assert stderr == ''

    def setup_enterprise(self):
        self.login()

        # install enterprise CLI
        self.exec_command(
            ["dcos", "package", "install", "dcos-enterprise-cli", "--cli"])

    @contextmanager
    def dcos_url(self, url):
        """Allows to override cli DC/OS URL"""

        existing_url = self.config.get("core.dcos_url")
        existing_auth_token = self.config.get("core.dcos_acs_token")

        # Only change DC/OS cli setting when provided URL doesn't match default
        # URL.
        if url != existing_url:
            self.config["core.dcos_url"] = url
            self.login()

            yield

            if existing_url:
                self.config["core.dcos_url"] = existing_url
            if existing_auth_token:
                self.config["core.dcos_acs_token"] = existing_auth_token
        else:
            yield


class Configuration:
    """Represents helper for simple access to the CLI configuration"""

    NOT_FOUND_MSG = "Property '{}' doesn't exist"

    def __init__(self, cli):
        self.cli = cli

    def get(self, key, default=None):
        """Retrieves configuration value from CLI"""

        try:
            stdout, _ = self.cli.exec_command(
                ["dcos", "config", "show", key])
            return stdout.strip("\n ")
        except subprocess.CalledProcessError as e:
            if self.NOT_FOUND_MSG.format(key) in e.stderr.decode('utf-8'):
                return default
            else:
                raise e

    def set(self, name, value):
        """Sets configuration option"""
        self.cli.exec_command(
            ["dcos", "config", "set", name, value])

    def __getitem__(self, key: str):
        value = self.get(key)
        if value is None:
            raise KeyError("'{}' wasn't found".format(key))

    def __setitem__(self, key, value):
        self.set(key, value)
