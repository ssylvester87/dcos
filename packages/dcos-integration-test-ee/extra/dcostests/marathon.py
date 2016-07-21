import collections
import json
import logging
import uuid

import pytest
import requests
import retrying

from dcostests import MarathonUrl


log = logging.getLogger(__name__)


sleep_app_definition = {
    'id': "/integration-test-sleep-app-%s" % str(uuid.uuid4()),
    'cpus': 0.1,
    'mem': 32,
    'cmd': 'sleep 100',
    'instances': 1,
    }


class MarathonApp:

    def __init__(self, app):
        self.app = app

    def deploy(self, headers=None):
        """Deploy an app to root Marathon.

        Return requests.models.Response object.
        """

        request_headers = {'Accept': 'application/json, text/plain, */*'}
        if headers:
            request_headers.update(headers)

        log.info('POSTing app definition to Marathon')
        r = requests.post(
            MarathonUrl('/v2/apps'),
            json=self.app,
            headers=request_headers
            )
        return r

    def wait(self, timeout=300, check_health=True, ignore_failed_tasks=False, headers=None):
        """
        Wait for Marathon to acknowledge successful creation or raise an
        exception.

        The application wait procedure is aborted if Marathon returns a
        non-empty `lastTaskFailure` field. Otherwise it waits until all
        instances reach the `tasksRunning` and, optionally, the `tasksHealthy`
        state.

        Args:
            app: A dict with A Marathon app definition.
            check_health: Wait until Marathon reports tasks as healthy before
                returning.
            timeout: Time in seconds to wait for the application to reach
                healthy state.
            headers: A dictionary defining additional headers to pass along
                Marathon HTTP requests.
            ignore_failed_tasks: whatever

        Returns: A list of namedtuple instances representing service points of
            deployed apps, e.g.

                [
                    Endpoint(host='172.17.10.202', port=10464),
                    Endpoint(host='172.17.10.201', port=1630)
                ]
        """
        @retrying.retry(
            wait_fixed=1000, stop_max_delay=timeout * 1000,
            retry_on_result=lambda ret: ret is None,
            retry_on_exception=lambda x: False
            )
        def _poll_for_app(app_id):

            url = MarathonUrl('/v2/apps' + app_id)
            log.info('Checking app state at %s', url)
            query_params = {'embed': ['apps.lastTaskFailure', 'apps.counts']}
            r = requests.get(
                url=url,
                params=query_params,
                headers=request_headers
                )
            r.raise_for_status()

            data = r.json()
            log.debug('app state: %s', json.dumps(data, indent=2))

            Endpoint = collections.namedtuple("Endpoint", ["host", "port"])

            if not ignore_failed_tasks:
                assert 'lastTaskFailure' not in data['app'], (
                        'Application deployment failed, reason: %s' %
                        data['app']['lastTaskFailure']['message']
                    )

            if (
                data['app']['tasksRunning'] == app['instances'] and
                (not check_health or data['app']['tasksHealthy'] == app['instances'])
            ):
                res = [Endpoint(t['host'], t['ports'][0]) for t in data['app']['tasks']]
                log.info('Application deployed. Endpoints: %s', res)
                return res
            else:
                log.info('Application not yet deployed.')
                return None

        request_headers = {'Accept': 'application/json, text/plain, */*'}
        if headers:
            request_headers.update(headers)

        app = self.app
        try:
            return _poll_for_app(app['id'])
        except retrying.RetryError:
            pytest.fail("Marathon app deployment timed out")
