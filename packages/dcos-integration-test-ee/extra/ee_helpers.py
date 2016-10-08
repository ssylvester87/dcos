OPS_ENDPOINTS = [
    '/acs/api/v1/users/',
    '/dcos-history-service/',
    '/exhibitor',
    '/mesos',
    '/mesos_dns/v1/config',
    '/metadata',
    '/networking/api/v1/vips',
    '/pkgpanda/active.buildinfo.full.json',
    '/secrets/v1/store',
    '/system/health/v1']


def sleep_app_definition(uid):
    return {
        'id': "/integration-test-sleep-app-%s" % uid,
        'cpus': 0.1,
        'mem': 32,
        'cmd': 'sleep 3600',
        'instances': 1,
        }
