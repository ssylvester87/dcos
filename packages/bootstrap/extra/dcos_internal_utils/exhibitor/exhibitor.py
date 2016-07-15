import codecs
import json
import logging
import os
import urllib.request


from .. import utils


log = logging.getLogger(__name__)


EXHIBITOR_STATUS_URL = 'http://127.0.0.1:8181/exhibitor/v1/cluster/status'


def wait(master_count_filename):
    if not os.path.exists(master_count_filename):
        log.info("master_count file doesn't exist, not waiting")
        return

    cluster_size = int(utils.read_file_line(master_count_filename))
    log.info('Expected cluster size: {}'.format(cluster_size))

    log.info('Waiting for ZooKeeper cluster to stabilize')
    try:
        response = urllib.request.urlopen(EXHIBITOR_STATUS_URL)
    except urllib.error.URLError:
        msg = 'Could not get exhibitor status: {}'.format(EXHIBITOR_STATUS_URL)
        raise Exception(msg)

    reader = codecs.getreader("utf-8")
    data = json.load(reader(response))

    serving = 0
    leaders = 0
    for node in data:
        if node['isLeader']:
            leaders += 1
        if node['description'] == 'serving':
            serving += 1

    if serving != cluster_size or leaders != 1:
        msg = 'Expected {} servers and 1 leader, got {} servers and {} leaders'.format(cluster_size, serving, leaders)
        raise Exception(msg)
