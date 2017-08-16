"""
Test dcos-backup functionality through Admin Router.
"""

import json
import logging
import time

from datetime import datetime
from datetime import timedelta


STATUS_READY = "STATUS_READY"
STATUS_UNKNOWN = "STATUS_UNKNOWN"
STATUS_BACKING_UP = "STATUS_BACKING_UP"
STATUS_RESTORING = "STATUS_RESTORING"
STATUS_ERROR = "STATUS_ERROR"
COMPONENT_NAMES = ['marathon']
BACKUP_READY_TIMEOUT = timedelta(seconds=120)
RESTORE_READY_TIMEOUT = timedelta(seconds=120)
POLL_SLEEP = 5  # seconds


class TestDCOSBackupUnauthorized:

    def test_noauth_access(self, noauth_api_session):
        r = noauth_api_session.get('/system/v1/backup/v1/list')
        assert r.status_code == 401

    def test_regular_user_access(self, peter_api_session):
        r = peter_api_session.get('/system/v1/backup/v1/list')
        assert r.status_code == 403


class TestDCOSBackupGeneralBehavior:

    # this test ensures that only one backup may happen at a time.
    def test_cluster_lock(self, superuser_api_session):
        self.delete_existing_backups(superuser_api_session)
        self.destroy_marathon_apps(superuser_api_session)

        # verify no backups exist
        r = superuser_api_session.get('/system/v1/backup/v1/list')
        assert r.status_code == 200
        assert r.text == '{}'
        logging.info("Verified no backups exist")

        # start the first backup
        r = superuser_api_session.post('/system/v1/backup/v1/create', json={"label": "foo"})
        assert r.status_code == 200
        data = r.json()
        info = data.get('backup_info')
        backup_id = info.get('id')
        assert backup_id is not None
        assert info.get('status') == STATUS_BACKING_UP

        # NB: the first backup is now happening in the background

        # now, try to create a second backup immediately and verify it fails
        r2 = superuser_api_session.post('/system/v1/backup/v1/create', json={"label": "bar"})
        assert r2.status_code == 500
        data = r2.json()
        errors = data.get("errors", [])
        assert len(errors) == 1
        assert "Could not backup bar: " + \
               "backup label=bar failed: backup/restore is currently busy: " + \
               "lock is already held" == errors[0]

        # then, wait for the original backup to finish
        deadline = datetime.now() + BACKUP_READY_TIMEOUT
        completed = False
        while datetime.now() < deadline:
            time.sleep(POLL_SLEEP)
            if self.is_backup_ready(superuser_api_session, backup_id):
                completed = True
                break
        assert completed, "The backup did not complete in time"

        # after the original backup has finished, ensure that the second backup can then proceed
        self.create_backup(superuser_api_session, label='bar')

    # this test exercises the expected behavior of dcos-backup
    def test_expected_behavior(self, superuser_api_session):
        self.delete_existing_backups(superuser_api_session)

        # verify no backups exist
        r = superuser_api_session.get('/system/v1/backup/v1/list')
        assert r.status_code == 200
        assert r.text == '{}'
        logging.info("Verified no backups exist")

        # setup the cluster before the backup
        self.destroy_marathon_apps(superuser_api_session)
        self.create_marathon_sleeper(superuser_api_session, "sleeper1")

        # create a backup. this backup should only have sleeper1 as running.
        backup_id_1 = self.create_backup(superuser_api_session, label='foo')
        logging.info("Created first backup {}".format(backup_id_1))

        # verify behavior after first backup
        self.verify_apps_in_marathon(superuser_api_session, ['sleeper1'])

        # now create a second marathon app (sleeper2)
        self.create_marathon_sleeper(superuser_api_session, "sleeper2")

        # NB: sleeper1 and sleeper2 should now be running

        # create a second backup
        backup_id_2 = self.create_backup(superuser_api_session, label='bar')
        logging.info("Created second backup {}".format(backup_id_2))

        # verify behavior after second backup
        self.verify_apps_in_marathon(superuser_api_session, ['sleeper1', 'sleeper2'])

        # perform a restore
        restore_id = self.restore_backup(superuser_api_session, backup_id_1)

        # verify cluster after the restore. should only include the sleeper1 app.
        self.verify_apps_in_marathon(superuser_api_session, ['sleeper1'])

        # delete the backup using the restore id -- should not work
        r = superuser_api_session.delete('/system/v1/backup/v1/delete', json={'id': restore_id})
        assert r.status_code == 400

        # delete the backup using the backup id -- this should work
        r = superuser_api_session.delete('/system/v1/backup/v1/delete', json={'id': backup_id_1})
        assert r.status_code == 200

    # creates a new backup. returns the id of the backup
    def create_backup(self, api, label='foo'):
        r = api.post('/system/v1/backup/v1/create', json={"label": label})
        assert r.status_code == 200
        data = r.json()
        info = data.get('backup_info')
        # save a reference to the backup id b/c we'll be restoring it later.
        backup_id = info.get('id')
        assert backup_id is not None
        assert info.get('status') == STATUS_BACKING_UP
        for component in COMPONENT_NAMES:
            assert info['component_status'][component]['status'] == STATUS_UNKNOWN

        # wait for the backup to complete successfully
        deadline = datetime.now() + BACKUP_READY_TIMEOUT
        completed = False
        while datetime.now() < deadline:
            time.sleep(POLL_SLEEP)
            if self.is_backup_ready(api, backup_id):
                completed = True
                break
        assert completed, "The backup did not complete in time"
        return backup_id

    # restore a backup. return the restore id.
    def restore_backup(self, api, backup_id):
        r = api.post('/system/v1/backup/v1/restore', json={"id": backup_id})
        assert r.status_code == 200
        info = r.json().get('backup_info')
        # save a reference to the restore id
        restore_id = info.get('id')
        # wait for the restore to complete successfully
        deadline = datetime.now() + RESTORE_READY_TIMEOUT
        completed = False
        while datetime.now() < deadline:
            time.sleep(POLL_SLEEP)
            if self.is_backup_ready(api, backup_id, restore_id=info['id']):
                completed = True
                break
        assert completed, "The restore did not complete in time"
        return restore_id

    def verify_apps_in_marathon(self, api, ids=None):
        if ids is None:
            ids = []
        apps = self.get_marathon_apps(api)
        for app_id in ids:
            assert ('/' + app_id) in apps, "app " + app_id + \
                " was not found in marathon. existing apps: " + json.dumps(apps)
        if len(apps) != len(ids):
            raise Exception("Expected app ids: {} but found {}".format(ids, apps.keys()))

    def get_marathon_apps(self, api):
        r = api.get('/service/marathon/v2/apps')
        assert r.status_code == 200
        s = set()
        for x in r.json().get('apps', []):
            s.add(x['id'])
        return s

    def destroy_marathon_apps(self, api):
        apps = self.get_marathon_apps(api)
        for app in apps:
            r = api.delete('/service/marathon/v2/apps/' + app + '?force=true')
            assert r.status_code == 200

    def create_marathon_sleeper(self, api, app_id):
        r = api.post('/service/marathon/v2/apps', json={"id": app_id, "instances": 1, "cmd": "sleep 100000"})
        assert r.status_code == 201

    # checks to see if a backup/restore is in the ready state. if
    # any statuses are STATUS_ERROR an error will be raised.
    def is_backup_ready(self, api, backup_id, restore_id=None):
        backup = self.find_backup_or_restore(api, backup_id, restore_id)
        if backup is None:
            raise Exception("No metadata found for backup_id=" + backup_id + " restore_id=" + restore_id)
        if backup.get('status') == STATUS_ERROR:
            if restore_id:
                raise Exception("Restore errored out")
            raise Exception("Backup errored out")
        if backup.get('status') == STATUS_READY:
            all_components_ready = True
            for component in COMPONENT_NAMES:
                component_status = backup.get('component_status', {}).get(component, {}).get('status')
                if component_status == STATUS_ERROR:
                    raise Exception("Component " + component + " errored out")
                if component_status != STATUS_READY:
                    all_components_ready = False
                    break
            if all_components_ready:
                return True
        return False

    # find_backup does a list on the api and tries to find the backup or restore specified
    def find_backup_or_restore(self, api, backup_id, restore_id=None):
        r = api.get('/system/v1/backup/v1/list')
        assert r.status_code == 200
        data = r.json()
        for backup in data.get('backup_info', []):
            if backup.get('id') == backup_id:
                # this is our backup. if restore_id is specified, see if we can find the
                # restore
                if restore_id:
                    for restore in backup.get('restores', []):
                        if restore.get('id') == restore_id:
                            return restore
                    return None
                return backup
        return None

    # delete all existing backups
    def delete_existing_backups(self, superuser_api_session):
        r = superuser_api_session.get('/system/v1/backup/v1/list')
        assert r.status_code == 200
        data = r.json()
        for backup in data.get('backup_info', []):
            r = superuser_api_session.delete('/system/v1/backup/v1/delete', json={"id": backup['id']})
            assert r.status_code == 200
