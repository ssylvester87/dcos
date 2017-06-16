"""
Test dcos-backup functionality through Admin Router.
"""

import time

from datetime import datetime
from datetime import timedelta


STATUS_READY = "STATUS_READY"
STATUS_UNKNOWN = "STATUS_UNKNOWN"
STATUS_BACKING_UP = "STATUS_BACKING_UP"
STATUS_RESTORING = "STATUS_RESTORING"
STATUS_ERROR = "STATUS_ERROR"
COMPONENT_NAMES = []  # should eventually contain 'marathon', 'secrets', etc
BACKUP_READY_TIMEOUT = timedelta(seconds=60)
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

    # this test exercises the expected behavior of dcos-backup
    def test_expected_behavior(self, superuser_api_session):
        self.delete_existing_backups(superuser_api_session)

        # verify no backups exist
        r = superuser_api_session.get('/system/v1/backup/v1/list')
        assert r.status_code == 200
        assert r.text == '{}'

        # create a backup with label=foo
        r = superuser_api_session.post('/system/v1/backup/v1/create', json={"label": "foo"})
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
            if self.is_backup_ready(superuser_api_session, backup_id):
                completed = True
                break
        assert completed, "The backup did not complete in time"

        # perform a restore
        r = superuser_api_session.post('/system/v1/backup/v1/restore', json={"id": backup_id})
        assert r.status_code == 200
        info = r.json().get('backup_info')
        # save a reference to the restore id
        restore_id = info.get('id')
        # wait for the restore to complete successfully
        deadline = datetime.now() + RESTORE_READY_TIMEOUT
        completed = False
        while datetime.now() < deadline:
            time.sleep(POLL_SLEEP)
            if self.is_backup_ready(superuser_api_session, backup_id, restore_id=info['id']):
                completed = True
                break
        assert completed, "The restore did not complete in time"

        # delete the backup using the restore id -- should not work
        r = superuser_api_session.delete('/system/v1/backup/v1/delete', json={'id': restore_id})
        assert r.status_code == 400

        # delete the backup using the backup id -- this should work
        r = superuser_api_session.delete('/system/v1/backup/v1/delete', json={'id': backup_id})
        assert r.status_code == 200

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
