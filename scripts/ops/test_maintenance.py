import unittest
from unittest.mock import patch

import backup
import maintenance
import zt
from test_zt import container


class MaintenanceTests(unittest.TestCase):
    def test_running_or_stopped_container_image_is_never_cleanup_candidate(self):
        self.assertEqual(maintenance.classify_image('id', [], {'id'}, set(), ''), 'in_use')

    def test_untagged_release_image_is_protected_by_manifest(self):
        self.assertEqual(maintenance.classify_image('id', [], set(), {'id'}, ''), 'keep_release_or_rollback')

    def test_rollback_alias_and_base_digest_are_kept(self):
        for tags, text in [(['app:rollback-previous'], ''), ([], 'FROM runtime@id'), (['app:v1'], 'image: app:v1')]:
            self.assertEqual(maintenance.classify_image('id', tags, set(), set(), text), 'keep_config_reference_or_rollback')

    def test_unused_means_review_not_permission_to_delete(self):
        self.assertEqual(maintenance.classify_image('id', [], set(), set(), ''), 'review_unused')

    def test_partial_lab_is_rejected_before_backup_or_stop(self):
        rows = {s: container(s) for s in zt.SERVICES}
        rows['school']['State']['Running'] = True
        with patch.object(zt, 'collect', return_value=rows), patch.object(zt, 'diagnose', return_value={'errors': []}), \
                patch.object(backup.layout, 'secure_directory') as mkdir, patch.object(backup.subprocess, 'run') as action:
            with self.assertRaisesRegex(RuntimeError, 'whole lab'):
                backup.main()
            mkdir.assert_not_called()
            action.assert_not_called()


if __name__ == '__main__':
    unittest.main()
