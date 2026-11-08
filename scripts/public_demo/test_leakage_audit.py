import json
import unittest
from leakage_audit import scan_text,eligible


class LeakageAuditTest(unittest.TestCase):
    def test_candidates_report_locations_never_values(self):
        marker="synthetic-secret-marker-never-log"
        found=scan_text('clientSecret = "'+marker+'"',"src/main/Fixture.java")
        self.assertEqual(1,len(found));self.assertNotIn(marker,json.dumps(found))
    def test_runtime_secret_files_are_not_read(self):
        for path in (".local-demo/private.key","deploy/.env.production","deploy/keys.private.json","target/fixture.java","deploy/identity.p12"):
            self.assertFalse(eligible(path))
    def test_reference_is_not_a_hardcoded_credential(self):
        self.assertEqual([],scan_text('clientSecret = "${SERVICE_SECRET}"',"src/main/Fixture.java"))
