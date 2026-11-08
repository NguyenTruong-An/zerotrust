import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from filtered_evidence import project
from observe import build_attempts, demo_rows


def illustration():
    return {"schema_version": 1, "mode": "ILLUSTRATION", "attempts": build_attempts(demo_rows())}


class FilteredEvidenceTest(unittest.TestCase):
    def test_preserves_captured_scores_weights_and_mfa_with_synthetic_label(self):
        report = illustration()
        payload = project(report, 1)
        self.assertEqual("SYNTHETIC_ILLUSTRATION", payload["evidence_type"])
        self.assertEqual(27.5, payload["risk_score"])
        self.assertEqual("LOW", payload["calculated_level"])
        self.assertEqual("MEDIUM", payload["effective_level"])
        self.assertEqual("STEP_UP_MFA", payload["decision"])
        self.assertEqual("OTP_EXECUTION_SUCCESS", payload["mfa"])
        self.assertEqual("LOGIN_SUCCESS", payload["keycloak_outcome"])
        self.assertEqual({"score": 60, "weight": .25, "contribution": 15}, payload["features"]["device"])

    def test_allowlist_reconstructs_nested_fields_and_drops_unknown_values(self):
        report = illustration()
        attempt = report["attempts"][0]
        sensitive = dict(password="canary-pass", otp="canary-otp", recovery="canary-recovery",
                         authorization="canary-token", refresh_token="canary-refresh", cookie="canary-cookie",
                         client_secret="canary-secret", private_key="canary-key", raw_ip="203.0.113.47",
                         user_agent="canary-agent", fingerprint="canary-device", account_id="canary-account")
        attempt.update(sensitive)
        attempt["risk"].update(sensitive, risk_level="CANARY_CONTEXT")
        attempt["detail"]["features"]["network"]["inputs"].update(sensitive)
        attempt["detail"]["features"]["network"]["score"] = float("inf")
        attempt["detail"]["features"]["network"]["contribution"] = True
        report.update(sensitive)
        output = project(report, 1)
        text = json.dumps(output, allow_nan=False)
        for value in [*sensitive.values(), attempt["evaluation_id"], attempt["correlation_id"], "CANARY_CONTEXT", "64512", "city_name", "generated_at"]:
            self.assertNotIn(value, text)
        self.assertEqual({"score": None, "weight": .25, "contribution": None}, output["features"]["network"])
        self.assertEqual("DEMO-ATTEMPT-01", output["attempt"])

    def test_historical_and_missing_proof_stay_distinct(self):
        for mode in ("IMPORTED_LOGS", "DOCKER_LOGS"):
            report = illustration()
            report["mode"] = mode
            attempt = report["attempts"][0]
            attempt.update(risk={"data_status": "INCOMPLETE"}, detail=None,
                           login_outcome=None, mfa="ENROLLMENT_PENDING")
            output = project(report, 1)
            self.assertEqual("FILTERED_HISTORICAL", output["evidence_type"])
            self.assertEqual("ENROLLMENT_PENDING", output["mfa"])
            self.assertIsNone(output["risk_score"])
            self.assertIsNone(output["keycloak_outcome"])
            self.assertEqual({}, output["features"])

    def test_conflict_invalid_mode_and_unselected_attempt_are_rejected(self):
        report = illustration()
        with self.assertRaises(ValueError):
            project(report, 0)
        with self.assertRaises(ValueError):
            project({**report, "mode": "LIVE_VERIFIED"}, 1)
        report["attempts"][0]["gaps"].append("CONFLICTING_IDS_OR_DETAILS")
        with self.assertRaises(ValueError):
            project(report, 1)

    def test_cli_outputs_only_projection_and_redacts_invalid_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "operator.json"
            path.write_text(json.dumps(illustration()), encoding="utf-8")
            cmd = [sys.executable, str(Path(__file__).with_name("filtered_evidence.py")),
                   "--report", str(path), "--attempt", "1"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.assertEqual(project(illustration(), 1), json.loads(result.stdout))
            path.write_text('{"password":"CANARY-PASSWORD"', encoding="utf-8")
            bad = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(1, bad.returncode)
            self.assertEqual("", bad.stdout)
            self.assertNotIn("CANARY-PASSWORD", bad.stderr)
