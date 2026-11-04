import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

import observe


class ObservationTests(unittest.TestCase):
    def test_real_ids_join_risk_details_to_mfa_and_login(self):
        attempts = observe.build_attempts(observe.demo_rows())
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0]["risk"]["risk_score"], 27.5)
        self.assertEqual(attempts[0]["mfa"], "OTP_EXECUTION_SUCCESS")
        self.assertEqual(attempts[0]["login_outcome"], "LOGIN_SUCCESS")
        self.assertEqual(attempts[0]["gaps"], [])

    def test_challenge_never_claims_mfa_success(self):
        rows = [r for r in observe.demo_rows() if r["stage"] not in
                ("MFA_GATE", "DEVICE_REGISTRATION", "AUTHENTICATION_EVENT")]
        attempt = observe.build_attempts(rows)[0]
        self.assertEqual(attempt["mfa"], "CHALLENGE_ONLY")
        self.assertIn("NO_MFA_COMPLETION_PROOF", attempt["gaps"])
        self.assertIn("NO_FINAL_LOGIN_EVENT", attempt["gaps"])

    def test_fallback_never_invents_evaluation_id_or_risk_score(self):
        row = observe.sanitize({"stage": "RISK_EVALUATION", "at": "2026-11-02T03:00:00Z",
            "outcome": "SERVICE_UNAVAILABLE_STEP_UP", "correlation_id": str(uuid.UUID(int=3)),
            "evaluation_id": None, "risk_score": None, "decision": "STEP_UP_MFA"})
        attempt = observe.build_attempts([row])[0]
        self.assertIsNone(attempt["evaluation_id"])
        self.assertIsNone(attempt["risk"]["risk_score"])
        self.assertIsNone(attempt["detail"])
        self.assertEqual(attempt["mfa"], "NOT_OBSERVED")

    def test_same_time_different_ids_never_cross_join(self):
        rows = observe.demo_rows()
        second = copy.deepcopy(rows)
        for row in second:
            if row["evaluation_id"]:
                row["evaluation_id"] = str(uuid.UUID(int=4))
            if row["correlation_id"]:
                row["correlation_id"] = str(uuid.UUID(int=5))
        second = [r for r in second if r["stage"] == "RISK_EVALUATION_DETAILS"]
        attempts = observe.build_attempts(rows + second)
        self.assertEqual(len(attempts), 2)
        standalone = next(a for a in attempts if a["evaluation_id"] == str(uuid.UUID(int=4)))
        self.assertIsNone(standalone["login_outcome"])
        self.assertEqual(standalone["mfa"], "NOT_OBSERVED")

    def test_sso_and_refresh_never_attach_to_nearby_login(self):
        rows = observe.demo_rows()
        for outcome in ("SSO_COOKIE_LOGIN", "REFRESH_SUCCESS_NO_BROWSER_FLOW"):
            rows.append(observe.sanitize({"stage": "AUTHENTICATION_EVENT", "at": rows[0]["at"], "outcome": outcome}))
        attempts = observe.build_attempts(rows)
        self.assertEqual(len(attempts), 3)
        no_evaluation = [a for a in attempts if not a["evaluation_id"]]
        self.assertTrue(all(a["detail"] is None for a in no_evaluation))

    def test_conflicting_correlations_are_not_given_another_attempts_details(self):
        rows = observe.demo_rows()
        conflicting = copy.deepcopy(rows[1])
        conflicting["correlation_id"] = str(uuid.UUID(int=9))
        attempts = observe.build_attempts(rows + [conflicting])
        self.assertTrue(all(a["detail"] is None for a in attempts))
        self.assertTrue(all("CONFLICTING_IDS_OR_DETAILS" in a["gaps"] for a in attempts))

    def test_allowlist_drops_secrets_identifiers_and_arbitrary_nested_objects(self):
        raw = {"stage": "RISK_EVALUATION_DETAILS", "evaluation_id": str(uuid.UUID(int=1)),
            "subjectId": "private-account", "ipAddress": "8.8.8.8", "access_token": "private-token",
            "subject_tag": "private-tag", "features": {"network": {"status": "AVAILABLE",
                "inputs": {"country_code": "VN", "raw_ip": "8.8.8.8", "cookie": "private-cookie"}}}}
        serialized = json.dumps(observe.sanitize(raw))
        for sensitive in ("private-account", "8.8.8.8", "private-token", "private-tag", "private-cookie"):
            self.assertNotIn(sensitive, serialized)
        self.assertIn("VN", serialized)

    def test_malformed_rows_are_skipped_and_null_scores_are_kept(self):
        lines = ["unrelated", "ZEROTRUST_RISK_TRACE {bad}", "ZEROTRUST_RISK_TRACE " +
            json.dumps({"stage": "RISK_EVALUATION", "risk_score": None, "decision": "STEP_UP_MFA"})]
        rows, malformed = observe.parse_lines(lines)
        self.assertEqual(malformed, 1)
        self.assertIsNone(rows[0]["risk_score"])

    def test_html_never_embeds_unescaped_log_text_as_markup(self):
        rows = observe.demo_rows()
        attack = '</script><img src=x onerror="alert(1)">'
        rows[0]["features"]["network"]["inputs"]["city_name"] = attack
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "index.html"
            observe.write_report(rows, output, "ILLUSTRATION")
            html = output.read_text(encoding="utf-8")
            self.assertNotIn(attack, html)
            self.assertIn(r"\u003c/script\u003e", html)
            data = json.loads(output.with_suffix(".json").read_text(encoding="utf-8"))
            self.assertEqual(data["mode"], "ILLUSTRATION")

    def test_large_counter_integers_are_not_rounded_by_javascript(self):
        self.assertEqual(observe.number(9223372036854775806), "9223372036854775806")
        self.assertIsNone(observe.number(10**1000))
        self.assertIsNone(observe.number(float("inf")))

    def test_open_with_watch_launches_once_after_report_exists(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "report with spaces" / "index.html"
            def launch(uri):
                self.assertTrue(output.is_file())
                self.assertEqual(uri, output.resolve().as_uri())
                return True
            with patch("observe.webbrowser.open", side_effect=launch) as browser, \
                    patch("observe.time.sleep", side_effect=[None, KeyboardInterrupt]), \
                    patch("sys.stdout", new=io.StringIO()):
                result = observe.main(["--demo", "--open", "--watch-seconds", "3", "--output", str(output)])
            self.assertEqual(result, 0)
            browser.assert_called_once()

    def test_browser_failure_keeps_report_and_does_not_fail_collection(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "index.html"
            with patch("observe.webbrowser.open", side_effect=OSError("No browser")), \
                    patch("sys.stdout", new=io.StringIO()) as console:
                result = observe.main(["--demo", "--open", "--output", str(output)])
            self.assertEqual(result, 0)
            self.assertTrue(output.is_file())
            self.assertIn("Không tự mở được trình duyệt", console.getvalue())

    def test_demo_default_output_is_separate_from_real_capture(self):
        with tempfile.TemporaryDirectory() as folder, patch("observe.ROOT", Path(folder)), \
                patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(observe.main(["--demo"]), 0)
            preview = Path(folder) / ".local-legacy/risk-observation/preview/index.json"
            self.assertEqual(json.loads(preview.read_text(encoding="utf-8"))["mode"], "ILLUSTRATION")
            self.assertFalse((preview.parent.parent / "latest/index.json").exists())


if __name__ == "__main__":
    unittest.main()
