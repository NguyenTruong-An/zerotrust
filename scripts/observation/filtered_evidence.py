"""Project one operator-selected Observatory attempt to shareable JSON on stdout."""

import argparse
import json
import math
from pathlib import Path
import sys

from observe import FEATURES


def choice(value, allowed):
    return value if isinstance(value, str) and value in allowed else None


def bounded_number(value, maximum=100):
    if type(value) not in (int, float) or not 0 <= value <= maximum:
        return None
    return value if math.isfinite(value) else None


def project(report, position):
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise ValueError("Unsupported Observatory report")
    origin = choice(report.get("mode"), {"ILLUSTRATION", "IMPORTED_LOGS", "DOCKER_LOGS"})
    attempts = report.get("attempts")
    if origin is None or not isinstance(attempts, list) or not 1 <= position <= len(attempts):
        raise ValueError("Select an attempt from a supported Observatory report")
    attempt = attempts[position - 1]
    if not isinstance(attempt, dict) or not isinstance(attempt.get("gaps"), list):
        raise ValueError("Invalid Observatory attempt")
    if "CONFLICTING_IDS_OR_DETAILS" in attempt["gaps"]:
        raise ValueError("Conflicting attempt evidence")

    risk = attempt.get("risk")
    risk = risk if isinstance(risk, dict) else {}
    detail = attempt.get("detail")
    inputs = detail.get("features") if isinstance(detail, dict) else None
    features = {}
    if isinstance(inputs, dict):
        for name in FEATURES:
            item = inputs.get(name)
            if isinstance(item, dict):
                features[name] = {
                    "score": bounded_number(item.get("score")),
                    "weight": bounded_number(item.get("weight"), 1),
                    "contribution": bounded_number(item.get("contribution")),
                }

    levels = {"LOW", "MEDIUM", "HIGH"}
    return {
        "schema_version": 1,
        "evidence_type": "SYNTHETIC_ILLUSTRATION" if origin == "ILLUSTRATION" else "FILTERED_HISTORICAL",
        "attempt": "DEMO-ATTEMPT-01",
        "risk_score": bounded_number(risk.get("risk_score")),
        "risk_level": choice(risk.get("risk_level"), levels),
        "calculated_level": choice(risk.get("calculated_level"), levels),
        "effective_level": choice(risk.get("effective_level"), levels),
        "data_status": choice(risk.get("data_status"), {"COMPLETE", "INCOMPLETE", "NOT_EVALUATED"}),
        "decision": choice(risk.get("decision"), {"ALLOW", "STEP_UP_MFA", "DENY"}),
        "mfa": choice(attempt.get("mfa"), {"OTP_EXECUTION_SUCCESS", "RECOVERY_EXECUTION_SUCCESS",
                                          "CHALLENGE_ONLY", "ENROLLMENT_PENDING", "NOT_SELECTED", "NOT_OBSERVED"}),
        "keycloak_outcome": choice(attempt.get("login_outcome"), {"LOGIN_SUCCESS", "LOGIN_ERROR"}),
        "features": features,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True, help="Operator-private Observatory JSON")
    parser.add_argument("--attempt", type=int, required=True, help="One-based attempt position in the report")
    args = parser.parse_args(argv)
    try:
        limit = 16 * 1024 * 1024
        with args.report.open("rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Report too large")
        payload = project(json.loads(data), args.attempt)
    except (OSError, ValueError, RecursionError):
        print("Unable to prepare filtered Observatory evidence.", file=sys.stderr)
        return 1
    print(json.dumps(payload, allow_nan=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
