"""Read-only Risk/Keycloak trace collector. Standard library only; never saves raw logs."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
import webbrowser

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PREFIXES = ("ZEROTRUST_RISK_SCORE_TRACE ", "ZEROTRUST_RISK_TRACE ")
FEATURES = ("device", "network", "temporal", "authentication_history")
ENUM = re.compile(r"^[A-Z][A-Z0-9_:.\-]{0,79}$")
STAGES = {"RISK_EVALUATION_DETAILS", "RISK_EVALUATION", "RISK_CALL_TIMING", "KEYCLOAK_ENFORCEMENT",
          "MFA_GATE", "MFA_FORM", "DEVICE_REGISTRATION", "AUTHENTICATION_EVENT"}
NUMERIC_INPUTS = set("accuracy_radius_km asn history_window_seconds minimum_events maximum_events sample_size "
                    "day_of_week hour hour_tolerance matching_days matching_hours minimum_day_frequency "
                    "minimum_hour_frequency subject_failures source_ip_failures subject_medium_minimum "
                    "subject_high_minimum source_ip_medium_minimum source_ip_high_minimum failure_window_seconds".split())
ENUM_INPUTS = set("recognition_reason recognition_source ip_source address_scope geoip_status policy_band "
                 "unavailable_reason geoip_scoring_field history_source window_semantics aggregation".split())
TEXT_INPUTS = {"city_name", "geoip_time_zone", "asn_organization", "zone_id"}


def identifier(value):
    try:
        return str(uuid.UUID(value)) if isinstance(value, str) else None
    except (ValueError, AttributeError):
        return None


def enum(value):
    return value if isinstance(value, str) and ENUM.fullmatch(value) else None


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if abs(value) > 9223372036854775807 or (isinstance(value, float) and not math.isfinite(value)):
        return None
    # Preserve exact large Redis/ASN integers when JSON is later consumed by JavaScript.
    return str(value) if isinstance(value, int) and abs(value) > 2**53 - 1 else value


def text(value):
    if not isinstance(value, str):
        return None
    return "".join(c if c.isprintable() else " " for c in value)[:120]


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value if parsed.tzinfo is not None else None
    except ValueError:
        return None


def sanitize_inputs(raw):
    if not isinstance(raw, dict):
        return None
    result = {}
    for key, value in raw.items():
        if key in NUMERIC_INPUTS:
            result[key] = number(value)
        elif key in ENUM_INPUTS:
            result[key] = enum(value)
        elif key in TEXT_INPUTS:
            result[key] = text(value)
        elif key == "evaluated_at":
            result[key] = timestamp(value)
        elif key == "country_code":
            result[key] = value if isinstance(value, str) and re.fullmatch("[A-Z]{2}", value) else None
    return result


def sanitize(raw):
    """Explicit allowlist: never forward subject IDs/tags, IPs, headers, sessions or arbitrary objects."""
    if not isinstance(raw, dict) or raw.get("stage") not in STAGES:
        return None
    row = {"stage": raw["stage"], "at": timestamp(raw.get("at")),
           "evaluation_id": identifier(raw.get("evaluation_id")),
           "correlation_id": identifier(raw.get("correlation_id"))}
    if raw["stage"] == "RISK_EVALUATION_DETAILS" and row["evaluation_id"] is None:
        return None
    for key in ("outcome", "decision", "risk_level", "calculated_level", "effective_level", "data_status",
                "decision_source", "evaluation_source", "risk_execution", "mfa_execution", "failure_type",
                "model_version", "mandatory_step_up_reason"):
        if key in raw:
            row[key] = enum(raw[key])
    for key in ("risk_score", "trust_score", "coverage", "risk_pipeline_duration_ms", "risk_call_duration_ms"):
        if key in raw:
            row[key] = number(raw[key])
    for key in ("mandatory_step_up_present", "user_agent_used_for_scoring"):
        if key in raw:
            row[key] = raw[key] if isinstance(raw[key], bool) else None
    row["reason_codes"] = [item for item in raw.get("reason_codes", [])[:40] if enum(item)] \
        if isinstance(raw.get("reason_codes"), list) else []
    digest = raw.get("numeric_config_digest")
    if isinstance(digest, str) and re.fullmatch("[a-f0-9]{64}", digest):
        row["numeric_config_digest"] = digest
    for key in ("risk_interval", "trust_interval"):
        value = raw.get(key)
        if isinstance(value, list) and len(value) == 2:
            row[key] = [number(item) for item in value]
    thresholds = raw.get("policy_thresholds")
    if isinstance(thresholds, dict):
        row["policy_thresholds"] = {key: number(thresholds.get(key))
                                    for key in ("medium_minimum", "high_minimum")}
    row["features"] = None
    features = raw.get("features")
    if raw["stage"] == "RISK_EVALUATION_DETAILS" and isinstance(features, dict):
        row["features"] = {}
        for name in FEATURES:
            feature = features.get(name)
            if isinstance(feature, dict):
                row["features"][name] = {"status": enum(feature.get("status")),
                                         "source": enum(feature.get("source")),
                                         **{key: number(feature.get(key)) for key in ("score", "weight", "contribution")},
                                         "inputs": sanitize_inputs(feature.get("inputs"))}
    return row


def parse_lines(lines):
    rows, malformed = [], 0
    for line in lines:
        prefix = next((p for p in PREFIXES if p in line), None)
        if prefix is None:
            continue
        if len(line) > 131072:
            malformed += 1
            continue
        try:
            row = sanitize(json.loads(line.split(prefix, 1)[1]))
            if row is not None:
                rows.append(row)
            else:
                malformed += 1
        except (ValueError, TypeError, RecursionError):
            malformed += 1
    return rows, malformed


def event_time(row):
    return dt.datetime.fromisoformat(row["at"].replace("Z", "+00:00")).timestamp() if row.get("at") else 0


def build_attempts(rows, limit=200):
    # No joins by account, nearby time, IP or MFA challenge. IDs are the only correlation evidence.
    unique = {json.dumps(row, sort_keys=True, ensure_ascii=True): row for row in rows}
    rows = sorted(unique.values(), key=event_time)
    owners = {}
    for row in rows:
        if row["evaluation_id"] and row["correlation_id"]:
            owners.setdefault(row["evaluation_id"], set()).add(row["correlation_id"])
    groups = {}
    for row in rows:
        ev, corr = row["evaluation_id"], row["correlation_id"]
        if corr:
            key = "attempt:" + corr
        elif ev and len(owners.get(ev, set())) == 1:
            key = "attempt:" + next(iter(owners[ev]))
        elif ev:
            key = "evaluation:" + ev
        else:
            # SSO/refresh/unobserved events stay independent, even if their times match.
            key = "event:" + hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()[:16]
        groups.setdefault(key, []).append(row)
    result = []
    for key, events in groups.items():
        ids = {e["evaluation_id"] for e in events if e["evaluation_id"]}
        correlations = {e["correlation_id"] for e in events if e["correlation_id"]}
        conflict = len(ids) > 1 or any(len(owners.get(ev, set())) > 1 for ev in ids)
        details = [e for e in events if e["stage"] == "RISK_EVALUATION_DETAILS"]
        detail_conflict = len(details) > 1
        detail = details[0] if len(details) == 1 and not conflict else None
        risk_events = [e for e in events if e["stage"] == "RISK_EVALUATION"]
        risk = detail or (risk_events[-1] if risk_events and not conflict else {})
        auth = [e for e in events if e["stage"] == "AUTHENTICATION_EVENT"]
        outcomes = {e.get("outcome") for e in events}
        proof = [e.get("mfa_execution") for e in events
                 if e.get("mfa_execution") in ("OTP_EXECUTION_SUCCESS", "RECOVERY_EXECUTION_SUCCESS")]
        mfa = proof[-1] if proof else "CHALLENGE_ONLY" if "CHALLENGE_RENDERED" in outcomes else \
            "ENROLLMENT_PENDING" if outcomes & {"ENROLLMENT_PENDING", "MFA_DEFERRED_TO_REQUIRED_ACTION"} else \
            "NOT_SELECTED" if "MFA_SUBFLOW_NOT_SELECTED" in outcomes else "NOT_OBSERVED"
        gaps = []
        if conflict or detail_conflict:
            gaps.append("CONFLICTING_IDS_OR_DETAILS")
        if detail is None:
            gaps.append("NO_RISK_DETAILS")
        elif detail.get("features") and not any(f.get("inputs") for f in detail["features"].values()):
            gaps.append("NO_SIGNAL_INPUTS")
        if not correlations:
            gaps.append("NO_SPI_CORRELATION")
        if not auth:
            gaps.append("NO_FINAL_LOGIN_EVENT")
        if risk.get("decision") == "STEP_UP_MFA" and not proof:
            gaps.append("NO_MFA_COMPLETION_PROOF")
        result.append({"id": key, "evaluation_id": next(iter(ids)) if len(ids) == 1 else None,
                       "correlation_id": next(iter(correlations)) if len(correlations) == 1 else None,
                       "at": events[0]["at"], "last_at": events[-1]["at"], "risk": risk,
                       "detail": detail, "mfa": mfa, "login_outcome": auth[-1].get("outcome") if auth else None,
                       "device_registered": "REGISTERED_204" in outcomes,
                       "cookie_issued": "COOKIE_ISSUED" in outcomes, "gaps": gaps, "events": events})
    return sorted(result, key=lambda a: event_time({"at": a["last_at"]}), reverse=True)[:limit]


def demo_rows():
    """Synthetic illustration only. These records never represent a real login."""
    ev, corr = str(uuid.UUID(int=1)), str(uuid.UUID(int=2))
    at = "2026-11-02T03:00:00Z"
    features = {}
    for name, score in zip(FEATURES, (60, 50, 0, 0)):
        features[name] = {"status": "AVAILABLE", "source": "NEW" if name == "device" else
                          "GEOIP" if name == "network" else None, "score": score,
                          "weight": .25, "contribution": score * .25, "inputs": {}}
    features["device"]["inputs"] = {"recognition_reason": "NOT_REGISTERED"}
    features["network"]["inputs"] = {"address_scope": "PUBLIC", "geoip_status": "AVAILABLE",
        "policy_band": "DEFAULT", "country_code": "VN", "city_name": "Thành phố minh họa",
        "asn": 64512, "asn_organization": "Mạng minh họa", "geoip_scoring_field": "COUNTRY_CODE"}
    features["temporal"]["inputs"] = {"sample_size": 20, "matching_days": 4, "matching_hours": 8,
        "minimum_events": 5, "minimum_day_frequency": .1, "minimum_hour_frequency": .2, "zone_id": "UTC"}
    features["authentication_history"]["inputs"] = {"subject_failures": 0, "source_ip_failures": 0,
        "subject_medium_minimum": 3, "subject_high_minimum": 5, "source_ip_medium_minimum": 10,
        "source_ip_high_minimum": 20, "failure_window_seconds": 900,
        "window_semantics": "COUNTER_TTL_FROM_FIRST_FAILURE"}
    details = {"stage": "RISK_EVALUATION_DETAILS", "at": at, "evaluation_id": ev,
        "risk_score": 27.5, "trust_score": 72.5, "decision": "STEP_UP_MFA", "data_status": "COMPLETE",
        "calculated_level": "LOW", "effective_level": "MEDIUM", "decision_source": "MANDATORY_STEP_UP",
        "mandatory_step_up_reason": "NEW_DEVICE", "reason_codes": ["NEW_DEVICE", "NETWORK_RISK"],
        "model_version": "BASELINE_B0:1", "features": features,
        "policy_thresholds": {"medium_minimum": 40, "high_minimum": 75}}
    rows = [details]
    for i, (stage, outcome, mfa) in enumerate([
        ("RISK_EVALUATION", "EVALUATED", None), ("KEYCLOAK_ENFORCEMENT", "STEP_UP_REQUIRED", None),
        ("MFA_FORM", "CHALLENGE_RENDERED", None), ("MFA_GATE", "RISK_STEP_PASSED", "OTP_EXECUTION_SUCCESS"),
        ("DEVICE_REGISTRATION", "REGISTERED_204", None),
        ("AUTHENTICATION_EVENT", "LOGIN_SUCCESS", "OTP_EXECUTION_SUCCESS")]):
        rows.append({"stage": stage, "outcome": outcome, "at": f"2026-11-02T03:00:{i + 1:02d}Z",
                     "evaluation_id": ev, "correlation_id": corr, "mfa_execution": mfa,
                     "decision": "STEP_UP_MFA"} if i == 0 else
                    {"stage": stage, "outcome": outcome, "at": f"2026-11-02T03:00:{i + 1:02d}Z",
                     "evaluation_id": ev, "correlation_id": corr, "mfa_execution": mfa})
    return [sanitize(row) for row in rows]


def docker(*args):
    try:
        completed = subprocess.run(["docker", *args], capture_output=True, timeout=30, encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("Không đọc được Docker; kiểm tra Docker Desktop.") from error
    if completed.returncode:
        raise RuntimeError("Docker từ chối đọc log. Kiểm tra tên container và Docker Desktop; không có thay đổi runtime.")
    return completed.stdout + (completed.stderr if args and args[0] == "logs" else "")


def resolve_containers(risk, keycloak):
    names = docker("ps", "--format", "{{.Names}}").splitlines()
    def choose(explicit, suffix):
        matches = [n for n in names if n.endswith(suffix)]
        name = explicit or (matches[0] if len(matches) == 1 else None)
        if not name or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", name):
            raise RuntimeError(f"Cần chỉ định container bằng --{suffix[1:]}-container.")
        return name
    return choose(risk, "-risk"), choose(keycloak, "-keycloak")


def write_report(rows, output, mode, malformed=0, watch=0, limit=200):
    report = {"schema_version": 1, "mode": mode, "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "refresh_seconds": watch, "malformed_rows": malformed, "attempts": build_attempts(rows, limit)}
    data = json.dumps(report, ensure_ascii=False, allow_nan=False)
    embedded = data.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e") \
        .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    html = (HERE / "viewer.html").read_text(encoding="utf-8")
    html = html.replace("/*__VIEWER_CSS__*/", (HERE / "viewer.css").read_text(encoding="utf-8"))
    html = html.replace("/*__VIEWER_JS__*/", (HERE / "viewer.js").read_text(encoding="utf-8"))
    html = html.replace("__REPORT_JSON__", embedded)
    output = Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    for path, content in ((output.with_suffix(".json"), data), (output, html)):
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
    return report


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = argparse.ArgumentParser(description="Xem tín hiệu Risk/MFA từ log; không gọi API hay sửa dữ liệu.")
    parser.add_argument("--risk-container")
    parser.add_argument("--keycloak-container")
    parser.add_argument("--risk-log", type=Path)
    parser.add_argument("--keycloak-log", type=Path)
    parser.add_argument("--demo", action="store_true", help="Dữ liệu minh họa, không phải bằng chứng đăng nhập")
    parser.add_argument("--since", default="30m", help="Khoảng log Docker: 30m, 2h…")
    parser.add_argument("--tail", type=int, default=10000)
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--watch-seconds", type=int, default=0)
    parser.add_argument("--open", dest="open_report", action="store_true",
                        help="Mở báo cáo một lần bằng trình duyệt mặc định")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.output is None:
        folder = "preview" if args.demo else "latest"
        args.output = ROOT / ".local-legacy/risk-observation" / folder / "index.html"
    if not 1 <= args.tail <= 100000 or not 1 <= args.limit <= 500:
        parser.error("--tail phải từ 1–100000; --limit từ 1–500")
    if args.watch_seconds and not 3 <= args.watch_seconds <= 300:
        parser.error("--watch-seconds phải từ 3–300")
    if not re.fullmatch(r"[1-9][0-9]{0,5}[smh]", args.since):
        parser.error("--since cần dạng 30m, 2h hoặc 60s")
    if args.output.suffix.lower() != ".html":
        parser.error("--output phải là file .html")
    if args.demo and (args.risk_log or args.keycloak_log or args.risk_container or args.keycloak_container):
        parser.error("--demo phải dùng riêng, không trộn dữ liệu thật")
    try:
        opened = False
        containers = None if args.demo or args.risk_log or args.keycloak_log else resolve_containers(
            args.risk_container, args.keycloak_container)
        while True:
            if args.demo:
                rows, malformed, mode = demo_rows(), 0, "ILLUSTRATION"
            else:
                lines = []
                if containers:
                    for container in containers:
                        lines.extend(docker("logs", "--since", args.since, "--tail", str(args.tail), container).splitlines())
                    mode = "DOCKER_LOGS"
                else:
                    for path in (args.risk_log, args.keycloak_log):
                        if path:
                            lines.extend(path.read_text(encoding="utf-8-sig").splitlines())
                    mode = "IMPORTED_LOGS"
                rows, malformed = parse_lines(lines)
            report = write_report(rows, args.output, mode, malformed, args.watch_seconds, args.limit)
            print(f"{len(report['attempts'])} lần/sự kiện | {mode} | {args.output.resolve()}", flush=True)
            if args.open_report and not opened:
                opened = True
                try:
                    launched = webbrowser.open(args.output.resolve().as_uri())
                except (webbrowser.Error, OSError):
                    launched = False
                if not launched:
                    print(f"Không tự mở được trình duyệt; mở file: {args.output.resolve()}", flush=True)
            if not args.watch_seconds:
                return 0
            time.sleep(args.watch_seconds)
    except KeyboardInterrupt:
        return 0
    except (RuntimeError, OSError, ValueError) as error:
        print(f"Không tạo được báo cáo: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
