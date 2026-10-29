"""Offline descriptive analysis of the already verified B0/B1 paired replay.

No Maven, application imports, HTTP, Docker, credentials, database or Redis access.
Fraction arithmetic reconstructs the documented formulas and checks the saved CSV;
counterfactual/perturbation outputs are analytical predictions, not new Java runs.
Only writes derived artifacts under this module's ignored target/research directory.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import unittest
from collections import Counter, defaultdict
from decimal import Decimal, ROUND_HALF_UP
from fractions import Fraction as F
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
RESEARCH = ROOT / "risk-scoring-service/target/research"
INPUT = RESEARCH / "b1-implementation/paired-replay.csv"
OUTPUT = RESEARCH / "b1-evaluation-20261029"
EXPECTED_SHA256 = "6d7bcbd14f8335039c2cb7e047e91a11aba6500f59649717f86a1de15918e82a"
ACTIONS = ("ALLOW", "STEP_UP_MFA", "DENY")


def cents(value: F) -> int:
    if value < 0:
        raise ValueError("Risk cannot be negative")
    q, r = divmod(value.numerator * 100, value.denominator)
    return q + (2 * r >= value.denominator)


def show(value: F | int, places: int = 2) -> str:
    value = F(value)
    return format((Decimal(value.numerator) / Decimal(value.denominator)).quantize(
        Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP), f".{places}f")


def action(score: int, mandatory: bool, medium: int = 4000, high: int = 7500) -> str:
    if score >= high:
        return "DENY"
    return "STEP_UP_MFA" if mandatory or score >= medium else "ALLOW"


def parts(row: dict) -> dict[str, F]:
    n, day, hour, failures = (row[k] for k in ("events", "day_matches", "hour_matches", "subject_failures"))
    return {
        "D": F(0 if row["device"] == "TRUSTED" else 80), "N": F(row["network"]),
        "T0": F(50 * (day * 10 < n) + 50 * (hour * 5 < n)),
        "T1": 50 * (max(F(0), 1 - F(10 * day, n)) + max(F(0), 1 - F(5 * hour, n))),
        "H0": F(100 if failures >= 5 else 50 if failures >= 3 else 0),
        "H1": min(F(100), F(50 * failures, 3) if failures <= 3 else F(50 + 25 * (failures - 3))),
    }


def guard_codes(row: dict) -> str:
    # All replay rows have IP failure count0 and no priority/reset/device-revoke state.
    return ("D" if row["device"] == "MISSING" else "") + ("N" if row["network"] == 100 else "") + (
        "H" if row["subject_failures"] >= 5 else "")


def scores(row: dict) -> dict[str, int]:
    p = parts(row)
    return {name: cents((p["D"] + p["N"] + p[t] + p[h]) / 4) for name, t, h in (
        ("B0", "T0", "H0"), ("T_ONLY", "T1", "H0"),
        ("H_ONLY", "T0", "H1"), ("B1", "T1", "H1"))}


def load_rows(path: Path) -> list[dict]:
    assert hashlib.sha256(path.read_bytes()).hexdigest() == EXPECTED_SHA256, "Unexpected replay: preserve and investigate"
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 4500
    for index, row in enumerate(rows, 1):
        row["pair_id"] = f"P{index:06d}"  # 1-based data row; physical CSV line = index+1.
        for k in ("events", "network", "day_matches", "hour_matches", "subject_failures"):
            row[k] = int(row[k])
        assert row["kind"] == "SYNTHETIC_OFFLINE"
        assert row["device"] in {"TRUSTED", "MISSING"} and row["network"] in {0, 50, 100}
        assert row["events"] in {10, 20, 50, 199, 200}
        assert 0 <= row["day_matches"] <= row["events"] and 0 <= row["hour_matches"] <= row["events"]
        assert 0 <= row["subject_failures"] <= 5
        row["b0"] = int(Decimal(row["b0_score"]) * 100)
        row["b1"] = int(Decimal(row["b1_score"]) * 100)
        s = scores(row)
        assert (s["B0"], s["B1"]) == (row["b0"], row["b1"]), row["pair_id"]
        assert action(row["b0"], bool(guard_codes(row))) == row["b0_decision"]
        assert action(row["b1"], bool(guard_codes(row))) == row["b1_decision"]
    return rows


def distribution(values: list[int]) -> dict:
    ordered = sorted(values)
    def quantile(q: F) -> str:
        position = (len(ordered) - 1) * q
        low = position.numerator // position.denominator
        high = min(low + 1, len(ordered) - 1)
        return show((F(ordered[low]) + (ordered[high] - ordered[low]) * (position - low)) / 100)
    mean = F(sum(values), len(values))
    return {"n": len(values), "mean": show(mean / 100, 4),
            "population_sd": round(math.sqrt(sum(float(v - mean) ** 2 for v in values) / len(values)) / 100, 4),
            **{k: quantile(F(q)) for k, q in (("min", "0"), ("p05", ".05"), ("p25", ".25"),
                ("median", ".5"), ("p75", ".75"), ("p95", ".95"), ("max", "1"))}}


def analyze(rows: list[dict]) -> tuple[dict, list[dict], list[dict]]:
    transitions = Counter((r["b0_decision"], r["b1_decision"]) for r in rows)
    assert {f"{a}->{b}": n for (a, b), n in transitions.items() if a != b} == {
        "ALLOW->STEP_UP_MFA": 122, "STEP_UP_MFA->ALLOW": 1,
        "DENY->STEP_UP_MFA": 42, "STEP_UP_MFA->DENY": 79}
    changed = [r for r in rows if r["b0_decision"] != r["b1_decision"]]
    detailed = []
    for r in changed:
        p, s, guards = parts(r), scores(r), guard_codes(r)
        detailed.append({
            "pair_id": r["pair_id"], **{k: r[k] for k in ("events", "device", "network", "day_matches", "hour_matches", "subject_failures")},
            **{k: show(v) for k, v in p.items()}, "b0_score": r["b0_score"], "b1_score": r["b1_score"],
            "delta_score": show(F(r["b1"] - r["b0"], 100)),
            "temporal_weighted_delta_exact": str((p["T1"] - p["T0"]) / 4),
            "history_weighted_delta_exact": str((p["H1"] - p["H0"]) / 4),
            "b0_decision": r["b0_decision"], "b1_decision": r["b1_decision"], "mandatory_guards": guards or "NONE",
            "priority_present_by_fixture": False, "data_status": "COMPLETE_BY_FIXTURE",
            "complete_replay_policy_violation": action(s["B1"], bool(guards)) != r["b1_decision"],
            "temporal_only_action": action(s["T_ONLY"], bool(guards)),
            "history_only_action": action(s["H_ONLY"], bool(guards)),
            "data_kind": "SYNTHETIC_REPLAY", "browser_feasibility": "CONDITIONAL_NOT_VERIFIED",
        })
    downgraded = [r for r in detailed if r["b0_decision"] == "DENY"]
    assert len(downgraded) == 42 and all(r["mandatory_guards"] != "NONE" for r in downgraded)
    assert all(F(r["temporal_weighted_delta_exact"]) < 0 for r in downgraded)
    assert all(r["temporal_only_action"] == "STEP_UP_MFA" for r in downgraded)

    invariants = {model: {
        "mandatory_to_allow": sum(bool(guard_codes(r)) and r[f"{model}_decision"] == "ALLOW" for r in rows),
        "high_score_not_deny": sum(r[model] >= 7500 and r[f"{model}_decision"] != "DENY" for r in rows),
    } for model in ("b0", "b1")}
    assert all(v == 0 for model in invariants.values() for v in model.values())
    cf_actions = {model: dict(Counter(action(scores(r)[model], bool(guard_codes(r))) for r in rows))
                  for model in ("B0", "T_ONLY", "H_ONLY", "B1")}
    contribution_patterns = {}
    for before, after in transitions:
        if before == after: continue
        subset = [r for r in changed if r["b0_decision"] == before and r["b1_decision"] == after]
        contribution_patterns[f"{before}->{after}"] = {
            "n": len(subset), "T_decreases": sum(parts(r)["T1"] < parts(r)["T0"] for r in subset),
            "H_increases": sum(parts(r)["H1"] > parts(r)["H0"] for r in subset),
            "mandatory": sum(bool(guard_codes(r)) for r in subset),
            "score0_range": [show(F(min(r["b0"] for r in subset), 100)), show(F(max(r["b0"] for r in subset), 100))],
            "score1_range": [show(F(min(r["b1"] for r in subset), 100)), show(F(max(r["b1"] for r in subset), 100))],
        }
    threshold = []
    # Classification what-if on saved scores only: no application/config policy is modified.
    policies = [(m, 7500) for m in (3500, 3999, 4000, 4001, 4500)] + [(4000, h) for h in (7000, 7499, 7501, 8000)]
    for m, h in policies:
        item = {"medium": show(F(m, 100)), "high": show(F(h, 100))}
        for model in ("b0", "b1"):
            item[model] = dict(Counter(action(r[model], bool(guard_codes(r)), m, h) for r in rows))
        item["deny_to_mfa"] = sum(action(r["b0"], bool(guard_codes(r)), m, h) == "DENY" and
                                    action(r["b1"], bool(guard_codes(r)), m, h) == "STEP_UP_MFA" for r in rows)
        threshold.append(item)
    by_size = {}
    for n in sorted({r["events"] for r in rows}):
        subset = [r for r in rows if r["events"] == n]
        by_size[str(n)] = {
            "n": len(subset), "b0_mean": distribution([r["b0"] for r in subset])["mean"],
            "b1_mean": distribution([r["b1"] for r in subset])["mean"],
            "transitions": dict(Counter(r["b0_decision"] + "->" + r["b1_decision"] for r in subset
                                        if r["b0_decision"] != r["b1_decision"])),
        }
    summary = {
        "dataset_sha256": EXPECTED_SHA256, "cases": len(rows), "label_kind": "UNLABELLED_SYNTHETIC_FEATURE_GRID",
        "score": {m: distribution([r[m] for r in rows]) for m in ("b0", "b1")},
        "trust": {m: distribution([10000 - r[m] for r in rows]) for m in ("b0", "b1")},
        "delta": distribution([r["b1"] - r["b0"] for r in rows]),
        "mean_absolute_delta": show(F(sum(abs(r["b1"] - r["b0"]) for r in rows), 100 * len(rows)), 4),
        "score_direction": dict(Counter("UP" if r["b1"] > r["b0"] else "DOWN" if r["b1"] < r["b0"] else "EQUAL" for r in rows)),
        "feature_means": {k: show(sum((parts(r)[k] for r in rows), F()) / len(rows), 6)
                          for k in ("D", "N", "T0", "T1", "H0", "H1")},
        "matrix": {a: {b: transitions[a, b] for b in ACTIONS} for a in ACTIONS},
        "attribution": contribution_patterns, "normalization_ablations": cf_actions,
        "invariants_on_complete_grid": invariants, "by_history_size": by_size,
        "threshold_what_if": threshold,
        "threshold_margins": {m: {str(t // 100): {
            "exact_threshold": sum(r[m] == t for r in rows),
            "within_one_point": sum(abs(r[m] - t) <= 100 for r in rows),
        } for t in (4000, 7500)} for m in ("b0", "b1")},
        "low_score_mfa_due_to_guard": {m: sum(r[m] < 4000 and bool(guard_codes(r)) for r in rows) for m in ("b0", "b1")},
        "all_denied_have_mandatory_signal": {m: all(bool(guard_codes(r)) for r in rows if r[m] >= 7500) for m in ("b0", "b1")},
        "downgrade_groups": dict(Counter((r["device"], r["network"], r["T0"], r["H0"], r["mandatory_guards"]) for r in downgraded)),
        "missing_or_cold_start_in_replay": 0,
    }
    summary["downgrade_groups"] = [{"device": k[0], "network": k[1], "T0": k[2], "H0": k[3],
                                    "guards": k[4], "n": v} for k, v in summary["downgrade_groups"].items()]
    return summary, detailed, downgraded


def stability(rows: list[dict]) -> dict:
    result = {}
    identity_fields = ("events", "device", "network", "day_matches", "hour_matches", "subject_failures")
    existing = {tuple(r[k] for k in identity_fields) for r in rows}
    for feature in ("day_matches", "hour_matches", "subject_failures", "network"):
        metrics = {m: {"edges": 0, "score_changed": 0, "decision_flips": 0, "max_abs_delta_cents": 0,
                       "sum_abs_delta_cents": 0, "guard_set_changed_edges": 0,
                       "guard_presence_changed_edges": 0, "flips_guard_unchanged": 0}
                   for m in ("B0", "B1")}
        sizes = defaultdict(lambda: {m: {"edges": 0, "decision_flips": 0, "max_abs_delta_cents": 0} for m in ("B0", "B1")})
        saved_neighbors = 0
        for r in rows:
            v = r[feature]
            limit = r["events"] if feature in ("day_matches", "hour_matches") else 5 if feature == "subject_failures" else 100
            if v >= limit: continue
            other = dict(r); other[feature] = v + (50 if feature == "network" else 1)
            saved_neighbors += tuple(other[k] for k in identity_fields) in existing
            same_guard = guard_codes(r) == guard_codes(other)
            before, after = scores(r), scores(other)
            for m in metrics:
                delta = abs(after[m] - before[m])
                flip = action(before[m], bool(guard_codes(r))) != action(after[m], bool(guard_codes(other)))
                entry = metrics[m]
                entry["edges"] += 1; entry["score_changed"] += delta != 0; entry["decision_flips"] += flip
                entry["sum_abs_delta_cents"] += delta
                entry["max_abs_delta_cents"] = max(entry["max_abs_delta_cents"], delta)
                entry["guard_set_changed_edges"] += not same_guard
                entry["guard_presence_changed_edges"] += bool(guard_codes(r)) != bool(guard_codes(other))
                entry["flips_guard_unchanged"] += flip and same_guard
                by_size = sizes[str(r["events"])][m]
                by_size["edges"] += 1; by_size["decision_flips"] += flip
                by_size["max_abs_delta_cents"] = max(by_size["max_abs_delta_cents"], delta)
        result[feature] = {"kind": "ANALYTICAL_ONE_COORDINATE_PERTURBATION_NOT_NEW_JAVA_RUN",
                           "neighbor_already_in_saved_replay_edges": saved_neighbors,
                           "metrics": metrics, "by_history_size": dict(sizes)}
    return result


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)


class AnalysisTests(unittest.TestCase):
    def test_half_up_and_exact_boundaries(self):
        self.assertEqual(cents(F(7999, 200)), 4000)
        self.assertEqual(cents(F(14999, 200)), 7500)
        self.assertEqual(action(3999, False), "ALLOW")
        self.assertEqual(action(4000, False), "STEP_UP_MFA")
        self.assertEqual(action(7500, True), "DENY")

    def test_saved_mfa_to_allow_case(self):
        r = {"device": "TRUSTED", "network": 50, "events": 20, "day_matches": 1,
             "hour_matches": 3, "subject_failures": 3}
        self.assertEqual(scores(r)["B0"], 5000)
        self.assertEqual(scores(r)["B1"], 3438)
        self.assertFalse(guard_codes(r))

    def test_guard_survives_a_low_score(self):
        self.assertEqual(action(0, True), "STEP_UP_MFA")
        self.assertEqual(action(7500, False), "DENY")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = unittest.main(argv=[__file__], exit=False)
        if not result.result.wasSuccessful():
            raise SystemExit(1)
        return
    rows = load_rows(INPUT)
    summary, changed, downgraded = analyze(rows)
    summary["sensitivity_stability"] = stability(rows)
    source_paths = [
        "risk-scoring-service/src/main/java/com/zerotrust/risk/service/BehavioralRiskNormalizer.java",
        "risk-scoring-service/src/main/java/com/zerotrust/risk/service/RiskScoringService.java",
        "risk-scoring-service/src/main/java/com/zerotrust/risk/service/RiskEvaluationService.java",
        "risk-scoring-service/src/test/java/com/zerotrust/risk/audit/B1ImplementationTests.java",
        "risk-scoring-service/src/test/java/com/zerotrust/risk/audit/AuditRiskFixture.java",
    ]
    summary["source_sha256"] = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in source_paths}
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "metrics.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    write_csv(OUTPUT / "decision-differences.csv", changed)
    write_csv(OUTPUT / "deny-to-mfa-42.csv", downgraded)
    print(json.dumps({"verified_saved_pairs": len(rows), "differences": len(changed),
                      "deny_to_mfa": len(downgraded), "output": OUTPUT.relative_to(ROOT).as_posix()}))


if __name__ == "__main__":
    main()
