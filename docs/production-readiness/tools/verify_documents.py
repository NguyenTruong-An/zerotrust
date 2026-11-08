"""Non-destructive link/syntax/limited-redaction QA for authored audit artifacts."""
import ast
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
issues, checked, coordinate_false_positives = [], 0, 0
required = ["PRODUCTION_READINESS_REPORT.md", "SECURITY_AUDIT.md", "PRODUCTION_ARCHITECTURE.md",
            "PRODUCTION_GAP_ANALYSIS.md", "PRODUCTION_DEPLOYMENT_PLAN.md", "PRODUCTION_OPERATIONS_RUNBOOK.md",
            "PRODUCTION_ROLLBACK_PLAN.md", "PRODUCTION_ACCEPTANCE_CHECKLIST.md", "PRODUCTION_GO_NO_GO.md"]
for name in required:
    if not (ROOT / name).is_file():
        issues.append({"missing_required": name})
for p in (ROOT / "tools").glob("*.py"):
    ast.parse(p.read_text(encoding="utf-8"))
for p in (ROOT / "evidence").glob("*.json"):
    json.loads(p.read_text(encoding="utf-8-sig"))
for p in (ROOT / "evidence").glob("*.jsonl"):
    for line in p.read_text(encoding="utf-8-sig").splitlines():
        json.loads(line)
for p in ROOT.glob("*.md"):
    content = p.read_text(encoding="utf-8")
    if content.count("```") % 2:
        issues.append({"file": p.name, "error": "unbalanced_fences"})
    for label, target in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", content):
        if target.startswith(("https://", "http://", "mailto:", "#")):
            continue
        filename, _, anchor = target.partition("#")
        destination = p.parent / filename
        checked += 1
        if not destination.exists():
            issues.append({"file": p.name, "missing_link": target})
        if anchor == "performance-gate" and "## Performance gate" not in destination.read_text(encoding="utf-8"):
            issues.append({"file": p.name, "missing_anchor": target})
    # Maven coordinates have @1.2.3.Final and must not be mistaken for email.
    for hit in re.finditer(r"(?<![\w])[-\w.]+@[-\w.]+\.[A-Za-z]{2,}", content):
        if "example.invalid" in hit.group():
            continue
        if p.name == "DEPENDENCY_FINDINGS.md" and re.search(r"@[0-9]+\.[0-9]+", hit.group()):
            coordinate_false_positives += 1
            continue
        issues.append({"file": p.name, "potential_sensitive_pattern": "email", "line": content[:hit.start()].count("\n")+1})
    for pattern in (r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
                    r"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}",
                    r"\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b"):
        if re.search(pattern, content):
            issues.append({"file": p.name, "potential_sensitive_pattern": "key_or_token"})
result = {"required_documents": len(required), "markdown_files": len(list(ROOT.glob("*.md"))),
          "local_links_checked": checked, "python_syntax": "parsed", "json_syntax": "parsed",
          "version_coordinates_triaged_as_not_email": coordinate_false_positives,
          "issues": issues, "mermaid_rendered": False,
          "scope": "Authored document/link/syntax/limited-redaction QA; not application acceptance or complete secret scan"}
(ROOT / "evidence/document-qa.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
print(json.dumps(result, indent=2))
raise SystemExit(bool(issues))
