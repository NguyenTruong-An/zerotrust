"""Limited local secret-pattern scan of reachable Git blobs. Outputs locations only.

No credential values or hashes of credentials are emitted. This is NOT Gitleaks
and cannot certify absence of secrets, particularly binary keystores/deleted refs.
"""
import json
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[3]
objects = subprocess.check_output(["git", "rev-list", "--objects", "--all"], cwd=root).decode().splitlines()
entries = [x.split(" ", 1) for x in objects if " " in x]
payload = ("\n".join(x[0] for x in entries) + "\n").encode()
process = subprocess.run(["git", "cat-file", "--batch"], cwd=root, input=payload, stdout=subprocess.PIPE, check=True)
data, pos, scanned, oversized, findings = process.stdout, 0, 0, 0, []
rules = {
    "private_key_marker": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "github_token_pattern": re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{50,255})"),
    "literal_secret_assignment_candidate": re.compile(rb"(?im)^\s*[\w.-]*(?:password|client-secret|pepper)[\w.-]*\s*[=:]\s*([^\r\n]{4,})$")}
for object_id, path in entries:
    end = data.index(b"\n", pos)
    header = data[pos:end].decode().split()
    pos = end + 1
    if len(header) != 3:
        continue
    size = int(header[2])
    blob = data[pos:pos+size]
    pos += size + 1
    if header[1] != "blob":
        continue
    if size > 2_000_000:
        oversized += 1
        continue
    scanned += 1
    if b"\0" in blob:
        continue
    for category, pattern in rules.items():
        for hit in pattern.finditer(blob):
            if category == "literal_secret_assignment_candidate":
                value = hit.group(1).strip()
                if (b"${" in value or b"os.environ" in value or b"getenv" in value or b"[REDACTED]" in value
                        or value.startswith((b"#", b"<", b"null", b"None"))):
                    continue
            findings.append({"path": path, "blob": object_id, "line": blob[:hit.start()].count(b"\n")+1,
                             "category": category,
                             "context": "test_or_fixture" if any(s in path.lower() for s in ("test", "fixture", "demo", "example", "qa-")) else "needs_manual_triage"})
result = {"scope": "All reachable objects in local refs; unique blobs; text <=2MB; limited regexes; no values emitted",
          "objects_with_path": len(entries), "blobs_scanned": scanned, "oversized_skipped": oversized,
          "findings": findings}
out = root / "docs/production-readiness/evidence/git-secret-patterns.json"
out.write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
print(json.dumps({"blobs_scanned": scanned, "oversized_skipped": oversized,
    "findings": len(findings), "manual_triage": [x for x in findings if x["context"] == "needs_manual_triage"][:50]}, indent=2))
