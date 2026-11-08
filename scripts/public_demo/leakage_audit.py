"""Bounded local source/history heuristic scan. Emits kind/path/line only, never values or excerpts.
Never scans ignored runtime, key/keystore files, databases, dumps, backups or environment files.
"""
import json
import re
import subprocess
from pathlib import Path

PATTERNS={
    "PRIVATE_KEY_BLOCK":re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{80,}-----END"),
    "ACCESS_TOKEN_PATTERN":re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16})\b"),
    "POTENTIAL_LITERAL_CREDENTIAL":re.compile(r'''(?i)(?:password|client[_-]?secret|pepper)["']?\s*[:=]\s*["']([^"'\r\n]{8,})["']'''),
}
PREFIXES=("src/","risk-scoring-service/src/","keycloak-risk-extension/src/","gateway/src/","frontend/","scripts/","deploy/",".github/")
EXTENSIONS={".java",".py",".ps1",".sh",".json",".properties",".xml",".yaml",".yml",".ts",".tsx",".js",".mjs"}


def eligible(name):
    p=Path(name)
    return (name.startswith(PREFIXES) and (p.suffix in EXTENSIONS or p.name.startswith("Dockerfile"))
            and not any(part.startswith(".env") or part in {"node_modules","target",".local-demo",".local-legacy",".public-demo-private"} for part in p.parts)
            and ".private." not in name)


def scan_text(text,path):
    found=[]
    for kind,pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            value=match.group(0)
            # References are configuration inputs, not embedded secret values.
            if kind=="POTENTIAL_LITERAL_CREDENTIAL" and ("${" in value or "$env:" in value):continue
            found.append({"kind":kind,"path":path,"line":text.count("\n",0,match.start())+1,
                          "status":"SYNTHETIC_TEST_FIXTURE" if "/test/" in path or "/tests/" in path or Path(path).name.startswith("test_") else "REVIEW_SOURCE_CONTEXT"})
    return found


def audit(root,history=True):
    root=Path(root)
    names=subprocess.check_output(["git","ls-files","--cached","--others","--exclude-standard","-z"],cwd=root).decode().split("\0")
    current=[];scanned=0
    for name in names:
        p=root/name
        if not eligible(name) or not p.is_file() or p.stat().st_size>2097152:continue
        scanned+=1;current+=scan_text(p.read_text(encoding="utf-8",errors="replace"),name)
    past=[];objects=0
    if history:
        entries=subprocess.check_output(["git","rev-list","--objects","--all"],cwd=root,text=True).splitlines()
        for line in entries:
            parts=line.split(" ",1)
            if len(parts)!=2 or not eligible(parts[1]):continue
            oid,name=parts
            size=subprocess.check_output(["git","cat-file","-s",oid],cwd=root,text=True).strip()
            if int(size)>2097152:continue
            content=subprocess.check_output(["git","cat-file","blob",oid],cwd=root).decode("utf-8",errors="replace")
            objects+=1;past+=scan_text(content,name)
    return {"scope":"nonignored source and reachable local source blobs <=2MiB; sensitive/ignored files excluded NOT_VERIFIED",
            "current_files":scanned,"history_objects":objects,"current_findings":current,"historical_findings":past,
            "limitations":"heuristics cannot prove absence/revocation; no token/private key value printed; no credential rotation"}


if __name__=="__main__":
    print(json.dumps(audit(Path(__file__).resolve().parents[2]),indent=2))
