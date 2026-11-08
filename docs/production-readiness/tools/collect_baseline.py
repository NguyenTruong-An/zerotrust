"""Read-only, allowlisted audit metadata. Never dumps Docker Env or private files.

Run from the repository root: python docs/production-readiness/tools/collect_baseline.py
Only writes evidence/baseline.json next to this tool. Does not start any container.
"""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "docs/production-readiness/evidence"


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, encoding="utf-8", errors="replace").strip()


def inspect(kind, name):
    return json.loads(run("docker", kind, "inspect", name))[0]


def main():
    project = "zerotrust-legacy-integration-20261026"
    result = {"observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "head": run("git", "rev-parse", "HEAD"),
              "branch": run("git", "branch", "--show-current"),
              "upstream": run("git", "rev-parse", "@{u}"),
              "ahead_behind": run("git", "rev-list", "--left-right", "--count", "HEAD...@{u}"),
              "docker_version": run("docker", "version", "--format", "{{.Server.Version}}"),
              "docker_resources": json.loads(run("docker", "info", "--format", '{"cpus":{{.NCPU}},"memory":{{.MemTotal}}}')),
              "containers": [], "networks": [], "source_configuration": {}, "build_manifests": []}
    for service in ("school", "risk-db", "keycloak-db", "redis", "keycloak", "crl", "frontend", "risk", "backend", "gateway"):
        c = inspect("container", project + "-" + service)
        h = c["HostConfig"]
        img = inspect("image", c["Image"])
        result["containers"].append({
            "service": service, "id": c["Id"], "image": c["Image"],
            "state": c["State"]["Status"], "exit_code": c["State"]["ExitCode"],
            "oom_killed": c["State"]["OOMKilled"], "finished_at": c["State"]["FinishedAt"],
            "restart": h["RestartPolicy"], "memory": h["Memory"], "memory_swap": h["MemorySwap"],
            "nano_cpus": h["NanoCpus"], "pids_limit": h["PidsLimit"],
            "user": c["Config"]["User"], "read_only_rootfs": h["ReadonlyRootfs"],
            "cap_drop": h["CapDrop"], "security_opt": h["SecurityOpt"],
            "ports": h["PortBindings"], "logging": h["LogConfig"],
            "environment_names": sorted(x.split("=", 1)[0] for x in c["Config"].get("Env", [])),
            "mounts": [{k: m.get(k) for k in ("Type", "Name", "Source", "Destination", "RW")} for m in c["Mounts"]],
            "networks": sorted(c["NetworkSettings"]["Networks"]),
            "image_created": img["Created"], "repo_digests": img["RepoDigests"],
            "provenance_labels": {k: v for k, v in (img["Config"].get("Labels") or {}).items()
                                  if k in ("org.opencontainers.image.revision", "io.zerotrust.source.snapshot", "io.zerotrust.build.version")}})
    for suffix in ("core", "edge"):
        n = inspect("network", project + "_" + suffix)
        result["networks"].append({"name": n["Name"], "internal": n["Internal"], "driver": n["Driver"]})
    for f in sorted((ROOT / ".build-artifacts").glob("*/build-manifest.json")):
        data = json.loads(f.read_text(encoding="utf-8-sig"))
        # Only known non-sensitive build metadata; never copy arbitrary manifest fields.
        result["build_manifests"].append({"path": f.relative_to(ROOT).as_posix(),
            "keys": sorted(data), **{k: data[k] for k in ("revision", "source_revision", "source_mode", "working_tree_dirty", "snapshot_sha256", "version", "success") if k in data}})
    for base in ("src/main/resources", "gateway/src/main/resources", "risk-scoring-service/src/main/resources"):
        for f in sorted((ROOT / base).glob("application*.properties")):
            content = f.read_text(encoding="utf-8")
            result["source_configuration"][f.relative_to(ROOT).as_posix()] = {
                "sha256": hashlib.sha256(f.read_bytes()).hexdigest(),
                "environment_names": sorted(set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", content)))}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "baseline.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"head": result["head"], "ahead_behind": result["ahead_behind"],
                      "containers": [{"service": c["service"], "state": c["state"], "image": c["image"][:19], "restart": c["restart"]["Name"]} for c in result["containers"]]}, indent=2))


if __name__ == "__main__":
    main()
