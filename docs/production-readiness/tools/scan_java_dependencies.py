"""Inventory executable JAR runtime dependencies and query OSV by coordinates.

Only public Maven coordinates/versions leave the machine. OS/package images and
provided Keycloak libraries are NOT covered. Run against a test build directory.
"""
import concurrent.futures
import datetime
import hashlib
import io
import json
from pathlib import Path
import sys
import urllib.request
import zipfile


def request(url, data=None):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "ZeroTrust-authorized-readiness-audit"})
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.load(response)


def main():
    build_root, output = Path(sys.argv[1]), Path(sys.argv[2])
    packages, inventory, unresolved = {}, [], []
    for module in (".", "risk-scoring-service", "gateway"):
        target = build_root / module / "target"
        jars = [p for p in target.glob("*.jar") if not p.name.endswith(("-sources.jar", "-tests.jar"))]
        if not jars:
            continue
        outer = zipfile.ZipFile(jars[0])
        for name in outer.namelist():
            if not name.startswith("BOOT-INF/lib/") or not name.endswith(".jar"):
                continue
            nested = zipfile.ZipFile(io.BytesIO(outer.read(name)))
            found = False
            for prop in nested.namelist():
                if not prop.startswith("META-INF/maven/") or not prop.endswith("/pom.properties"):
                    continue
                fields = {}
                for line in nested.read(prop).decode(errors="replace").splitlines():
                    if "=" in line and not line.startswith("#"):
                        key, value = line.split("=", 1)
                        fields[key] = value
                if not all(k in fields for k in ("groupId", "artifactId", "version")):
                    continue
                found = True
                package = fields["groupId"] + ":" + fields["artifactId"]
                key = (package, fields["version"])
                packages.setdefault(key, set()).add(module)
                inventory.append({"module": module, "jar": name, "package": package, "version": fields["version"]})
            if not found:
                unresolved.append({"module": module, "jar": name})
    # Spring/Tomcat jars often omit pom.properties. Resolve against Maven's tree,
    # accepting ONLY artifacts whose exact jar filename exists in the executable JAR.
    for module in (".", "risk-scoring-service", "gateway"):
        tree = build_root / module / "target/audit-dependencies.json"
        if not tree.exists():
            continue
        runtime_names = {Path(x["jar"]).name for x in unresolved if x["module"] == module}
        def visit(node):
            filename = node["artifactId"] + "-" + node["version"]
            if node.get("classifier"):
                filename += "-" + node["classifier"]
            filename += ".jar"
            if filename in runtime_names:
                package = node["groupId"] + ":" + node["artifactId"]
                packages.setdefault((package, node["version"]), set()).add(module)
                inventory.append({"module": module, "jar": "BOOT-INF/lib/" + filename, "package": package,
                                  "version": node["version"], "coordinate_source": "Maven dependency tree matched to executable JAR filename"})
            for child in node.get("children", []):
                visit(child)
        visit(json.loads(tree.read_text()))
    resolved = {(x["module"], x["jar"]) for x in inventory}
    unresolved = [x for x in unresolved if (x["module"], x["jar"]) not in resolved]
    # Maven trees omit conflict nodes. Confirm the remaining jar bytes against
    # local Maven repository files, then use that repository coordinate path.
    cache = Path.home() / ".m2/repository"
    needed = {Path(x["jar"]).name for x in unresolved}
    candidates = {}
    for jar in cache.rglob("*.jar"):
        if jar.name in needed:
            candidates.setdefault(jar.name, []).append(jar)
    for item in unresolved:
        outer_path = next((build_root / item["module"] / "target").glob("*.jar"))
        with zipfile.ZipFile(outer_path) as outer:
            expected = hashlib.sha256(outer.read(item["jar"])).digest()
        for candidate in candidates.get(Path(item["jar"]).name, []):
            if hashlib.sha256(candidate.read_bytes()).digest() != expected:
                continue
            relative = candidate.relative_to(cache).parts
            group, artifact, version = ".".join(relative[:-3]), relative[-3], relative[-2]
            package = group + ":" + artifact
            packages.setdefault((package, version), set()).add(item["module"])
            inventory.append({**item, "package": package, "version": version,
                "coordinate_source": "Exact SHA256 match to local Maven repository JAR and coordinate path"})
            break
    resolved = {(x["module"], x["jar"]) for x in inventory}
    unresolved = [x for x in unresolved if (x["module"], x["jar"]) not in resolved]
    keys = sorted(packages)
    query = {"queries": [{"package": {"ecosystem": "Maven", "name": name}, "version": version} for name, version in keys]}
    response = request("https://api.osv.dev/v1/querybatch", query)
    ids = sorted({v["id"] for r in response["results"] for v in r.get("vulns", [])})
    matches = [{"package": name, "version": version, "modules": sorted(packages[(name, version)]),
                "advisory_ids": [v["id"] for v in r.get("vulns", [])]}
               for (name, version), r in zip(keys, response["results"]) if r.get("vulns")]
    previous = json.loads(output.read_text()) if output.exists() else {}
    result = {"observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "scope": "Executable Spring Boot JAR nested runtime libraries with Maven pom.properties; no exploit proof; excludes OS/JDK and Keycloak server/provided libs",
              "unique_coordinates": len(keys), "inventory": inventory, "unresolved": unresolved,
              "matches": matches, "advisories": previous.get("advisories", {}), "detail_errors": []}
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    def detail(identifier):
        try:
            return identifier, request("https://api.osv.dev/v1/vulns/" + identifier), None
        except Exception as error:
            return identifier, None, type(error).__name__
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        for identifier, advisory, error in executor.map(detail, [i for i in ids if i not in result["advisories"]]):
            if advisory is not None:
                result["advisories"][identifier] = advisory
            else:
                result["detail_errors"].append({"id": identifier, "error_type": error})
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"coordinates": len(keys), "unresolved_jars": len(unresolved), "matches": matches, "advisories": len(ids)}, indent=2))


if __name__ == "__main__":
    main()
