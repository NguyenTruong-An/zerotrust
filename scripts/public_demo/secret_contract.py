"""Reference-only Public Demo secret policy and fail-closed preflight. Never prints values/digests.
File checks are explicit opt-in, for authorized new-environment files, never Lab discovery.
"""
import argparse
import copy
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath

BINDINGS = {
    "backend": {"spring.datasource.password": "school-db-runtime", "keycloak.admin.client-secret": "portal-identity-client",
                "app.risk-admin.client-secret": "portal-risk-client", "server.ssl.key-store-password": "portal-tls-password",
                "portal-tls.p12": "portal-tls-keystore"},
    "risk": {"spring.datasource.password": "risk-db-runtime", "spring.data.redis.password": "risk-redis-auth",
             "risk.device-fingerprint.pepper": "device-pepper", "risk.authentication-history.pepper": "history-pepper",
             "server.ssl.key-store-password": "risk-tls-password", "risk-tls.p12": "risk-tls-keystore"},
    "keycloak": {"/run/public-demo/keycloak.conf": "keycloak-runtime-config", "risk-caller-client-secret": "risk-caller-client",
                 "keycloak-tls.p12": "keycloak-tls-keystore"},
    "gateway": {"server.ssl.key-store-password": "gateway-tls-password", "gateway-tls.p12": "gateway-tls-keystore"},
    "redis": {"/run/public-demo/redis.conf": "redis-runtime-config"},
}


def require(valid):
    if not valid:
        raise ValueError("Public Demo secret contract rejected (values and paths redacted)")


def template(stage="production"):
    require(stage in ("staging", "production"))
    entries = {}
    for consumer, bindings in BINDINGS.items():
        for target, identifier in bindings.items():
            entries[identifier] = {"file": f"/srv/zerotrust-secrets/{stage}/{identifier}", "mode": "0400",
                                   "owner": consumer+" runtime UID; verify candidate", "target": target, "consumer": consumer}
    return {"version": 1, "environment": stage, "not_a_deployment": True,
            "entries": entries, "bindings": copy.deepcopy(BINDINGS),
            "keycloak_environment": {"PUBLIC_DEMO_MODE": "public-demo", "PUBLIC_DEMO_ACADEMIC_READ_ONLY": "true",
                                     "PUBLIC_DEMO_RISK_CALLER_SECRET_FILE": "/run/secrets/risk-caller-client-secret"},
            "forbidden_runtime_material": ["ca-private-key", "backup-decryption-key", "bootstrap-admin-password", "lab-export"],
            "read_only_mounts": True, "native_ownership_acceptance_required": True}


def validate(c):
    try:
        require(set(c) == set(template()))
        require(c["version"] == 1 and c["environment"] in ("production", "staging") and c["not_a_deployment"] is True)
        expected = template(c["environment"])
        require(c["bindings"] == BINDINGS and c["keycloak_environment"] == expected["keycloak_environment"])
        require(c["forbidden_runtime_material"] == expected["forbidden_runtime_material"])
        require(c["read_only_mounts"] is True and c["native_ownership_acceptance_required"] is True)
        require(set(c["entries"]) == set(expected["entries"]))
        for identifier, entry in c["entries"].items():
            require(entry == expected["entries"][identifier])
        return c
    except (KeyError, TypeError, AttributeError):
        raise ValueError("Public Demo secret contract rejected (values and paths redacted)") from None


def validate_files(c, root=None):
    """root is an explicit synthetic/authorized relocated directory, never searched automatically."""
    validate(c)
    fingerprints = set()
    try:
        for identifier, entry in c["entries"].items():
            path = Path(entry["file"]) if root is None else Path(root)/identifier
            metadata = path.lstat()
            require(stat.S_ISREG(metadata.st_mode) and 16 <= metadata.st_size <= 1048576)
            if os.name == "posix":
                require(stat.S_IMODE(metadata.st_mode) == 0o400)
            # lstat + O_NOFOLLOW prevent final-component symlink substitution where supported.
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                require(stat.S_ISREG(opened.st_mode) and (metadata.st_dev, metadata.st_ino) == (opened.st_dev, opened.st_ino))
                payload = stream.read(1048577)
            require(16 <= len(payload) <= 1048576)
            digest = hashlib.sha256(payload).digest()
            require(digest not in fingerprints)
            fingerprints.add(digest)  # No digest or raw content is returned/logged.
    except Exception:
        raise ValueError("Public Demo secret file validation rejected (values and paths redacted)") from None


def validate_keycloak_config(text):
    """Validate a private rendered secret config before native startup; no realm/store connection."""
    try:
        pairs = {}
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            k, v = line.split("=", 1)
            require(k not in pairs)
            pairs[k] = v
        for key in ("db-password", "https-key-store-password"):
            require(16 <= len(pairs[key]) <= 4096 and not pairs[key].isspace() and "${" not in pairs[key])
        require(pairs["db-password"] != pairs["https-key-store-password"])
        require(pairs.get("http-enabled") == "false" and pairs.get("hostname-strict") == "true")
        require(pairs.get("spi-connections-jpa--quarkus--migration-strategy") == "validate")
        require(pairs.get("spi-connections-jpa--quarkus--initialize-empty") == "false")
    except Exception:
        raise ValueError("Private Keycloak configuration rejected (values redacted)") from None


REDIS_COMMANDS={"ping","hello","client|setinfo","client|setname","select","eval","evalsha","script|load","time","exists","type","get","set","incr","expire"}


def validate_redis_config(text):
    """ACL contract only; TLS/storage/command behavior still needs native acceptance."""
    try:
        users=[line.split() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        require(len(users)==1)
        tokens=users[0]
        require(tokens[:4]==["user","default","reset","on"] and re.fullmatch(r"#[a-f0-9]{64}",tokens[4]) is not None)
        require(tokens[5:10]==["resetkeys","~zerotrust:risk:auth-history:*","resetchannels","-@all","+ping"])
        require(len(tokens)==9+len(REDIS_COMMANDS) and set(tokens[9:])=={"+"+command for command in REDIS_COMMANDS})
    except Exception:
        raise ValueError("Private Redis ACL configuration rejected (values redacted)") from None


def validate_deployment(config):
    """Additional check to compose preflight; no file content or Docker inspection."""
    try:
        services = config["services"]
        stage=services["backend"]["environment"]["PUBLIC_DEMO_ENVIRONMENT"]
        require(stage in ("production","staging") and services["risk"]["environment"]["PUBLIC_DEMO_ENVIRONMENT"]==stage)
        sources = set()
        for name in BINDINGS:
            service = services[name]
            require(not service.get("build") and not service.get("env_file") and not service.get("privileged"))
            env = service.get("environment", {})
            require(isinstance(env, dict))
            for key, value in env.items():
                upper = key.upper().replace("-", "_")
                sensitive = any(term in upper for term in ("PASSWORD", "SECRET", "PEPPER", "PRIVATE_KEY")) or ("TOKEN" in upper and not upper.endswith(("TOKEN_URI","TOKEN_URL")))
                require(not sensitive or (name == "keycloak" and key == "PUBLIC_DEMO_RISK_CALLER_SECRET_FILE"
                                         and value == "/run/secrets/risk-caller-client-secret"))
                require(upper not in {"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "SPRING_APPLICATION_JSON"})
            mounts = service.get("secrets", [])
            require(len(mounts) == len(BINDINGS[name]))
            targets = set()
            for mount in mounts:
                require(set(mount) == {"source", "target", "mode"} and mount["mode"] in (0o400, "0400"))
                require(mount["target"] not in targets)
                targets.add(mount["target"])
                require(mount["source"] not in sources)
                sources.add(mount["source"])
                declaration = config["secrets"][mount["source"]]
                require(set(declaration) == {"file"})
                source = PurePosixPath(declaration["file"])
                require(source.is_absolute() and ".." not in source.parts and str(source).startswith(f"/srv/zerotrust-secrets/{stage}/"))
                require("lab" not in str(source).lower())
                require(BINDINGS[name].get(mount["target"]) == source.name)
            require(targets == set(BINDINGS[name]))
        # Restrict aliases and writable bind/volume mounts over credential/config paths.
        for name,service in services.items():
            if name not in BINDINGS:
                require(not service.get("secrets") and not service.get("env_file") and not service.get("build"))
                require(not any(any(term in key.upper() for term in ("PASSWORD","SECRET","PEPPER","TOKEN","PRIVATE_KEY")) for key in service.get("environment",{})))
            for mount in service.get("volumes", []):
                require(isinstance(mount, dict))
                target = mount.get("target", "")
                require(not any(target == p or target.startswith(p+"/") or p.startswith(target.rstrip("/")+"/")
                                for p in ("/run/secrets", "/run/public-demo")))
        for name in ("gateway","keycloak"):
            env=services[name].get("environment",{})
            require(env.get("PUBLIC_DEMO_MODE")=="public-demo" and env.get("PUBLIC_DEMO_ACADEMIC_READ_ONLY")=="true")
        require(services["gateway"]["environment"].get("SPRING_PROFILES_ACTIVE")=="public-demo")
        require(services["gateway"]["environment"].get("SPRING_CONFIG_IMPORT")=="configtree:/run/secrets/")
    except Exception:
        raise ValueError("Public Demo deployment secret references rejected (values redacted)") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract", type=Path)
    parser.add_argument("--check-files", action="store_true")
    parser.add_argument("--deployment-json", type=Path, help="Rendered Compose JSON; combines data and secret preflights, no Docker calls")
    args = parser.parse_args()
    try:
        c = validate(load_json(args.contract.read_text(encoding="utf-8")))
        if args.check_files:
            validate_files(c)
        if args.deployment_json:
            deployment=load_json(args.deployment_json.read_text(encoding="utf-8"))
            from validate_configuration import validate as validate_data
            validate_data(deployment)
            validate_deployment(deployment)
    except Exception:
        print("Public Demo secret preflight rejected (values and paths redacted)")
        return 1
    print("Public Demo secret references PASS; native ownership/realm/runtime NOT VERIFIED")
    return 0


def load_json(text):
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result)
            result[key]=value
        return result
    return json.loads(text,object_pairs_hook=unique)


if __name__ == "__main__":
    raise SystemExit(main())
