"""Validate rendered Compose JSON from stdin; never print values or read secret files.

This is an offline preflight, not a deploy command or a runtime/TLS/grant attestation.
The final manifest must use this check in PD-03-03 and acceptance in PD-04/05.
"""
import json
import re
import sys
from urllib.parse import urlsplit, parse_qsl

JAVA_ENTRYPOINT = [
    "java", "@/run/public-demo/jvm.args", "-jar", "/app/application.jar",
    "--spring.config.additional-location=file:/run/public-demo/application.properties",
    "--spring.profiles.active=public-demo", "--app.public-demo.mode=public-demo",
    "--app.public-demo.academic-read-only=true",
]
KEYCLOAK_COMMAND = ["--config-file=/run/public-demo/keycloak.conf", "start", "--optimized"]


class ConfigurationRejected(ValueError):
    pass


def require(valid, key):
    if not valid:
        raise ConfigurationRejected("Public Demo configuration rejected: " + key + " (value redacted)")


def jdbc(url, schema):
    key = "database URL"
    try:
        require(isinstance(url, str) and url.startswith("jdbc:mysql://"), key)
        uri = urlsplit(url[5:])
        require(uri.hostname and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", uri.hostname), key)
        require(uri.hostname != "localhost" and not uri.hostname.startswith("127.")
                and uri.hostname != "0.0.0.0" and "lab" not in uri.hostname.lower(), key)
        require(not uri.username and not uri.password and not uri.fragment and uri.path == "/" + schema, key)
        require(uri.port is None or 0 < uri.port <= 65535, key)
        pairs = parse_qsl(uri.query, keep_blank_values=True, strict_parsing=True)
        require("%" not in uri.query and len(dict(pairs)) == len(pairs), key)
        require(dict(pairs).get("sslMode") == "VERIFY_IDENTITY", key)
        for name, value in pairs:
            require(name in {"sslMode", "serverTimezone", "characterEncoding", "connectTimeout", "socketTimeout"}, key)
            if name == "serverTimezone": require(value == "UTC", key)
            if name == "characterEncoding": require(value == "UTF-8", key)
            if name in {"connectTimeout", "socketTimeout"}: require(re.fullmatch(r"[1-9][0-9]{0,5}", value), key)
    except Exception:
        raise ConfigurationRejected("Public Demo configuration rejected: database URL (value redacted)") from None


def secret_refs(config, service, targets):
    mounts = service.get("secrets", [])
    require(isinstance(mounts, list), "secret references")
    found = set()
    for mount in mounts:
        require(isinstance(mount, dict), "explicit secret target")
        source, target = mount.get("source"), mount.get("target")
        require(source in config.get("secrets", {}), "secret source declaration")
        found.add(target)
    require(targets <= found, "required secret targets")


def exclude_test_tools(services):
    for name, service in services.items():
        image = service.get("image", "").split("@", 1)[0].rsplit("/", 1)[-1].split(":", 1)[0]
        build = service.get("build")
        dockerfile = build.get("dockerfile", "") if isinstance(build, dict) else ""
        require(name not in {"tools", "probe", "risk-fault"}
                and image not in {"tools", "zerotrust-build-crl"}
                and not image.endswith("-tools")
                and dockerfile.replace("\\", "/").rsplit("/", 1)[-1] != "Dockerfile.tools",
                "test-only tools in release manifest")


def validate(config):
    require(isinstance(config, dict), "document")
    services = config.get("services", {})
    require(isinstance(services, dict), "service mapping")
    exclude_test_tools(services)
    stages = set()
    for name, domain, prefix in [("backend", "school", "DB_"), ("risk", "risk", "RISK_DB_")]:
        require(name in services, "required service")
        service = services[name]
        env = service.get("environment", {})
        require(isinstance(env, dict), "effective environment mapping")
        for key, expected in {"SPRING_PROFILES_ACTIVE": "public-demo", "PUBLIC_DEMO_MODE": "public-demo",
                              "PUBLIC_DEMO_ACADEMIC_READ_ONLY": "true",
                              "SPRING_CONFIG_IMPORT": "configtree:/run/secrets/"}.items():
            require(env.get(key) == expected, name + "." + key)
        stage = env.get("PUBLIC_DEMO_ENVIRONMENT")
        require(stage in {"staging", "production"}, "PUBLIC_DEMO_ENVIRONMENT")
        stages.add(stage)
        schema = "pd_" + stage + "_" + domain
        require(env.get(prefix + "USERNAME") == schema + "_runtime", name + ".database user")
        jdbc(env.get(prefix + "URL"), schema)
        require(service.get("entrypoint") == JAVA_ENTRYPOINT and not service.get("command"), name + ".launcher")
        require(not service.get("env_file"), name + ".unresolved env_file")
        require(not any("PASSWORD" in k or "SECRET" in k or "PEPPER" in k for k in env), name + ".inline secrets")
        targets = {"spring.datasource.password"}
        if domain == "school": targets |= {"keycloak.admin.client-secret", "app.risk-admin.client-secret"}
        else: targets |= {"spring.data.redis.password", "risk.device-fingerprint.pepper",
                          "risk.authentication-history.pepper", "server.ssl.key-store-password"}
        secret_refs(config, service, targets)
    require(len(stages) == 1, "environment isolation")
    require("keycloak" in services, "required service")
    keycloak = services["keycloak"]
    env = keycloak.get("environment", {})
    schema = "pd_" + next(iter(stages)) + "_keycloak"
    require(env.get("KC_DB") == "mysql" and env.get("KC_DB_USERNAME") == schema + "_runtime", "keycloak database")
    jdbc(env.get("KC_DB_URL"), schema)
    require(env.get("KC_SPI_CONNECTIONS_JPA__QUARKUS__MIGRATION_STRATEGY") == "validate", "keycloak schema policy")
    require(env.get("KC_SPI_CONNECTIONS_JPA__QUARKUS__INITIALIZE_EMPTY") == "false", "keycloak empty schema policy")
    require(keycloak.get("command") == KEYCLOAK_COMMAND, "keycloak launcher")
    require(not keycloak.get("entrypoint"), "keycloak entrypoint override")
    require(not keycloak.get("env_file"), "keycloak unresolved env_file")
    require(not any(k.startswith(("KC_DB_", "KCRAW_DB_")) and k not in {"KC_DB_URL", "KC_DB_USERNAME"}
                    for k in env), "keycloak database overrides")
    require(not any("PASSWORD" in k for k in env), "keycloak inline secret")
    secret_refs(config, keycloak, {"/run/public-demo/keycloak.conf"})


def main():
    try:
        validate(json.load(sys.stdin))
    except ConfigurationRejected as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        print("Public Demo configuration rejected: invalid document (values redacted)", file=sys.stderr)
        return 1
    print("Public Demo configuration preflight PASS; runtime/TLS/grants NOT VERIFIED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
