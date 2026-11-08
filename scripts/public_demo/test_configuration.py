import json
from pathlib import Path
import subprocess
import sys
import unittest

from validate_configuration import validate, jdbc, ConfigurationRejected, JAVA_ENTRYPOINT

ROOT = Path(__file__).resolve().parents[2]


def fixture():
    config = json.loads((ROOT / "deploy/public-demo/configuration-contract.json").read_text(encoding="utf-8"))
    config["secrets"] = {}
    for service_name, domain in [("backend", "school"), ("risk", "risk"), ("keycloak", "keycloak")]:
        service = config["services"][service_name]
        env = service["environment"]
        if service_name != "keycloak":
            env["PUBLIC_DEMO_ENVIRONMENT"] = "production"
            service["entrypoint"] = JAVA_ENTRYPOINT.copy()
        prefix = {"backend": "DB_", "risk": "RISK_DB_", "keycloak": "KC_DB_"}[service_name]
        env[prefix + "URL"] = "jdbc:mysql://" + domain + "-db/pd_production_" + domain + "?sslMode=VERIFY_IDENTITY"
        env[prefix + "USERNAME"] = "pd_production_" + domain + "_runtime"
        targets = {"backend": ["spring.datasource.password", "keycloak.admin.client-secret", "app.risk-admin.client-secret"],
                   "risk": ["spring.datasource.password", "spring.data.redis.password", "risk.device-fingerprint.pepper",
                            "risk.authentication-history.pepper", "server.ssl.key-store-password"],
                   "keycloak": ["/run/public-demo/keycloak.conf"]}[service_name]
        service["secrets"] = []
        for index, target in enumerate(targets):
            source = service_name + "_secret_" + str(index)
            config["secrets"][source] = {"external": True}
            service["secrets"].append({"source": source, "target": target})
    return config


class ConfigurationContractTest(unittest.TestCase):
    def test_complete_synthetic_reference_contract(self):
        validate(fixture())

    def test_candidate_tools_cannot_enter_the_release_manifest(self):
        for service, tool in (
                ("probe", {"image": "candidate-helper:synthetic"}),
                ("helper", {"image": "registry.example:5000/zt-pd02-candidate/tools:pd-r11"}),
                ("helper", {"image": "zerotrust-build-crl:synthetic"}),
                ("helper", {"build": {"dockerfile": "deploy/docker/Dockerfile.tools"}})):
            with self.subTest(service=service, tool=tool):
                config = fixture()
                config["services"][service] = tool
                with self.assertRaisesRegex(ConfigurationRejected, "test-only tools"):
                    validate(config)

    def test_unrendered_fragment_is_not_a_deployment_acceptance(self):
        config = json.loads((ROOT / "deploy/public-demo/configuration-contract.json").read_text(encoding="utf-8"))
        with self.assertRaises(ConfigurationRejected): validate(config)

    def test_missing_each_marker_and_all_markers_is_rejected(self):
        for name in ("backend", "risk"):
            for keys in [("PUBLIC_DEMO_MODE",), ("PUBLIC_DEMO_ACADEMIC_READ_ONLY",),
                         ("SPRING_PROFILES_ACTIVE",), ("PUBLIC_DEMO_MODE", "PUBLIC_DEMO_ACADEMIC_READ_ONLY", "SPRING_PROFILES_ACTIVE")]:
                with self.subTest(service=name, keys=keys):
                    config = fixture()
                    for key in keys: del config["services"][name]["environment"][key]
                    with self.assertRaises(ConfigurationRejected): validate(config)

    def test_no_service_can_use_root_lab_schema_or_unverified_tls(self):
        for name, prefix in [("backend", "DB_"), ("risk", "RISK_DB_"), ("keycloak", "KC_DB_")]:
            for key, value in [(prefix + "USERNAME", "root"), (prefix + "URL", "jdbc:mysql://localhost/vip_pro?useSSL=false"),
                               (prefix + "URL", "jdbc:mysql://school-db/pd_production_school?sslMode=VERIFY_CA")]:
                with self.subTest(service=name, key=key):
                    config = fixture(); config["services"][name]["environment"][key] = value
                    with self.assertRaises(ConfigurationRejected): validate(config)

    def test_secret_references_required_and_no_inline_secret(self):
        for name in ("backend", "risk", "keycloak"):
            for inline in (False, True):
                config = fixture()
                if inline: config["services"][name]["environment"]["DB_PASSWORD"] = "synthetic-must-never-be-printed"
                else: config["services"][name]["secrets"] = []
                with self.assertRaises(ConfigurationRejected): validate(config)

    def test_launcher_override_cannot_remove_production_pins(self):
        for name in ("backend", "risk"):
            for key, value in [("entrypoint", ["java", "-jar", "/app/application.jar"]),
                               ("command", ["--spring.profiles.active=dev", "--app.public-demo.mode=lab"])]:
                config = fixture(); config["services"][name][key] = value
                with self.assertRaises(ConfigurationRejected): validate(config)

    def test_keycloak_runtime_cannot_migrate_or_initialize_empty_schema(self):
        for suffix, value in [("MIGRATION_STRATEGY", "update"), ("INITIALIZE_EMPTY", "true")]:
            config = fixture()
            config["services"]["keycloak"]["environment"]["KC_SPI_CONNECTIONS_JPA__QUARKUS__" + suffix] = value
            with self.assertRaises(ConfigurationRejected): validate(config)

    def test_environment_mismatch(self):
        config = fixture(); config["services"]["risk"]["environment"]["PUBLIC_DEMO_ENVIRONMENT"] = "staging"
        with self.assertRaises(ConfigurationRejected): validate(config)

    def test_jdbc_encoded_duplicate_credential_and_creation_options_fail(self):
        base = "jdbc:mysql://school-db/pd_production_school?sslMode=VERIFY_IDENTITY"
        for suffix in ("&sslMode=DISABLED", "&%73slMode=DISABLED", "&user=root", "&password=synthetic",
                       "&createDatabaseIfNotExist=true", "&allowPublicKeyRetrieval=true"):
            with self.subTest(option=suffix):
                with self.assertRaises(ConfigurationRejected): jdbc(base + suffix, "pd_production_school")

    def test_cli_rejection_redacts_values_and_invalid_json(self):
        config = fixture(); config["services"]["backend"]["environment"]["DB_URL"] = "jdbc:mysql://root:synthetic-must-never-be-printed@localhost/x"
        for payload in (json.dumps(config), '{"secret":"synthetic-must-never-be-printed"'):
            result = subprocess.run([sys.executable, str(ROOT / "scripts/public_demo/validate_configuration.py")],
                                    input=payload, text=True, capture_output=True)
            self.assertEqual(1, result.returncode)
            self.assertNotIn("synthetic-must-never-be-printed", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
