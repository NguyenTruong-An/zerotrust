"""Unit validation plus opt-in real NGINX/TLS loopback tests; no Docker or external service calls."""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ingress_contract", ROOT / "deploy/public-demo/render_ingress.py")
ingress = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ingress)


class IngressContractTest(unittest.TestCase):
    def setUp(self):
        self.c = ingress.load(ROOT / "deploy/public-demo/ingress-contract.json")

    def test_valid_contract_renders_tls_and_separate_auth_token_zones(self):
        text = ingress.render(self.c)
        for expected in ("proxy_ssl_verify on", "proxy_pass_request_headers off", "X-Forwarded-For $remote_addr",
                         "zone=token", "zone=auth", "limit_req_status 429", "Retry-After 1", "error_page 413"):
            self.assertIn(expected, text)
        self.assertNotIn("proxy_add_x_forwarded_for", text)
        self.assertNotIn("real_ip_header", text)

    def test_keycloak_contract_pins_hostname_and_trust(self):
        text = ingress.keycloak_properties(self.c)
        for expected in ("hostname-strict=true", "proxy-headers=xforwarded", "proxy-trusted-addresses=10.50.0.2/32",
                         "hostname=https://auth.example.invalid", "http-enabled=false"):
            self.assertIn(expected, text)
        self.assertIn("GATEWAY_TRUSTED_PROXY_CIDRS=10.50.0.2/32", ingress.gateway_environment(self.c))

    def test_missing_fields_fail_closed(self):
        for key in self.c:
            with self.subTest(key=key):
                c = copy.deepcopy(self.c)
                del c[key]
                with self.assertRaises(ValueError):
                    ingress.validate(c)

    def test_invalid_controls_and_injection_fail_without_values_in_error(self):
        cases = [("listen_ip", "host.invalid"), ("listen_port", 0), ("realm", "master"), ("realm", "demo; return 200;"),
                 ("portal_host", "evil; return 200;"), ("auth_host", self.c["portal_host"]),
                 ("trusted_proxy_cidrs", []), ("trusted_proxy_cidrs", ["0.0.0.0/0"]),
                 ("trusted_proxy_cidrs", ["::/0"]), ("trusted_proxy_cidrs", ["proxy.invalid/32"]),
                 ("certificate", "/tmp/cert;evil"), ("certificate_key", "relative.key")]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                c = copy.deepcopy(self.c)
                c[key] = value
                with self.assertRaisesRegex(ValueError, "values redacted"):
                    ingress.validate(c)
        for group in self.c["limits"]:
            for key in ("bytes", "rate", "burst"):
                for value in (None, 0, -1, True, 999999999):
                    with self.subTest(group=group, key=key, value=value):
                        c = copy.deepcopy(self.c)
                        c["limits"][group][key] = value
                        with self.assertRaises(ValueError):
                            ingress.validate(c)

    def test_upstreams_require_tls_and_no_credentials_or_uri_injection(self):
        for url in ("http://gateway.internal", "https://user:secret@gateway.internal", "https://gateway.internal/path",
                    "https://gateway.internal?override=1", "https://gateway.internal;evil", "https://gateway.internal:0"):
            with self.subTest(url=url):
                c = copy.deepcopy(self.c)
                c["gateway"]["url"] = url
                with self.assertRaises(ValueError):
                    ingress.validate(c)

    def test_duplicate_json_and_unknown_fields_fail(self):
        c = copy.deepcopy(self.c)
        c["disable_security"] = True
        with self.assertRaises(ValueError):
            ingress.validate(c)
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "duplicate.json"
            p.write_text('{"approval":1,"approval":2}', encoding="utf-8")
            with self.assertRaises(ValueError):
                ingress.load(p)


if __name__ == "__main__":
    unittest.main()
