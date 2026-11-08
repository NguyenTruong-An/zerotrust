"""Explicit opt-in native NGINX test. All three listeners bind 127.0.0.1; synthetic TLS keys only.

PD05_NGINX_EXE / PD05_JAVA_HOME must reference already available portable tools.
No environment, service, realm, database, container, CA or real signing key is changed.
"""
import contextlib
import copy
import http.client
import http.server
import json
import os
import socket
import ssl
import subprocess
import threading
import time
import unittest
from pathlib import Path
from test_ingress_contract import ROOT, ingress

NATIVE = bool(os.environ.get("PD05_NGINX_EXE") and os.environ.get("PD05_JAVA_HOME"))
HIDDEN = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


class SyntheticTlsUpstream:
    def __init__(self, cert, key):
        self.calls = []
        self.entered = threading.Event()
        self.release = threading.Event()
        owner = self
        calls = self.calls
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def do_GET(self):
                self.handle_request()
            def do_POST(self):
                self.handle_request()
            def handle_request(self):
                size = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(size)
                calls.append((self.path, dict(self.headers), body))
                status = 401 if self.path == "/api/unauthorized" else 200
                if "hold" in self.path:
                    owner.entered.set()
                    owner.release.wait(timeout=5)
                if "redirect" in self.path:
                    status = 302
                payload = b'{"synthetic":true}'
                self.send_response(status)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Content-Type", "application/json")
                if "redirect" in self.path:
                    self.send_header("Location", "https://auth.test/realms/demo/login-actions/authenticate?session_code=synthetic")
                    self.send_header("Set-Cookie", "AUTH_SESSION_ID=synthetic; Path=/realms/demo/; Secure; HttpOnly; SameSite=None")
                self.end_headers()
                self.wfile.write(payload)
            def log_message(self, *args):
                pass
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@unittest.skipUnless(NATIVE, "native loopback harness requires explicit portable NGINX/JDK paths")
class IngressHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = ROOT / "target/pd-02-05/ingress-harness" / str(time.time_ns())
        cls.root.mkdir(parents=True)
        java = Path(os.environ["PD05_JAVA_HOME"])
        cls.nginx = Path(os.environ["PD05_NGINX_EXE"]).resolve()
        cert, key = cls.root / "fixture.crt", cls.root / "fixture.key"
        store = cls.root / "fixture.p12"
        subprocess.run([str(java / "bin/keytool.exe"), "-genkeypair", "-alias", "fixture", "-keyalg", "RSA", "-keysize", "2048",
                        "-validity", "1", "-dname", "CN=loopback-fixture", "-ext", "SAN=ip:127.0.0.1,dns:portal.test,dns:auth.test",
                        "-storetype", "PKCS12", "-keystore", str(store), "-storepass", "synthetic-fixture-only", "-noprompt"],
                       check=True, capture_output=True, creationflags=HIDDEN)
        exporter = cls.root / "ExportFixture.java"
        exporter.write_text('''import java.nio.file.*;import java.security.*;import java.util.Base64;
class ExportFixture {public static void main(String[] a)throws Exception{
KeyStore k=KeyStore.getInstance("PKCS12");try(var in=Files.newInputStream(Path.of(a[0]))){k.load(in,"synthetic-fixture-only".toCharArray());}
var b=Base64.getMimeEncoder(64,new byte[]{10});
Files.writeString(Path.of(a[1]),"-----BEGIN CERTIFICATE-----\\n"+b.encodeToString(k.getCertificate("fixture").getEncoded())+"\\n-----END CERTIFICATE-----\\n");
Files.writeString(Path.of(a[2]),"-----BEGIN PRIVATE KEY-----\\n"+b.encodeToString(k.getKey("fixture","synthetic-fixture-only".toCharArray()).getEncoded())+"\\n-----END PRIVATE KEY-----\\n");}}
''', encoding="utf-8")
        subprocess.run([str(java / "bin/java.exe"), str(exporter), str(store), str(cert), str(key)], check=True,
                       capture_output=True, creationflags=HIDDEN)
        cls.cert = cert
        cls.key = key
        cls.ctx = ssl.create_default_context(cafile=str(cert))
        cls.gateway = SyntheticTlsUpstream(cert, key)
        cls.keycloak = SyntheticTlsUpstream(cert, key)
    @classmethod
    def tearDownClass(cls):
        cls.gateway.close()
        cls.keycloak.close()

    @contextlib.contextmanager
    def proxy(self, limits=None, connections=None):
        c = ingress.load(ROOT / "deploy/public-demo/ingress-contract.json")
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        directory = self.root / str(time.time_ns())
        (directory / "logs").mkdir(parents=True)
        (directory / "temp").mkdir()
        c.update(listen_ip="127.0.0.1", listen_port=port, portal_host="portal.test", auth_host="auth.test",
                 admin_host="operator.private.test", realm="demo", certificate=self.cert.as_posix(), certificate_key=self.key.as_posix(),
                 upstream_ca=self.cert.as_posix(), trusted_proxy_cidrs=["127.0.0.1/32"])
        for name, stub in (("gateway", self.gateway), ("keycloak", self.keycloak)):
            # DNS SAN verifies upstream IP independently of the TLS listener/public Host header.
            c[name] = {"url": f"https://127.0.0.1:{stub.server.server_port}", "tls_name": "portal.test"}
        for limit in c["limits"].values():
            limit.update(bytes=1024, rate=100, burst=200)
        if limits:
            for group, values in limits.items():
                c["limits"][group].update(values)
        if connections:
            c["connections"].update(connections)
        conf = directory / "nginx.conf"
        conf.write_text(ingress.render(c), encoding="utf-8")
        args = [str(self.nginx), "-p", directory.as_posix()+"/", "-c", conf.as_posix()]
        syntax = subprocess.run(args+["-t"], check=False, capture_output=True, creationflags=HIDDEN)
        (directory / "syntax.txt").write_bytes(syntax.stdout+syntax.stderr)
        self.assertEqual(0, syntax.returncode, syntax.stderr.decode(errors="replace"))
        process = subprocess.Popen(args+["-g", "daemon off; master_process off;"], cwd=directory,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=HIDDEN)
        try:
            deadline = time.monotonic()+5
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.2):
                        break
                except OSError:
                    self.assertIsNone(process.poll(), "isolated NGINX exited")
                    if time.monotonic() > deadline:
                        self.fail("isolated NGINX did not bind loopback")
                    time.sleep(.025)
            yield port
        finally:
            # Signals only this harness prefix/config; never signal any system NGINX.
            subprocess.run(args+["-s", "quit"], capture_output=True, creationflags=HIDDEN, timeout=5)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)

    def request(self, port, host, path, body=None, headers=None, chunked=False):
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=self.ctx, timeout=5)
        try:
            h = {"Host": host, "Connection": "close"}
            h.update(headers or {})
            conn.request("POST" if body is not None else "GET", path, body=body, headers=h, encode_chunked=chunked)
            r = conn.getresponse()
            result = (r.status, dict(r.getheaders()), r.read())
            return result
        finally:
            conn.close()

    def test_01_http_surface_routing_and_internal_admin_isolation(self):
        with self.proxy() as port:
            for path in ("/", "/students", "/api/students/me", "/api/admin/users", "/_next/static/unit.js"):
                self.assertEqual(200, self.request(port, "portal.test", path)[0])
                self.assertEqual(path, self.gateway.calls[-1][0])
            for path in ("/realms/demo/.well-known/openid-configuration", "/realms/demo/protocol/openid-connect/auth",
                         "/realms/demo/protocol/openid-connect/token", "/realms/demo/login-actions/authenticate", "/resources/unit.js"):
                before = len(self.gateway.calls)
                self.assertEqual(200, self.request(port, "auth.test", path)[0])
                self.assertEqual(path, self.keycloak.calls[-1][0])
                self.assertEqual(before, len(self.gateway.calls))
            for host in ("auth.test", "operator.private.test", "attacker.invalid"):
                for path in ("/admin/", "/management", "/health", "/metrics", "/internal/v1/risk/evaluations", "/realms/master/"):
                    before = len(self.keycloak.calls)
                    self.assertIn(self.request(port, host, path)[0], (404, 421))
                    self.assertEqual(before, len(self.keycloak.calls))
            for path in ("/internal/v1/risk/evaluations", "/actuator/health", "/health", "/metrics", "/realms/demo/"):
                self.assertEqual(404, self.request(port, "portal.test", path)[0])

    def test_observatory_and_exports_are_denied_before_either_upstream(self):
        with self.proxy() as port:
            before = (len(self.gateway.calls), len(self.keycloak.calls))
            for host in ("portal.test", "auth.test"):
                for path in ("/observatory/index.html", "/api/admin/observatory/export",
                             "/scripts/observation/viewer.js", "/.local-legacy/risk-observation/latest/index.json",
                             "/presentation/risk-observatory-evidence-20261103-L1/evidence.json",
                             "/api/%6fbservatory/raw-traces", "/resources/observation/viewer.js"):
                    self.assertEqual(404, self.request(port, host, path)[0], path)
            self.assertEqual(before, (len(self.gateway.calls), len(self.keycloak.calls)))

    def test_02_conflicting_forwarding_headers_are_replaced_from_tcp_socket(self):
        with self.proxy() as port:
            forged = {"Forwarded": "for=203.0.113.7;proto=http;host=attacker.invalid", "X-Forwarded-For": "203.0.113.7, 10.50.0.2",
                      "X-Real-IP": "8.8.8.8", "X-Forwarded-Proto": "http", "X-Forwarded-Host": "attacker.invalid",
                      "X-Forwarded-Port": "80", "X-Forwarded-User": "admin", "X-Role": "ADMIN", "X-Subject": "admin",
                      "Authorization": "Bearer synthetic", "Cookie": "AUTH_SESSION_ID=synthetic"}
            for host, path, stub in (("portal.test", "/api/students/me", self.gateway),
                                     ("auth.test", "/realms/demo/login-actions/authenticate", self.keycloak)):
                self.assertEqual(200, self.request(port, host, path, headers=forged)[0])
                h = {k.lower(): v for k, v in stub.calls[-1][1].items()}
                self.assertEqual("127.0.0.1", h["x-forwarded-for"])
                self.assertEqual(host, h["host"])
                self.assertEqual(host, h["x-forwarded-host"])
                self.assertEqual("https", h["x-forwarded-proto"])
                self.assertEqual("443", h["x-forwarded-port"])
                for key in ("forwarded", "x-real-ip", "x-forwarded-user", "x-role", "x-subject"):
                    self.assertNotIn(key, h)
                self.assertEqual("Bearer synthetic", h["authorization"])
                self.assertEqual("AUTH_SESSION_ID=synthetic", h["cookie"])

    def test_03_declared_and_chunked_body_bounds_apply_to_gateway_and_keycloak(self):
        with self.proxy() as port:
            for host, path, stub in (("portal.test", "/api/admin/users", self.gateway),
                                     ("auth.test", "/realms/demo/login-actions/authenticate", self.keycloak),
                                     ("auth.test", "/realms/demo/protocol/openid-connect/token", self.keycloak)):
                for chunked in (False, True):
                    before = len(stub.calls)
                    body = iter([b"x"*700, b"y"*700]) if chunked else b"x"*1400
                    status, headers, payload = self.request(port, host, path, body=body, chunked=chunked)
                    self.assertEqual(413, status)
                    self.assertEqual(before, len(stub.calls))
                    self.assertEqual({"status": 413, "error": "REQUEST_REJECTED"}, json.loads(payload))
                body = iter([b"abc", b"def"])
                self.assertEqual(200, self.request(port, host, path, body=body, chunked=True)[0])
                self.assertEqual(b"abcdef", stub.calls[-1][2])

    def test_04_auth_and_token_bursts_have_independent_real_429(self):
        with self.proxy({"auth": {"rate": 1, "burst": 1}, "token": {"rate": 1, "burst": 1}}) as port:
            for path in ("/realms/demo/login-actions/authenticate", "/realms/demo/protocol/openid-connect/token"):
                start = time.monotonic()
                paths = [path, path+"/", path] if path.endswith("/token") else [path]*3
                results = [self.request(port, "auth.test", variant, body=b"synthetic") for variant in paths]
                self.assertLess(time.monotonic()-start, 1, "fixture burst must finish before refill")
                self.assertEqual([200, 200, 429], [r[0] for r in results])
                self.assertEqual("1", results[-1][1]["Retry-After"])
                self.assertEqual({"status": 429, "error": "REQUEST_REJECTED"}, json.loads(results[-1][2]))
                if path.endswith("/token"):
                    self.assertEqual(429, self.request(port, "auth.test", path+"/", body=b"synthetic")[0])
            self.assertEqual(200, self.request(port, "portal.test", "/api/students/me")[0])

    def test_05_nat_default_burst_allows_small_class_and_preserves_redirect_cookie(self):
        with self.proxy({"auth": {"rate": 10, "burst": 60}}) as port:
            for _ in range(8):
                self.assertEqual(200, self.request(port, "auth.test", "/realms/demo/login-actions/authenticate", body=b"legitimate-synthetic")[0])
            status, h, _ = self.request(port, "auth.test", "/realms/demo/redirect")
            self.assertEqual(302, status)
            self.assertEqual("https://auth.test/realms/demo/login-actions/authenticate?session_code=synthetic", h["Location"])
            self.assertIn("Secure; HttpOnly; SameSite=None", h["Set-Cookie"])
            self.assertEqual(401, self.request(port, "portal.test", "/api/unauthorized")[0])

    def test_06_ambiguous_paths_and_oversized_header_fail_before_upstream(self):
        with self.proxy() as port:
            before = len(self.keycloak.calls)
            for path in ("/realms/demo/%252e%252e/admin", "/realms/demo/%2fadmin", "/realms/demo/;admin"):
                self.assertEqual(400, self.request(port, "auth.test", path)[0])
            self.assertEqual(before, len(self.keycloak.calls))
            self.assertEqual(400, self.request(port, "auth.test", "/realms/demo/", headers={"X-Padding": "x"*17000})[0])

    def test_07_connection_admission_is_bounded_and_recovers(self):
        with self.proxy(connections={"per_ip": 1}) as port:
            self.keycloak.entered.clear()
            self.keycloak.release.clear()
            result = []
            thread = threading.Thread(target=lambda: result.append(self.request(port, "auth.test", "/realms/demo/hold")[0]), daemon=True)
            thread.start()
            try:
                self.assertTrue(self.keycloak.entered.wait(timeout=3))
                r = self.request(port, "auth.test", "/realms/demo/login-actions/authenticate")
                self.assertEqual(429, r[0])
                self.assertEqual("1", r[1]["Retry-After"])
            finally:
                self.keycloak.release.set()
                thread.join(timeout=5)
            self.assertEqual([200], result)
            self.assertEqual(200, self.request(port, "auth.test", "/realms/demo/login-actions/authenticate")[0])

    def test_08_conflicting_content_length_transfer_encoding_is_not_forwarded(self):
        with self.proxy() as port:
            before = len(self.keycloak.calls)
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                with self.ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                    tls.sendall(b"POST /realms/demo/login-actions/authenticate HTTP/1.1\r\nHost: auth.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
                    self.assertTrue(tls.recv(4096).startswith(b"HTTP/1.1 400"))
            self.assertEqual(before, len(self.keycloak.calls))


if __name__ == "__main__":
    unittest.main()
