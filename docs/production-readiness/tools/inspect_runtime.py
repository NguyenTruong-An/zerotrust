"""Public TLS metadata and allowlisted configuration; run with runtime mounted RO.

No private-key parsing, passwords, raw user data, or container execution on Lab.
Usage inside an isolated tools container: python /audit/inspect_runtime.py /runtime
"""
import datetime
import json
from pathlib import Path
import re
import sys
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding

root = Path(sys.argv[1])
now = datetime.datetime.now(datetime.timezone.utc)
safe = re.compile(r"^(server\.(address|port|forward-headers-strategy|shutdown|tomcat\..*|ssl\.(enabled|enabled-protocols))|spring\.(profiles\..*|jpa\.(hibernate\.ddl-auto|open-in-view)|flyway\.enabled|datasource\.hikari\..*|data\.redis\.(host|port|timeout|connect-timeout|ssl\.enabled))|risk\.security\.(require-https|issuer-uri|jwk-set-uri|audience|allowed-client-id|revoke-client-id)|app\.(routes\..*|security\..*|risk-admin\.(base-url|token-uri|allow-http|connect-timeout|read-timeout))|keycloak\.admin\.(server-url|realm|client-id|connect-timeout|read-timeout|connection-pool-size|connection-checkout-timeout)|hostname|hostname-strict|http-enabled|https-port|proxy-headers|proxy-trusted-addresses|health-enabled|metrics-enabled|db|db-url|cache|cache-stack|port|tls-port|tls-auth-clients|appendonly|appendfsync|maxmemory|maxmemory-policy|save|bind|protected-mode|require_secure_transport|ssl[-_]ca|ssl[-_]cert|tls_version|binlog_expire_logs_seconds|log_bin)$")
output = {"observed_at_utc": now.isoformat(), "configuration": {}, "certificates": [], "crls": [], "jvm_flags": {}}
for folder in ("backend", "gateway", "risk", "keycloak", "school", "risk-db", "keycloak-db", "redis"):
    for f in (root / folder).glob("*"):
        if f.name not in ("application.properties", "keycloak.conf", "server.cnf", "redis.conf", "legacy-policy.env", "jvm.args"):
            continue
        selected = {}
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";", "[")):
                continue
            if f.name == "jvm.args":
                continue
            bits = re.split(r"\s*[=]\s*|\s+", line, maxsplit=1)
            if len(bits) != 2:
                continue
            key, value = bits
            if re.fullmatch(r"risk\.policy\.(model|weights\.(device|network|temporal|authentication-history)|thresholds\.(medium-minimum|high-minimum))", key):
                selected[key] = value if re.fullmatch(r"BASELINE_B0|CONTINUOUS_B1|[0-9]+(?:\.[0-9]+)?", value) else "REFERENCE_OR_UNEXPECTED_VALUE_NOT_PRINTED"
            if safe.match(key) and not re.search(r"password|secret|pepper|credential|token(?!-uri)", key, re.I):
                # URL credentials are always removed, including JDBC query strings.
                value = re.sub(r"([?&](?:password|user)=)[^&]*", r"\1[REDACTED]", value, flags=re.I)
                value = re.sub(r"(://)[^/@]+:[^/@]+@", r"\1[REDACTED]@", value)
                selected[key] = value
            if key in ("spring.datasource.username", "db-username", "user"):
                selected[key + ".is_root"] = value.strip() == "root"
            if key == "spring.datasource.url":
                selected["jdbc_security_flags"] = {p: bool(re.search(p + r"=true", value, re.I)) for p in ("useSSL", "requireSSL", "verifyServerCertificate", "allowPublicKeyRetrieval")}
                selected["jdbc_sslMode"] = re.search(r"sslMode=([^&]+)", value).group(1) if "sslMode=" in value else "not-explicit"
            if f.name == "legacy-policy.env" and key in ("RISK_SCORING_MODEL", "RISK_WEIGHT_DEVICE", "RISK_WEIGHT_NETWORK", "RISK_WEIGHT_TEMPORAL", "RISK_WEIGHT_AUTHENTICATION_HISTORY", "RISK_THRESHOLD_MEDIUM_MINIMUM", "RISK_THRESHOLD_HIGH_MINIMUM", "RISK_NETWORK_INTELLIGENCE_ENABLED", "RISK_GEOIP_ENABLED"):
                selected[key] = value
        output["configuration"][f.relative_to(root).as_posix()] = selected
        if f.name == "jvm.args":
            content = f.read_text()
            output["jvm_flags"][folder] = {flag: flag in content for flag in ("com.sun.net.ssl.checkRevocation=true", "com.sun.security.enableCRLDP=true", "java.security.properties", "-Xmx", "-XX:MaxRAMPercentage")}
for folder in ("public-ca", "backend", "risk", "gateway", "keycloak", "school", "risk-db", "keycloak-db", "redis"):
    for f in (root / folder).glob("*.crt"):
        c = x509.load_pem_x509_certificate(f.read_bytes())
        try:
            sans = [str(v.value) for v in c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
        except x509.ExtensionNotFound:
            sans = []
        ca = x509.load_pem_x509_certificate((root / "public-ca/ca.crt").read_bytes())
        key = ca.public_key()
        signature_valid = False
        try:
            if isinstance(key, rsa.RSAPublicKey):
                key.verify(c.signature, c.tbs_certificate_bytes, padding.PKCS1v15(), c.signature_hash_algorithm)
            elif isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(c.signature, c.tbs_certificate_bytes, ec.ECDSA(c.signature_hash_algorithm))
            else:
                raise ValueError("Unsupported CA key type")
            signature_valid = c.issuer == ca.subject
        except Exception:
            signature_valid = False
        output["certificates"].append({"path": f.relative_to(root).as_posix(), "not_before": c.not_valid_before_utc.isoformat(), "not_after": c.not_valid_after_utc.isoformat(), "valid_now": c.not_valid_before_utc <= now < c.not_valid_after_utc, "sans": sans, "signature_valid_against_lab_ca": signature_valid})
for f in (root / "public-ca").glob("*.crl"):
    raw = f.read_bytes()
    crl = x509.load_pem_x509_crl(raw) if raw.startswith(b"-----BEGIN") else x509.load_der_x509_crl(raw)
    ca = x509.load_pem_x509_certificate((root / "public-ca/ca.crt").read_bytes())
    output["crls"].append({"path": f.relative_to(root).as_posix(), "last_update": crl.last_update_utc.isoformat(), "next_update": crl.next_update_utc.isoformat(), "expired": now >= crl.next_update_utc, "signature_valid": crl.is_signature_valid(ca.public_key()), "revoked_count": len(crl)})
print(json.dumps(output, indent=2))
