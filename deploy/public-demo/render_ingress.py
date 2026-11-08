"""Offline single-ingress contract renderer. Never launches NGINX or reads certificate/secret contents."""
import argparse
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit


def _check(condition):
    if not condition:
        raise ValueError("Ingress contract rejected (values redacted)")


def _keys(obj, expected):
    _check(isinstance(obj, dict) and set(obj) == set(expected.split()))


def _integer(value, low, high):
    _check(type(value) is int and low <= value <= high)


def _name(value):
    _check(isinstance(value, str) and 1 <= len(value) <= 253
           and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")))


def validate(c):
    try:
        _keys(c, "approval listen_ip listen_port portal_host auth_host admin_host realm trusted_proxy_cidrs certificate certificate_key upstream_ca gateway keycloak limits connections timeouts")
        _check(c["approval"] == "PROPOSED — NOT APPROVED")
        ipaddress.ip_address(c["listen_ip"])
        _integer(c["listen_port"], 1, 65535)
        for key in ("portal_host", "auth_host", "admin_host"):
            _name(c[key])
        _check(len({c["portal_host"], c["auth_host"], c["admin_host"]}) == 3)
        _check(bool(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", c["realm"])) and c["realm"].lower() != "master")
        _check(isinstance(c["trusted_proxy_cidrs"], list) and 1 <= len(c["trusted_proxy_cidrs"]) <= 16)
        for value in c["trusted_proxy_cidrs"]:
            network = ipaddress.ip_network(value, strict=True)
            _check(network.prefixlen > 0)
        for key in ("certificate", "certificate_key", "upstream_ca"):
            _check(isinstance(c[key], str) and re.fullmatch(r"(?:/|[A-Za-z]:/)[A-Za-z0-9_:/.-]+", c[key])
                   and ".." not in c[key])
        for key in ("gateway", "keycloak"):
            _keys(c[key], "url tls_name")
            u = urlsplit(c[key]["url"])
            _check(u.scheme == "https" and not u.username and not u.password and u.path == "" and not u.query and not u.fragment)
            _name(u.hostname)
            _integer(443 if u.port is None else u.port, 1, 65535)
            _check(re.fullmatch(r"https://[a-z0-9.-]+(?::[0-9]+)?", c[key]["url"]) is not None)
            _name(c[key]["tls_name"])
        _keys(c["limits"], "api static auth token")
        for limit in c["limits"].values():
            _keys(limit, "bytes rate burst")
            _integer(limit["bytes"], 1, 1048576)
            _integer(limit["rate"], 1, 10000)
            _integer(limit["burst"], 1, 10000)
        _keys(c["connections"], "global per_ip")
        _integer(c["connections"]["global"], 1, 256)
        _integer(c["connections"]["per_ip"], 1, c["connections"]["global"])
        _keys(c["timeouts"], "header body_idle keepalive connect upstream_read upstream_send client_send")
        for value in c["timeouts"].values():
            _integer(value, 1, 30)
        return c
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError("Ingress contract rejected (values redacted)") from None


def load(path):
    def unique(pairs):
        obj = {}
        for k, v in pairs:
            _check(k not in obj)
            obj[k] = v
        return obj
    return validate(json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique))


def keycloak_properties(c):
    validate(c)
    return ("# PROPOSED — NOT APPROVED. Merge with PD-02-03 data/TLS/secret contract in Phase 03.\n"
            f"hostname=https://{c['auth_host']}\nhostname-admin=https://{c['admin_host']}\n"
            "hostname-strict=true\nhttp-enabled=false\nproxy-headers=xforwarded\n"
            f"proxy-trusted-addresses={','.join(c['trusted_proxy_cidrs'])}\n"
            "http-max-queued-requests=64\nhttp-pool-max-threads=32\n")


def gateway_environment(c):
    validate(c)
    return ("# PROPOSED — NOT APPROVED. Also activate the public-demo profile; no secret values.\n"
            "PUBLIC_DEMO_MODE=public-demo\nPUBLIC_DEMO_ACADEMIC_READ_ONLY=true\n"
            f"GATEWAY_TRUSTED_PROXY_CIDRS={','.join(c['trusted_proxy_cidrs'])}\n")


def render(c):
    validate(c)
    t = c["timeouts"]
    listen = c["listen_ip"]
    if ":" in listen:
        listen = f"[{listen}]"
    listen = f"{listen}:{c['listen_port']}"
    tls = (f"listen {listen} ssl;\nssl_certificate {c['certificate']};\n"
           f"ssl_certificate_key {c['certificate_key']};\nssl_protocols TLSv1.2 TLSv1.3;\n")
    out = ["# PROPOSED — NOT APPROVED. Single trusted ingress; no real_ip module or upstream header trust.\n",
           "worker_processes 1;\npid logs/nginx.pid;\nerror_log logs/error.log crit;\nevents { worker_connections 512; }\nhttp {\n",
           "server_tokens off;\naccess_log off;\ndefault_type application/json;\n",
           "client_header_buffer_size 4k;\nlarge_client_header_buffers 2 8k;\n",
           f"client_header_timeout {t['header']}s;\nclient_body_timeout {t['body_idle']}s;\n",
           f"keepalive_timeout {t['keepalive']}s;\nkeepalive_requests 100;\nsend_timeout {t['client_send']}s;\n",
           "reset_timedout_connection on;\nlimit_req_status 429;\nlimit_conn_status 429;\n",
           "map $server_name $all_connections { default all; }\n",
           "limit_conn_zone $all_connections zone=global:1m;\nlimit_conn_zone $binary_remote_addr zone=per_ip:1m;\n"]
    for group, limit in c["limits"].items():
        out.append(f"limit_req_zone $binary_remote_addr zone={group}:1m rate={limit['rate']}r/s;\n")
    out.append(f"server {{\n{tls}server_name _;\nreturn 421;\n}}\n")

    def proxy(target, host):
        upstream = c[target]
        # Explicit request allowlist prevents arbitrary X-Forwarded-*, role/subject and identity header propagation.
        allowed = {"Authorization": "$http_authorization", "Cookie": "$http_cookie", "Content-Type": "$http_content_type",
                   "Accept": "$http_accept", "Accept-Language": "$http_accept_language", "Origin": "$http_origin",
                   "Referer": "$http_referer", "User-Agent": "$http_user_agent"}
        text = (f"proxy_pass {upstream['url']};\nproxy_http_version 1.1;\nproxy_pass_request_headers off;\n"
                "proxy_set_header Connection \"\";\n")
        for key, value in allowed.items():
            text += f"proxy_set_header {key} {value};\n"
        text += (f"proxy_set_header Host {host};\nproxy_set_header X-Forwarded-Host {host};\n"
                 "proxy_set_header X-Forwarded-For $remote_addr;\nproxy_set_header X-Forwarded-Proto https;\n"
                 "proxy_set_header X-Forwarded-Port 443;\nproxy_set_header Forwarded \"\";\nproxy_set_header X-Real-IP \"\";\n"
                 "proxy_request_buffering on;\nproxy_ssl_server_name on;\nproxy_ssl_verify on;\n"
                 f"proxy_ssl_name {upstream['tls_name']};\nproxy_ssl_trusted_certificate {c['upstream_ca']};\n"
                 f"proxy_connect_timeout {t['connect']}s;\nproxy_read_timeout {t['upstream_read']}s;\n"
                 f"proxy_send_timeout {t['upstream_send']}s;\nproxy_next_upstream off;\n")
        return text

    def location(selector, group, target, host):
        limit = c["limits"][group]
        return (f"location {selector} {{\nclient_max_body_size {limit['bytes']};\n"
                f"limit_req zone={group} burst={limit['burst']} nodelay;\n{proxy(target,host)}}}\n")

    for host, auth in ((c["portal_host"], False), (c["auth_host"], True)):
        out.extend([f"server {{\n{tls}server_name {host};\n",
                    f"limit_conn global {c['connections']['global']};\nlimit_conn per_ip {c['connections']['per_ip']};\n",
                    'if ($request_uri ~* "^[^?]*(%2f|%5c|%2e|%25|%3b|//|;)") { return 400; }\n',
                    'if ($uri ~* "(?:^|/)(?:internal|observatory|observation|risk-observation|risk-observatory(?:-[a-z0-9_-]+)?|risk-traces?|raw-traces?|presentation|\\.local-legacy|\\.local-demo)(?:/|$)") { return 404; }\n',
                    "error_page 413 = @too_large;\nerror_page 429 = @too_many;\n",
                    "location @too_large { add_header Cache-Control no-store always; return 413 '{\"status\":413,\"error\":\"REQUEST_REJECTED\"}'; }\n",
                    "location @too_many { add_header Cache-Control no-store always; add_header Retry-After 1 always; return 429 '{\"status\":429,\"error\":\"REQUEST_REJECTED\"}'; }\n"])
        if auth:
            realm = c["realm"]
            out.append(location(f"= /realms/{realm}/protocol/openid-connect/token", "token", "keycloak", host))
            out.append(location(f"= /realms/{realm}/protocol/openid-connect/token/", "token", "keycloak", host))
            out.append(location(f"^~ /realms/{realm}/", "auth", "keycloak", host))
            out.append(location("^~ /resources/", "static", "keycloak", host))
            out.append("location / { return 404; }\n")
        else:
            out.append("location ~* ^/(?:internal|actuator|health|metrics|management|realms|resources)(?:/|$) { return 404; }\n")
            out.append(location("= /api", "api", "gateway", host))
            out.append(location("/api/", "api", "gateway", host))
            out.append(location("/", "static", "gateway", host))
        out.append("}\n")
    out.append("}\n")
    return "".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract", type=Path)
    parser.add_argument("--nginx-output", required=True, type=Path)
    parser.add_argument("--keycloak-output", required=True, type=Path)
    parser.add_argument("--gateway-output", required=True, type=Path)
    args = parser.parse_args()
    c = load(args.contract)
    args.nginx_output.write_text(render(c), encoding="utf-8")
    args.keycloak_output.write_text(keycloak_properties(c), encoding="utf-8")
    args.gateway_output.write_text(gateway_environment(c), encoding="utf-8")
    print("Validated and rendered proposed ingress contract; no process launched")


if __name__ == "__main__":
    main()
