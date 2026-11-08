# Public Demo ingress contract — PD-02-05

**PROPOSED — NOT APPROVED.** D-04 hostnames and D-06 cohort/workload/limits remain pending.
This is an offline source contract. It does not create a deployment, private network, public port,
DNS record, certificate, realm or operator access. Progress is managed only in
[the Master Roadmap](../../docs/production-readiness/PUBLIC_DEMO_ROADMAP.md).

Internet HTTPS terminates at **one ingress**. Portal/API traffic goes to Gateway; OIDC/token/login/OTP
traffic goes directly to Keycloak. Both private upstream connections use HTTPS with certificate
verification and an explicit TLS name. Risk, Portal backend, databases, Redis, management, Observatory
and Keycloak Admin must have no public listener/published port. Network enforcement and verified
upstream TLS for the complete service graph require the Phase 03/04/05 manifests and acceptance.

`ingress-contract.json` is the common input for NGINX, Keycloak proxy/hostname settings and Gateway's
proxy allowlist. Addresses under `.invalid`, private service names, certificate mount references and
the sample `10.50.0.2/32` are placeholders. Replace with reviewed environment-specific inputs before
rendering the final candidate. The trusted address is ingress's **upstream-facing TCP source**, not
the client's address or the ingress public listener. Use exact `/32` or `/128` entries where possible.
No wildcard `/0`, hostnames, extra JSON fields, duplicate keys, non-TLS upstreams or injected directives
are accepted. IPv4/IPv6 listen addresses and trusted proxy CIDRs are supported; upstream URLs use DNS
names or IPv4 literals, with an explicit certificate name.

Render into a selected review directory (no processes are launched or secrets read):

```powershell
python deploy/public-demo/render_ingress.py deploy/public-demo/ingress-contract.json `
  --nginx-output target/pd-02-05/proposed-nginx.conf `
  --keycloak-output target/pd-02-05/proposed-keycloak.conf `
  --gateway-output target/pd-02-05/proposed-gateway.env
```

NGINX requires writable, bounded `logs`/temporary directories under its runtime prefix. The generated
Keycloak file is a **fragment**, to be merged with PD-02-03 DB/TLS/migration/secret configuration;
Gateway must also activate `public-demo` and receive the full route/JWT/CORS configuration. Do not use
these fragments as the final Compose manifest. Phase 03 must pin effective config and compare both
allowlists with the actual private network/interface; environment overrides cannot be accepted as
an attestation. The private admin hostname by itself provides no isolation. This public ingress
does not route that hostname, `/admin`, `/realms/master`, management, health or Risk endpoints on
the auth host. A separate reviewed private operator path is still required. Portal's `/admin` SPA
remains a Portal route; its APIs retain ADMIN authorization and academic read-only enforcement.

Ingress discards incoming request headers and forwards an explicit application allowlist, replacing
X-Forwarded-For with **one `$remote_addr`** and Host/X-Forwarded-Host/Proto/Port with the selected canonical
host/HTTPS/443. Forwarded, X-Real-IP and arbitrary identity aliases are dropped. There is no
`real_ip_header` or appended client chain. No upstream proxy/CDN is supported by this contract:
adding one needs a reviewed peer allowlist/parser before use. Direct Gateway peers outside its
numeric CIDRs get 403. A trusted peer must send exactly one numeric XFF, otherwise 400. Gateway uses
only that IP for anonymous static quota, then removes all forwarding/identity headers before routing;
JWT bearer claims alone authenticate/authorize API requests. Portal/Risk reject automatic forwarded
header processing in Public Demo. SPI uses Keycloak's native connection address and Risk uses the
authenticated service DTO IP, never HTTP forwarding headers. Native Keycloak proxy resolution still
requires real-runtime tests in Phase 04–06.

Keycloak uses `proxy-headers=xforwarded`, an explicit `proxy-trusted-addresses` list,
`hostname=https://<auth_host>`, `hostname-strict=true`, private `hostname-admin`, `http-enabled=false`.
Issuer must be exactly `https://<auth_host>/realms/<realm>`; HTTPS redirect URIs/web origins and
secure cookie behavior must be accepted in a real browser on the final hostname. Authorization,
cookies, content type, Origin, Referer, language and User-Agent pass through without rewriting;
response redirect/cookie attributes pass through. Browser Flow, brute-force/MFA/session policy and
server version are unchanged. Generated queue64/threads32 are proposed overload settings; native
Keycloak queue overflow is **503**, distinct from ingress 429.

All defaults below are **PROPOSED — NOT APPROVED**, configurable before final acceptance:

| Layer/group | Request rate / burst | Body bytes | Other bounds |
|---|---|---|---|
| Ingress API | 100/s + burst200 per socket client IP | 65536 | Shared global128 / per-IP64 active connections |
| Ingress Portal/static/resources | 100/s + burst200 per IP | 8192 | Same connection limits |
| Ingress realm/auth/login/OTP | 10/s + burst60 per IP | 32768 | Separate auth zone; no IP ban/account lock introduced |
| Ingress token, including trailing slash | 5/s + burst30 per IP | 32768 | Separate token zone, does not consume auth zone |
| Gateway authenticated API | 10/s, token capacity20 per issuer+subject | 65536 | Global32 / subject4 active requests |
| Gateway anonymous/static | 100/s, capacity200 per canonical IP | 8192 | Same global32 / per-IP16 |

NGINX uses leaky buckets (`burst` means excess requests; first request is additional) with no queue
delay and four fixed1MiB rate zones plus two1MiB connection zones. Gateway uses token buckets:
capacity includes the first request. Its synchronized, single-process table has at most4096 SHA-256
keys, no queue, monotonic refill, inactive TTL60s, and idempotent release on completion/error/cancel.
Full table fails closed429; active keys are never evicted, and TTL cannot be shorter than a full
refill interval. Worst configured default admitted API payload is32×64KiB=2MiB of byte arrays,
plus join/copy transients, Netty/TLS/header/client buffers and table/object overhead. This is not an
RSS/capacity measurement. Replicas/restarts reset local quota; multi-replica coordination is not
implemented or approved. No Redis limiter, Lua, Risk counter/history namespace or security event is
written for an ingress/Gateway admission denial. Denied transport requests are not fabricated as
failed authentications. Existing synchronous event delivery residuals remain OPEN.

Eight synthetic logins from one NAT fit the proposed auth burst; distinct JWT subjects have separate
API quotas. Broad per-IP/global edge guards can still affect a shared NAT under saturation. They do
not identify individual people and make no fairness/SLA guarantee. D-06 acceptance must replay the
actual account mix and parallel auth/refresh/static/API bursts; adjust coarse limits to that approved
envelope while retaining security controls. Username, unsigned claims or untrusted header changes
must never manufacture a new authenticated quota.

Gateway counts actual buffered bytes, including chunked/unknown Content-Length bodies, before any
upstream forwarding. It normalizes forwarded Content-Length after buffering. Declared length alone
is not trusted. HTTP framing errors such as TE+CL are rejected by native parsers; underreported CL
without transfer framing denotes a different HTTP message, not a longer body. Gateway body deadline
is2s and total filtered exchange deadline15s (408 if uncommitted; committed streaming responses are
cancelled/closed). Client connect2s, upstream response5s, fixed pool32/acquire2s, idle15s/lifetime60s;
server idle15s/keepalive100 and total header bound16KiB. NGINX single header max8KiB with two large
buffers, header/body-idle5s, keepalive15s/100 requests, upstream connect2s/read5s/send5s, client send10s,
worker connections512. NGINX body/read/send timeouts are **idle/progress timeouts**, not an absolute
exchange duration. Ingress body buffering uses its own bounded runtime temporary storage; deployment
must bound its disk and verify slow-client behavior. Reject responses use safe constant JSON,
Cache-Control:no-store and 429 Retry-After:1; 413 has no fabricated recovery time.

Run offline validation tests:

```powershell
python -m unittest discover -s scripts/public_demo -p 'test*.py' -v
```

Native tests skip unless both `PD05_NGINX_EXE` and `PD05_JAVA_HOME` explicitly point to existing
portable tools. With these set, `test_ingress_http.py` runs real NGINX syntax + TLS HTTP on ephemeral
**127.0.0.1 only**, synthetic HTTPS Gateway/Keycloak stubs, disposable fixture keys under ignored target
and guaranteed own-process shutdown. No Lab CA, actual Keycloak, database, Redis or external address
is contacted. Defaults are tested for routing/header behavior; small test overrides exercise exact
429/413/concurrency deterministically. The separate Gateway suite exercises real Netty, signed JWT
verification and HTTP upstreams on loopback. These fixtures do not establish Linux deployment,
Public HTTPS/browser/OTP/issuer/network-isolation/capacity acceptance; see
[PD-02-05 evidence](../../docs/production-readiness/evidence/PD-02-05_ABUSE_LIMITS_TRUSTED_PROXY.md).
