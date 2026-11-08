"""Generate redacted inventory and per-advisory register from audit evidence only."""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1]


def read(name):
    return json.loads((OUT / "evidence" / name).read_text(encoding="utf-8-sig"))


def clean(value):
    return str(value).replace("|", " / ").replace("\n", " ")


def java_condition(package, advisory):
    summary = advisory.get("summary", "").lower()
    details = advisory.get("details", "").lower()
    if "withissuerlocation" in summary:
        return "SOURCE REVIEWED: decoder dùng withJwkSetUri + explicit issuer validator; chưa thấy điều kiện misconfiguration này."
    if "http headers" in summary:
        return "Có servlet SecurityFilterChain6.5.6; điều kiện response path cần regression; Gateway no-store chỉ giảm một phần."
    for keyword, explanation in (
        ("digest", "Không thấy Tomcat DIGEST authenticator; JWT REST khác đường này."),
        ("lockoutrealm", "Không dùng Tomcat Realm để xác thực password; Keycloak sở hữu password."),
        ("jndirealm", "Không thấy JNDIRealm trong cấu hình."),
        ("ajp", "Không thấy AJP connector; staging port/protocol readback vẫn cần."),
        ("webdav", "Không thấy WebDAV servlet/LOCK/PROPFIND nghiệp vụ."),
        ("jsonaccesslogvalve", "Không thấy JsonAccessLogValve trong cấu hình."),
        ("daoauthenticationprovider", "Password do Keycloak, không thấy DaoAuthenticationProvider app."),
        ("jdbconetimetokenservice", "Không thấy Spring one-time-token login; OTP do Keycloak."),
        ("x.509 client", "Không thấy X.509 user authentication; internal TLS khác cơ chế này."),
        ("websocket", "Không thấy WebSocket endpoint nghiệp vụ; xác minh framework/proxy exposure."),
        ("http/2", "Phụ thuộc HTTP/2 enabled/exposure; chưa chứng minh runtime protocol/exploit."),
        ("polymorphic", "Cần default-typing/gadget conditions; DTO hiện hữu không chứng minh exploit."),
        ("expression", "Cần attacker-controlled expression; chưa thấy eval SpEL từ API input."),
    ):
        if keyword in summary:
            return "Suy luận từ source: " + explanation
    if package.startswith("io.netty:"):
        return "Gateway dùng Reactor Netty HTTP; Risk dùng Lettuce/Netty. Cần xác định codec/TLS/DNS path theo advisory, chưa exploit."
    if package.startswith("com.fasterxml.jackson"):
        return "API nhận JSON bằng DTO; cần kiểm parsing/annotation/type conditions và body bounds; chưa exploit."
    if "logback" in package or "log4j" in package:
        return "Cần cấu hình/log input/attacker quyền tương ứng; không suy ra Log4Shell từ tên package."
    if "spring-web" in package:
        return "MVC REST Portal/Risk hoặc WebFlux Gateway có thật; feature-specific conditions cần test; version match chưa là exploit."
    if "spring-data" in package:
        return "Dùng JPA/Redis template; không thấy Spring Data REST/Redis repositories (đã tắt); kiểm đúng feature advisory."
    return "NEEDS MANUAL REACHABILITY: version match được xác nhận; chưa chứng minh điều kiện khai thác trong ứng dụng."


def inventory():
    baseline, build, runtime = read("baseline.json"), read("build-provenance.json"), read("runtime-public.json")
    lines = ["# Baseline Inventory", "", "**06/11/2026 — c401e17; VERIFIED metadata/config, không live health. Overall NO-GO.**",
             "", "Nguồn: [baseline JSON](evidence/baseline.json), [build provenance](evidence/build-provenance.json), [runtime public metadata](evidence/runtime-public.json), [endpoint mappings](evidence/endpoints.json). Xem [report](PRODUCTION_READINESS_REPORT.md) và [architecture Proposed](PRODUCTION_ARCHITECTURE.md).", "",
             "## Modules và công nghệ", "",
             "| Module | Công nghệ/phiên bản trong source | Vai trò |",
             "|---|---|---|",
             "| Portal (pom.xml/src) | Java17, Boot3.5.7, Keycloak admin-client26.0.11, JPA/Hibernate, MySQL driver9.4.0 | Resource server/học vụ/reset orchestration |",
             "| risk-scoring-service | Java17, Boot3.5.7, Flyway (SQL V1–V4 + Java V5), Redis/Lettuce6.6.0, geoip2 5.2.0 | B0/scoring/history/trust; V5 chỉ MySQL8.0.46 |",
             "| keycloak-risk-extension | Java17, Keycloak26.7.0 provided, Apache HttpClient4.5.14 | Authenticator/MFA condition/registration/events/trace |",
             "| gateway | Java17, Boot3.5.7, Spring Cloud2025.0.3 | JWT/RBAC/routing/header boundary, chưa rate limit |",
             "| frontend | Node24.16.0, Next16.2.6, React19.2.6, keycloak-js26.2.4, TS5.9.3 | Code+PKCE SPA/admin/student |",
             "| keycloak-theme | Theme đóng gói cùng Keycloak | Form/OTP/recovery presentation, không tự xác thực |",
             "| deploy/docker + scripts | Multi-stage/pinned bases; Python3.11+ ops | Build, backup, restore, observation |", "",
             "POM/API/source versions không tự chứng minh thư viện trong image gắn container. Image IDs bên dưới là nhận dạng thực; source snapshot mới và candidate Lab khác nhau. Java runtime JAR inventory của audit build: [java-runtime-jars](evidence/java-runtime-jars.json).", "",
             "## 10 service và image gắn container", "",
             "| Service | Trách nhiệm | State | Image ID | User | RAM MiB | Restart | Host ports |",
             "|---|---|---|---|---|---:|---|---|"]
    roles = {"school":"School MySQL9.1.0", "risk-db":"Risk MySQL8.0.46", "keycloak-db":"Keycloak MySQL8.4.13",
             "redis":"Failure counters/dedup Redis7.4.7", "keycloak":"Keycloak26.7.0 + SPI/theme", "crl":"Public CA/CRL files",
             "frontend":"Next standalone", "risk":"Risk API B0", "backend":"Portal API", "gateway":"HTTPS entry/routing"}
    for c in baseline["containers"]:
        ports = ", ".join(f"{v['HostIp']}:{v['HostPort']}→{k}" for k, values in (c["ports"] or {}).items() for v in values)
        lines.append(f"| {c['service']} | {roles[c['service']]} | {c['state']} | `{c['image']}` | `{c['user'] or 'image/entrypoint default'}` | {c['memory']//1048576} | {c['restart']['Name']} | {ports or 'Không publish'} |")
    lines += ["", "Config.User trống ở official DB image không tự chứng minh mysqld chạy root; entrypoint có thể drop privilege. CRL/Gateway/Portal/Risk/Frontend/Keycloak app user và hardening chi tiết trong JSON. Cả10 stopped; exit codes không được gọi crash/OOM nếu thiếu evidence. Tổng memory limits5.3125GiB, chưa gồm host/headroom. CPU/PID limits phần lớn chưa khai báo.", "",
              "## Build mới có sẵn nhưng chưa triển khai", "",
              f"Revision `{build['revision']}`, source_mode `{build['source_mode']}`, snapshot `{build['snapshot']}`, {build['input_count']} Git blobs checked, mismatches={len(build['git_head_input_mismatches'])}. Build ngày04/11, HISTORICAL VERIFIED; không rebuild application images trong audit.", "",
              "| Service | Build status | Build image ID |",
              "|---|---|---|"]
    lines += [f"| {s} | {v['status']} | `{v['image_id']}` |" for s,v in build["services"].items()]
    lines += ["", "## Persistence, topology và interfaces", "",
              "| Store | Volume canonical | Schema/data và giới hạn kiểm chứng |",
              "|---|---|---|",
              "| School | zerotrust-legacy-integration-20261026_school-data | vip_pro, FK/unique/CHECK/version, schema source; actual DB hôm nay chưa đọc |",
              "| Risk | zerotrust-legacy-integration-20261026_risk-db-data | risk_db; known_devices, success events, trust generation, revocations, Flyway ledger5 entries |",
              "| Keycloak | zerotrust-legacy-integration-20261026_keycloak-db-data | Realm DoAn/identity/credentials/signing/session state; không truy xuất row trong audit |",
              "| Redis | zerotrust-legacy-integration-20261026_redis-data | /data AOF everysec; failure15m/event dedup1h; trust nguồn chính là MySQL, không cookie/Redis đơn lẻ |", "",
              "Core internal bridge: tất cả service; edge bridge: Gateway/Keycloak/CRL. Chỉ loopback28443/28444/28445. Browser không đi Gateway để gọi Keycloak: auth endpoint trực tiếp28444. Gateway→frontend HTTP3000; Gateway→Portal HTTPS8443; SPI→Risk HTTPS8443; Portal→Keycloak admin/token và Risk revoke; JWT decoders→Keycloak JWKS. MySQL3306/Redis6379 chỉ private/TLS config. Không publish DB/Redis/Risk API.", "",
              "Runtime root `../runtime/lab` ngoài Git, RO bind /run/demo cho8 service cấu hình và /public-ca cho CRL (frontend không bind); authority private management không mount vào app/CRL. Hai external networks/bốn external volumes dùng existing identities, không tạo mới trong audit. Docker socket/host mount escalation chưa thấy trong service mounts được chọn.", "",
              "External interfaces: browser HTTPS/OIDC, operator local Docker access, offline/update GeoLite vendor process, build dependency registries và GitHub CI. GeoIP lookup không gửi raw IP tới API bên ngoài theo request. Production offsite/secret store/metrics sinks mới là đề xuất, chưa interface đang chạy.", "",
              "## Authentication/authorization identities", "",
              "| Caller | Boundary/role/scope |",
              "|---|---|",
              "| SPA zerotrust-spa | Public Code+PKCE S256, user bearer, business ADMIN/STUDENT |",
              "| zerotrust-api | Audience Portal/Gateway; realm roles và ownership |",
              "| zerotrust-risk-api | Risk audience và client roles, không public business login |",
              "| zerotrust-risk-caller | azp + risk:evaluate / risk:device:write / risk:events:write |",
              "| zerotrust-portal-risk-admin | azp + risk:device:revoke cho revoke/completion |",
              "| zerotrust-provisioner | Keycloak admin client cho user/role operations; actual least-privilege grants chưa readback live |",
              "| DB app/admin/backup; Redis password | Username app non-root trong config; actual grants/ACL/runtime effective NOT VERIFIED |", "",
              "Không in client secrets/passwords/pepper/key values. Keycloak password/MFA/token boundary khác Portal resource server. SSO/refresh không bảo đảm fresh Risk; token cũ có residual lifetime.", "",
              "## API inventory", "",
              "Mapping source, không live endpoint discovery. Portal /api/admin/** ADMIN, /api/students/** STUDENT, /api/users/me authenticated. Risk internal endpoints áp caller/role table ở trên; GET /actuator/health public nội bộ, các path khác default deny. Gateway routes /api/**→Portal và /**→frontend.", "",
              "| Module | Method | Path | Source |", "|---|---|---|---|"]
    for row in read("endpoints.json"):
        lines.append(f"| {row['module']} | {row['method']} | `{row['path']}` | [{Path(row['source']).name} L{row['line']}](../../{row['source']}) |")
    lines += ["", "## Environment/configuration inventory", "",
              "Các tên dưới trích từ placeholder source, **không có giá trị secret**. Chúng không phải danh sách đầy đủ mọi Spring/Keycloak/Docker env có thể override; environment_names trong baseline JSON là tên thực container, runtime-public là allowlist setting hiện hữu. Precedence: application defaults/profile → environment → additional private application.properties/JVM/system args theo Spring; phải kiểm effective config trước release.", ""]
    for name, value in baseline["source_configuration"].items():
        lines += [f"### {name}", "", ", ".join(f"`{n}`" for n in value["environment_names"]) or "Không có placeholder env bổ sung.", ""]
    lines += ["## TLS/PKI và sensitive data flows", "",
              "Public metadata:17 certificate files (gồm CA copies), tất cả valid time/signature against Lab CA theo offline check; leaf SAN service/localhost, leaf expiry24/01/2027; CRL signature valid/nextUpdate11/11/2026 10:52:23 GMT+7. Không chứng minh live handshake/revocation enforcement. Public CA/internal CA/production domain boundaries chưa có.", "",
              "Sensitive flows: password/OTP/recovery ở Browser↔Keycloak; ADMIN create-student password có qua SPA→Gateway→Portal→Keycloak nhưng không lưu Portal password; bearer user tokens và service tokens trong memory/TLS; raw IP/device identifier transient SPI→Risk, HMAC pseudonyms trong Redis/MySQL; subject/client/time success history và generation/revoke audit trong Risk; profile/grades School; GeoIP metadata allowlist trong trace lab. Credentials/MFA/signing/CA material có thể trong backup runtime/database; tar.gz không encryption. Không có source file chứa password store/JWT issuer riêng Portal.", "",
              "Chi tiết retention, proxy IP và recovery gap: PR-003/006/007/012/014/015/017 trong [Security Audit](SECURITY_AUDIT.md)."]
    (OUT / "BASELINE_INVENTORY.md").write_text("\n".join(lines)+"\n",encoding="utf-8")


def dependencies():
    java, npm = read("java-osv.json"), read("npm-audit.json")
    lock = json.loads((OUT.parents[1] / "frontend/package-lock.json").read_text())
    lines = ["# Dependency findings — PR-001", "",
             "**Scan06/11/2026, c401e17.** Version match là TEST VERIFIED; exploit chưa được chứng minh. Upstream severity giữ riêng với project priority. Tất cả row bên dưới có parent PR-001: impact tùy advisory/đường dùng; verification bằng inventory+OSV/npm; fix phải rebuild/rescan; regression/deployment gate ở [Security Audit](SECURITY_AUDIT.md). Không đổi dependency/source baseline trong audit.", "",
             f"Java: **{java['unique_coordinates']} unique Maven coordinates**, **{len(java['matches'])} package versions có match**, **{len(java['advisories'])} advisory detail records tải được**, detail errors={len(java['detail_errors'])}. Phạm vi runtime nested JARs Portal/Risk/Gateway xác nhận bằng pom.properties, dependency tree và exact hash với local Maven cache. Unresolved instances={len(java['unresolved'])}; Keycloak server/provided SPI libs/OS/JDK ngoài scope scanner này. [Raw evidence](evidence/java-osv.json).", "",
             "npm: **15 package entries:1Critical/6High/8Moderate** (tính cả dependency chains/dev tools), không phải15CVE/15exploit. [Raw evidence](evidence/npm-audit.json). Docker Scout installed nhưng login required, chưa scan image; không suy no-CVE từ việc build đạt.", "",
             "## Triage có nguồn vendor và source", "",
             "- Next16.2.6/sharp0.34.5 nằm trong [SVG/lib advisory CVE-2026-96889](https://github.com/vercel/next.js/security/advisories/GHSA-2464-fhr4-w9xw); glibc Linux phù hợp base bookworm, nhưng đường xử lý SVG không an toàn chưa chứng minh (không cấu hình dangerouslyAllowSVG/upload/remote image trong source). Patch Next+sharp và/hoặc chặn optimizer không dùng rồi test; không gọi RCE đã khai thác.",
             "- [GHSA-673q-mjm6-r5xr](https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr): chưa thấy use cache functions trả typed arrays; không xác nhận condition. [Windows CVE-2026-75604](https://github.com/vercel/next.js/security/advisories/GHSA-p293-qw3h-jr36): NOT APPLICABLE cho Linux Docker runtime, khác Windows host filesystem của native Next server.",
             "- [Spring CVE-2026-22732](https://spring.io/security/cve-2026-22732/): servlet security6.5.6 nằm trong affected range, fixed6.5.9 cho advisory này; kiểm response/cache/header cases. Cần patch train bao phủ mọi advisory, không chỉ6.5.9.",
             "- [Spring CVE-2026-22748](https://spring.io/security/cve-2026-22748/): source có explicit issuer validation nên chưa thấy condition. Tomcat [vendor list](https://tomcat.apache.org/security-10.html) và Netty per-advisory cần feature/protocol triage; JWT REST không mặc nhiên dùng DIGEST/AJP/WebDAV/JNDI Realm.", "",
             "Các nhận xét source là suy luận có giới hạn, không phải exploit test. Rows ghi NEEDS MANUAL REACHABILITY chưa được ký waiver. Fixed lists lấy advisory của đúng artifact, ưu tiên branch hiện có; không cam kết đó là phiên bản mới nhất hoặc bao phủ các advisory khác. Upgrade compatible BOM/framework train, không override ngẫu nhiên từng jar.", "",
             "## Java per-advisory register", "",
             "| ID | Package/version; modules | Advisory/CVE; upstream severity | Điều kiện/cách dùng project | Fixed versions cùng branch (hoặc cần chọn train) |",
             "|---|---|---|---|---|"]
    count=0
    for match in java["matches"]:
        for ident in match["advisory_ids"]:
            count+=1
            a=java["advisories"].get(ident,{})
            aliases=", ".join(x for x in a.get("aliases",[]) if x.startswith("CVE-")) or "Chưa có CVE trong record"
            severity=a.get("database_specific",{}).get("severity","NOT VERIFIED")
            fixed=[]
            for affected in a.get("affected",[]):
                if affected.get("package",{}).get("name")!=match["package"]:continue
                for bounds in affected.get("ranges",[]):
                    fixed += [event["fixed"] for event in bounds.get("events",[]) if "fixed" in event]
            prefix=".".join(match["version"].split(".")[:2])+"."
            selected=list(dict.fromkeys(x for x in fixed if x.startswith(prefix)))
            fix=", ".join(selected) or "Chọn compatible patched train; xem affected/fixed ranges trong JSON"
            condition=java_condition(match["package"],a)
            lines.append(f"| J-{count:03d} | `{match['package']}@{match['version']}` ({', '.join(match['modules'])}) | [{ident}](https://osv.dev/vulnerability/{ident}); {aliases}; {severity} | {clean(condition)} | {clean(fix)} |")
    lines += ["", "Một advisory có thể ảnh hưởng nhiều packages/modules; không cộng rows thành số lỗ hổng độc lập. Scanner severity không thay CVSS vector hoặc severity ứng dụng đã đánh giá. OSV mapping có thể chậm hơn vendor; tái quét release mới và đọc vendor trước quyết định patch. Không tự gán P0 cho rows Critical.", "",
              "## npm per-advisory register", "",
              "| ID | Package/locked versions | Advisory; severity | Điều kiện/phạm vi; priority | Fix/gate |", "|---|---|---|---|---|"]
    n=0
    seen=set()
    for name, entry in npm.get("vulnerabilities",{}).items():
        versions=sorted({str(v.get('version')) for path,v in lock.get('packages',{}).items() if path.endswith('node_modules/'+name)})
        for via in entry["via"]:
            if not isinstance(via,dict):continue
            identity=(name,via["url"],via.get("range"))
            if identity in seen:continue
            seen.add(identity);n+=1
            if name=="next":
                condition="Runtime Linux App Router; feature-specific conditions cần xác minh. P1 release patch gate."
                if "windows" in via['title'].lower(): condition="NOT APPLICABLE cho Linux image; không chạy native Next trên Windows."
                elif "use cache" in via['title']:condition="Không thấy use cache function; source không chứng minh condition. P1 upgrade gate theo vendor."
                fix="npm đề xuất Next16.4.5 tại scan date; chọn bản mới đã triage và rebuild browser regression"
            elif name=="sharp":
                condition="Native image stack của Next; untrusted optimizer path chưa exploit. P1 cùng Next."
                fix="sharp≥0.35.5 bao phủ SVG advisory được trích; recheck libvips/libheif và all advisories"
            else:
                condition="Chủ yếu build/dev tooling hoặc transitive runtime library; chưa thấy untrusted CSS/glob/YAML/schema input từ public API. P2 nếu build-only, P1 nếu runtime reachable."
                fix="Update lockfile/compatible parent; từng affected range trong npm JSON; không npm audit fix --force/downgrade eslint-config mù"
            lines.append(f"| N-{n:03d} | `{name}`: {', '.join(versions)} | [{via['url'].rsplit('/',1)[-1]}]({via['url']}); {via['severity']} | {clean(condition)} | {clean(fix)} |")
    lines += ["", "Các entry eslint-config-next/typescript-eslint không có own advisory là dependency-chain effect, không tạo CVE mới. Source-map-js/postcss có thể xuất hiện nhiều instance/version; đối chiếu affected nodes/range trong raw JSON, không xem mọi version liệt kê đều vulnerable.", "",
              "## Acceptance và giới hạn", "",
              "- Mỗi applicable finding cần owner, runtime reachability, impact/conditions, patched artifact hoặc mitigation được thử, regression evidence và deployment digest. Chưa có các mục này thì PR-001 chưa đóng.",
              "- Kiểm header/caching/JWT/caller/RBAC/CORS/redirect/cookie sau framework update; HTTP parsing/body limits và frontend routes/optimizer. Không thử exploit destructive trên Lab.",
              "- Quét all10 images (bao gồm database/Redis/CRL/base OS/JDK/Keycloak server) và full secret/build-layer scope trước go-live; lần Scout hiện không hoàn tất vì yêu cầu login. Không cài scanner quyền hệ thống hay tự đăng nhập tài khoản Docker trong audit.",
              "- Không xác nhận exploitable auth bypass/RCE chỉ từ advisory range; sự vắng mặt một record cũng không chứng minh thư viện an toàn."]
    (OUT / "DEPENDENCY_FINDINGS.md").write_text("\n".join(lines)+"\n",encoding="utf-8")


if __name__ == "__main__":
    inventory()
    dependencies()
    print("Generated inventory and dependency advisory register (no secret values).")
