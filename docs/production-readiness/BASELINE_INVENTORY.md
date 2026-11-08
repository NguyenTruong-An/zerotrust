# Baseline Inventory

**06/11/2026 — c401e17; VERIFIED metadata/config, không live health. Overall NO-GO.**

Nguồn: [Tóm tắt baseline đã lược metadata](evidence/baseline.json), [build provenance](evidence/build-provenance.json), [Tóm tắt kiểm cấu hình và PKI offline](evidence/runtime-public.json), [endpoint mappings](evidence/endpoints.json). Xem [report](PRODUCTION_READINESS_REPORT.md) và [architecture Proposed](PRODUCTION_ARCHITECTURE.md).

## Modules và công nghệ

| Module | Công nghệ/phiên bản trong source | Vai trò |
|---|---|---|
| Portal (pom.xml/src) | Java17, Boot3.5.7, Keycloak admin-client26.0.11, JPA/Hibernate, MySQL driver9.4.0 | Resource server/học vụ/reset orchestration |
| risk-scoring-service | Java17, Boot3.5.7, Flyway (SQL V1–V4 + Java V5), Redis/Lettuce6.6.0, geoip2 5.2.0 | B0/scoring/history/trust; V5 chỉ MySQL8.0.46 |
| keycloak-risk-extension | Java17, Keycloak26.7.0 provided, Apache HttpClient4.5.14 | Authenticator/MFA condition/registration/events/trace |
| gateway | Java17, Boot3.5.7, Spring Cloud2025.0.3 | JWT/RBAC/routing/header boundary, chưa rate limit |
| frontend | Node24.16.0, Next16.2.6, React19.2.6, keycloak-js26.2.4, TS5.9.3 | Code+PKCE SPA/admin/student |
| keycloak-theme | Theme đóng gói cùng Keycloak | Form/OTP/recovery presentation, không tự xác thực |
| deploy/docker + scripts | Multi-stage/pinned bases; Python3.11+ ops | Build, backup, restore, observation |

POM/API/source versions không tự chứng minh thư viện trong image gắn container. Image IDs bên dưới là nhận dạng thực; source snapshot mới và candidate Lab khác nhau. Java runtime JAR inventory của audit build: [java-runtime-jars](evidence/java-runtime-jars.json).

## Kết quả kiểm kê 10 dịch vụ

Cả 10 container ở trạng thái stopped tại thời điểm kiểm kê. Ba dịch vụ có cổng host bind loopback. Database, Redis và Risk không publish cổng host. Inventory gốc giữ ánh xạ container, image và giới hạn tài nguyên cho audit. Trạng thái stopped không xác nhận crash, OOM hoặc live health.

## Build mới có sẵn nhưng chưa triển khai

Revision `c401e17029d64f9a96738d845b8c0ad0f03fc164`, source_mode `committed_head`, snapshot `74d896368c3a49a4434bf5e81ac23f9f0074a076bc3494f3103388f24200ce64`, 473 Git blobs checked, mismatches=0. Build ngày04/11, HISTORICAL VERIFIED; không rebuild application images trong audit.

| Service | Build status | Build image ID |
|---|---|---|
| backend | passed | `sha256:b76677aa93e4bd58eb39f364c80a1ce4b02e6b626f349d47747b0adcde2615ad` |
| risk | passed | `sha256:3d1b1f5ff5f4457a3df375d63fcae5ebfe397535bc8cd4c8a31dfca040ada8f8` |
| gateway | passed | `sha256:08e90cfba64dfbfe727b68c0a5a0fce961d31cf7afa8d910f9084dff09157eca` |
| frontend | passed | `sha256:cd002aa43f9e47c0e1c88265007ad708c2dbd0598f34f769965c69e75e7efb41` |
| keycloak | passed | `sha256:43dfe27827901bba2281abb2ca162ab0bafc8acfa2b855fedf51ecd562581c43` |
| crl | passed | `sha256:691f153f8d8efd7835ccf2b8379eb02ad786ca2407bf2549fc172b6bf8cac0c1` |

## Persistence, topology và interfaces

| Store | Volume canonical | Schema/data và giới hạn kiểm chứng |
|---|---|---|
| School | Named volume riêng | vip_pro, FK/unique/CHECK/version, schema source; actual DB hôm nay chưa đọc |
| Risk | Named volume riêng | risk_db; known_devices, success events, trust generation, revocations, Flyway ledger5 entries |
| Keycloak | Named volume riêng | Realm DoAn/identity/credentials/signing/session state; không truy xuất row trong audit |
| Redis | Named volume riêng | /data AOF everysec; failure15m/event dedup1h; trust nguồn chính là MySQL, không cookie/Redis đơn lẻ |

Core internal bridge: tất cả service; edge bridge: Gateway/Keycloak/CRL. Chỉ loopback28443/28444/28445. Browser không đi Gateway để gọi Keycloak: auth endpoint trực tiếp28444. Gateway→frontend HTTP3000; Gateway→Portal HTTPS8443; SPI→Risk HTTPS8443; Portal→Keycloak admin/token và Risk revoke; JWT decoders→Keycloak JWKS. MySQL3306/Redis6379 chỉ private/TLS config. Không publish DB/Redis/Risk API.

Runtime root `../runtime/lab` ngoài Git, RO bind /run/demo cho8 service cấu hình và /public-ca cho CRL (frontend không bind); authority private management không mount vào app/CRL. Hai external networks/bốn external volumes dùng existing identities, không tạo mới trong audit. Docker socket/host mount escalation chưa thấy trong service mounts được chọn.

External interfaces: browser HTTPS/OIDC, operator local Docker access, offline/update GeoLite vendor process, build dependency registries và GitHub CI. GeoIP lookup không gửi raw IP tới API bên ngoài theo request. Production offsite/secret store/metrics sinks mới là đề xuất, chưa interface đang chạy.

## Authentication/authorization identities

| Caller | Boundary/role/scope |
|---|---|
| SPA zerotrust-spa | Public Code+PKCE S256, user bearer, business ADMIN/STUDENT |
| zerotrust-api | Audience Portal/Gateway; realm roles và ownership |
| zerotrust-risk-api | Risk audience và client roles, không public business login |
| zerotrust-risk-caller | azp + risk:evaluate / risk:device:write / risk:events:write |
| zerotrust-portal-risk-admin | azp + risk:device:revoke cho revoke/completion |
| zerotrust-provisioner | Keycloak admin client cho user/role operations; actual least-privilege grants chưa readback live |
| DB app/admin/backup; Redis password | Username app non-root trong config; actual grants/ACL/runtime effective NOT VERIFIED |

Không in client secrets/passwords/pepper/key values. Keycloak password/MFA/token boundary khác Portal resource server. SSO/refresh không bảo đảm fresh Risk; token cũ có residual lifetime.

## API inventory

Mapping source, không live endpoint discovery. Portal /api/admin/** ADMIN, /api/students/** STUDENT, /api/users/me authenticated. Risk internal endpoints áp caller/role table ở trên; GET /actuator/health public nội bộ, các path khác default deny. Gateway routes /api/**→Portal và /**→frontend.

| Module | Method | Path | Source |
|---|---|---|---|
| Portal | POST | `/api/admin/student-classes` | [AdminController.java L53](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | GET | `/api/admin/student-classes` | [AdminController.java L62](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | DELETE | `/api/admin/student-classes/{classId}` | [AdminController.java L82](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | POST | `/api/admin/subjects` | [AdminController.java L88](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | GET | `/api/admin/subjects` | [AdminController.java L96](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | DELETE | `/api/admin/subjects/{subjectId}` | [AdminController.java L111](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | GET | `/api/admin/subjects/{subjectId}/score-sheet` | [AdminController.java L117](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | POST | `/api/admin/subjects/{subjectId}/scores/batch` | [AdminController.java L131](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | POST | `/api/admin/students/{studentId}/scores` | [AdminController.java L140](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | GET | `/api/admin/students/{studentId}/scores` | [AdminController.java L151](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | PATCH | `/api/admin/scores/{scoreId}` | [AdminController.java L172](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | DELETE | `/api/admin/scores/{scoreId}` | [AdminController.java L181](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | POST | `/api/admin/students` | [AdminController.java L187](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | GET | `/api/admin/students` | [AdminController.java L195](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | GET | `/api/admin/students/{id}` | [AdminController.java L214](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | PATCH | `/api/admin/students/{id}` | [AdminController.java L222](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | GET | `/api/admin/users` | [AdminController.java L231](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | POST | `/api/admin/users/{id}/mfa/reset` | [AdminController.java L237](../../src/main/java/com/zerotrust/zerotrust/controller/AdminController.java) |
| Portal | GET | `/api/students/me` | [StudentController.java L32](../../src/main/java/com/zerotrust/zerotrust/controller/StudentController.java) |
| Portal | GET | `/api/students/me/scores/summary` | [StudentController.java L41](../../src/main/java/com/zerotrust/zerotrust/controller/StudentController.java) |
| Portal | GET | `/api/students/me/scores` | [StudentController.java L50](../../src/main/java/com/zerotrust/zerotrust/controller/StudentController.java) |
| Portal | GET | `/api/users/me` | [UserController.java L22](../../src/main/java/com/zerotrust/zerotrust/controller/UserController.java) |
| Risk | POST | `/internal/v1/authentication-failures` | [AuthenticationFailureController.java L20](../../risk-scoring-service/src/main/java/com/zerotrust/risk/controller/AuthenticationFailureController.java) |
| Risk | POST | `/internal/v1/authentication-successes` | [AuthenticationSuccessController.java L20](../../risk-scoring-service/src/main/java/com/zerotrust/risk/controller/AuthenticationSuccessController.java) |
| Risk | POST | `/internal/v1/risk/evaluations` | [RiskEvaluationController.java L22](../../risk-scoring-service/src/main/java/com/zerotrust/risk/controller/RiskEvaluationController.java) |
| Risk | POST | `/internal/v1/trusted-devices` | [TrustedDeviceController.java L20](../../risk-scoring-service/src/main/java/com/zerotrust/risk/controller/TrustedDeviceController.java) |
| Risk | POST | `/internal/v1/subjects/{subjectId}/trusted-devices/revocations` | [TrustedDeviceRevocationController.java L19](../../risk-scoring-service/src/main/java/com/zerotrust/risk/controller/TrustedDeviceRevocationController.java) |
| Risk | POST | `/internal/v1/subjects/{subjectId}/trusted-devices/revocations/completion` | [TrustedDeviceRevocationController.java L28](../../risk-scoring-service/src/main/java/com/zerotrust/risk/controller/TrustedDeviceRevocationController.java) |

## Environment/configuration inventory

Các tên dưới trích từ placeholder source, **không có giá trị secret**. Chúng không phải danh sách đầy đủ mọi Spring/Keycloak/Docker env có thể override; environment_names trong baseline JSON là tên thực container, runtime-public là allowlist setting hiện hữu. Precedence: application defaults/profile → environment → additional private application.properties/JVM/system args theo Spring; phải kiểm effective config trước release.

### src/main/resources/application-dev.properties

`CORS_ALLOWED_ORIGINS`

### src/main/resources/application-prod.properties

`CORS_ALLOWED_ORIGINS`, `KEYCLOAK_ISSUER_URI`, `KEYCLOAK_JWK_SET_URI`

### src/main/resources/application.properties

`CORS_ALLOWED_ORIGINS`, `DB_PASSWORD`, `DB_URL`, `DB_USERNAME`, `JPA_DDL_AUTO`, `JPA_FORMAT_SQL`, `JPA_SHOW_SQL`, `KEYCLOAK_ADMIN_CLIENT_ID`, `KEYCLOAK_ADMIN_CLIENT_SECRET`, `KEYCLOAK_API_AUDIENCE`, `KEYCLOAK_CONNECTION_CHECKOUT_TIMEOUT`, `KEYCLOAK_CONNECTION_POOL_SIZE`, `KEYCLOAK_CONNECT_TIMEOUT`, `KEYCLOAK_ISSUER_URI`, `KEYCLOAK_JWK_SET_URI`, `KEYCLOAK_MIN_TOKEN_VALIDITY_SECONDS`, `KEYCLOAK_READ_TIMEOUT`, `KEYCLOAK_REALM`, `KEYCLOAK_URL`, `PORTAL_RISK_ALLOW_HTTP`, `PORTAL_RISK_BASE_URL`, `PORTAL_RISK_CLIENT_ID`, `PORTAL_RISK_CLIENT_SECRET`, `PORTAL_RISK_CONNECT_TIMEOUT`, `PORTAL_RISK_READ_TIMEOUT`, `PORTAL_RISK_TOKEN_URI`

### gateway/src/main/resources/application.properties

`BACKEND_URL`, `CORS_ALLOWED_ORIGINS`, `FRONTEND_URL`, `GATEWAY_PORT`, `KEYCLOAK_API_AUDIENCE`, `KEYCLOAK_ISSUER_URI`, `KEYCLOAK_JWK_SET_URI`

### risk-scoring-service/src/main/resources/application-dev.properties

`RISK_JWT_ISSUER_URI`, `RISK_JWT_JWK_SET_URI`, `RISK_REDIS_SSL`

### risk-scoring-service/src/main/resources/application-prod.properties

`RISK_TLS_KEY_ALIAS`, `RISK_TLS_KEY_STORE`, `RISK_TLS_KEY_STORE_PASSWORD`

### risk-scoring-service/src/main/resources/application.properties

`RISK_AUTH_EVENT_DEDUPLICATION_TTL`, `RISK_AUTH_FAILURE_WINDOW`, `RISK_AUTH_HISTORY_HIGH_SCORE`, `RISK_AUTH_HISTORY_KEY_PREFIX`, `RISK_AUTH_HISTORY_MEDIUM_SCORE`, `RISK_AUTH_HISTORY_PEPPER`, `RISK_AUTH_IP_HIGH_MINIMUM`, `RISK_AUTH_IP_MEDIUM_MINIMUM`, `RISK_AUTH_SUBJECT_HIGH_MINIMUM`, `RISK_AUTH_SUBJECT_MEDIUM_MINIMUM`, `RISK_BIND_ADDRESS`, `RISK_BLOCKED_IP_ADDRESSES`, `RISK_DB_PASSWORD`, `RISK_DB_URL`, `RISK_DB_USERNAME`, `RISK_DEVICE_FINGERPRINT_PEPPER`, `RISK_DEVICE_SCORE_MISSING`, `RISK_DEVICE_SCORE_NEW`, `RISK_DEVICE_SCORE_PENDING`, `RISK_DEVICE_SCORE_REVOKED`, `RISK_DEVICE_SCORE_TRUSTED`, `RISK_GEOIP_ASN_DATABASE_PATH`, `RISK_GEOIP_CITY_DATABASE_PATH`, `RISK_GEOIP_ELEVATED_COUNTRY_CODES`, `RISK_GEOIP_ENABLED`, `RISK_GEOIP_HIGH_RISK_COUNTRY_CODES`, `RISK_GEOIP_TRUSTED_COUNTRY_CODES`, `RISK_JPA_SHOW_SQL`, `RISK_JWT_ALLOWED_CLIENT_ID`, `RISK_JWT_AUDIENCE`, `RISK_JWT_ISSUER_URI`, `RISK_JWT_JWK_SET_URI`, `RISK_JWT_REVOKE_CLIENT_ID`, `RISK_NETWORK_DEFAULT_SCORE`, `RISK_NETWORK_ELEVATED_CIDRS`, `RISK_NETWORK_ELEVATED_SCORE`, `RISK_NETWORK_HIGH_RISK_CIDRS`, `RISK_NETWORK_HIGH_SCORE`, `RISK_NETWORK_INTELLIGENCE_ENABLED`, `RISK_NETWORK_TRUSTED_CIDRS`, `RISK_REDIS_COMMAND_TIMEOUT`, `RISK_REDIS_CONNECT_TIMEOUT`, `RISK_REDIS_HOST`, `RISK_REDIS_PASSWORD`, `RISK_REDIS_PORT`, `RISK_REDIS_SSL`, `RISK_SCORING_MODEL`, `RISK_SERVICE_PORT`, `RISK_TEMPORAL_HIGH_SCORE`, `RISK_TEMPORAL_HISTORY_WINDOW`, `RISK_TEMPORAL_HOUR_TOLERANCE`, `RISK_TEMPORAL_MAXIMUM_EVENTS`, `RISK_TEMPORAL_MEDIUM_SCORE`, `RISK_TEMPORAL_MINIMUM_DAY_FREQUENCY`, `RISK_TEMPORAL_MINIMUM_EVENTS`, `RISK_TEMPORAL_MINIMUM_HOUR_FREQUENCY`, `RISK_TEMPORAL_ZONE_ID`, `RISK_THRESHOLD_HIGH_MINIMUM`, `RISK_THRESHOLD_MEDIUM_MINIMUM`, `RISK_WEIGHT_AUTHENTICATION_HISTORY`, `RISK_WEIGHT_DEVICE`, `RISK_WEIGHT_NETWORK`, `RISK_WEIGHT_TEMPORAL`

## TLS/PKI và sensitive data flows

Đối chiếu offline 17 tệp chứng chỉ và một CRL. Chi tiết SAN, đường dẫn và mốc hiệu lực được giữ trong hồ sơ audit riêng. Kiểm tra này chưa xác nhận live handshake hoặc thực thi thu hồi.

Sensitive flows: password/OTP/recovery ở Browser↔Keycloak; ADMIN create-student password có qua SPA→Gateway→Portal→Keycloak nhưng không lưu Portal password; bearer user tokens và service tokens trong memory/TLS; raw IP/device identifier transient SPI→Risk, HMAC pseudonyms trong Redis/MySQL; subject/client/time success history và generation/revoke audit trong Risk; profile/grades School; GeoIP metadata allowlist trong trace lab. Credentials/MFA/signing/CA material có thể trong backup runtime/database; tar.gz không encryption. Không có source file chứa password store/JWT issuer riêng Portal.

Chi tiết retention, proxy IP và recovery gap: PR-003/006/007/012/014/015/017 trong [Security Audit](SECURITY_AUDIT.md).
