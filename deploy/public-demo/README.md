# Public Demo data/configuration contract

This directory contains Public Demo source configuration and a candidate build recipe.
Progress and decisions belong only to [the master roadmap](../../docs/production-readiness/PUBLIC_DEMO_ROADMAP.md).
The configuration fragments require an approved deployment manifest and isolated inputs.

## Application startup

The canonical Portal and Risk `main` methods install `PublicDemoStartupInitializer`.
It checks the **effective Spring environment after ConfigData loading, before bean creation**.
`prod`, `production`, `public-demo`, an explicit Public Demo mode, or an orphan read-only
flag activates the strict check. There is no H2/test-profile override in this launcher.
Programmatic test contexts that omit this initializer test narrower components; they do
not prove a production launch. The Boot 4 migration retains the PD-02-01 authorization assertions.

Public Demo requires `PUBLIC_DEMO_MODE=public-demo`, `PUBLIC_DEMO_ACADEMIC_READ_ONLY=true`,
and `PUBLIC_DEMO_ENVIRONMENT=staging|production`. Use the `public-demo` Spring profile.
Namespace contract: `pd_<environment>_school` / `pd_<environment>_risk`, with corresponding
`<schema>_runtime` users. These names reserve a fresh namespace, not a MySQL engine choice.
Lab schema names and runtime/migrator identity reuse are rejected. Fresh credentials,
host identity, secret provenance and non-reuse still require downstream inventory proof.

JDBC uses a single `jdbc:mysql://host[:port]/schema?sslMode=VERIFY_IDENTITY` target.
Only `serverTimezone=UTC`, `characterEncoding=UTF-8`, positive `connectTimeout` and
`socketTimeout` are additional accepted query options. Credentials, legacy TLS flags,
database creation, session SQL, alternate socket factories, encoded/duplicate properties,
localhost and known Lab namespaces are rejected. Configure fresh JVM trust material
outside the URL; no bypass of CA or hostname verification is allowed.
`VERIFY_IDENTITY` verifies the CA and hostname per the
[Connector/J security contract](https://dev.mysql.com/doc/connector-j/en/connector-j-connp-props-security.html).
Actual certificate trust, hostname/SAN and TLS handshake are not proved by parsing.

Both applications require `ddl-auto=validate`, `generate-ddl=false`, SQL init `never`,
Flyway/Liquibase disabled, SQL display off, and no alternate datasource/Hibernate overrides.
Runtime must not receive migration/seed credentials. Missing secrets, unresolved placeholders
and short secrets (minimum 16 characters) fail with a property name and a redacted value.
Portal requires HTTPS identity/Risk endpoints and CORS origins, and configured service secrets.
Risk requires HTTPS JWT endpoints, server TLS keystore credentials, Redis TLS/credentials
and the existing fingerprint/history peppers. No scoring or caller policy is changed.

## Account separation

| Account/process | Allowed work | Prohibited at application startup |
|---|---|---|
| School runtime `pd_<env>_school_runtime` | SELECT on exactly `users`, `students`, `student_classes`, `subjects`, `scores` | INSERT/UPDATE/DELETE, DDL, global/schema-wide grants, roles, GRANT OPTION, seed |
| School migrator (private, separate) | Reviewed schema installation/upgrade with a ledger | Mounted into or run by Portal |
| Synthetic provisioner (private, separate) | Controlled synthetic academic rows/account crosswalk after schema validation | Mounted into or run by Portal; public provisioning |
| Risk runtime `pd_<env>_risk_runtime` | Existing required SELECT/INSERT/UPDATE/DELETE on security-state tables; no DDL/global grants | Flyway migrate/repair, seed, schema creation |
| Risk migrator (private, separate) | Reviewed Flyway V1–V5 installer, version/quiescence preflight and ledger | Runtime credentials/automatic app-start migration |
| Keycloak runtime `pd_<env>_keycloak_runtime` | Session/credential/MFA/auth state DML on its own schema, no DDL/global grants | Empty-schema initialization or uncontrolled upgrade |
| Keycloak installer/provisioner (private, separate) | Reviewed vendor schema bootstrap/upgrade and controlled synthetic realm provisioning | Runtime identity reuse or importing Lab realm/keys |

Portal uses the pool read-only hint **and** a startup metadata check before readiness:
actual catalog/MySQL product, effective CURRENT_USER runtime identity, nonempty session TLS cipher and `SHOW GRANTS FOR CURRENT_USER`.
All five table SELECT grants must exist; extra privileges, roles, schema/global grants,
unknown grant formats or query failure cause startup failure. It executes only read-only
metadata SQL. The hint and `@Transactional(readOnly=true)` alone are not authorization.
Risk pool remains writable; evaluation/history/trust/event/counter APIs are not disabled.
Exact Risk/Keycloak table-level grants, DB account TLS requirements and operator host
restrictions must be reviewed/tested against the chosen engine/schema in PD-03-06/04-02.

Risk Flyway V5 and its helper remain immutable: checksum **661092940**, exact MySQL
**8.0.46** guard, no history repair. PD-03-06 must resolve D-14, validate the fresh-install
path and non-atomic DDL recovery before any DB operation. This task chooses no engine.

## Deployment preflight

`configuration-contract.json` is a YAML-compatible Compose **fragment** with fixed profile,
mode, read-only pins and separate `/run/public-demo` launch inputs. It contains no images,
networks, volumes, live hosts or real credentials. Final PD-03-03 configuration must add
all endpoints, resource isolation and explicit read-only secret mounts. Spring configtree
secret targets are canonical effective property names (e.g. `spring.datasource.password`);
they override classpath placeholders. The actual presence and value are checked at startup.
Keycloak uses a protected complete `keycloak.conf` secret mounted at
`/run/public-demo/keycloak.conf`, with its own DB password and TLS configuration.

Keycloak template pins `KC_SPI_CONNECTIONS_JPA__QUARKUS__MIGRATION_STRATEGY=validate`
and `KC_SPI_CONNECTIONS_JPA__QUARKUS__INITIALIZE_EMPTY=false`. Verify these settings on the
approved server candidate before acceptance.
See [vendor provider options](https://www.keycloak.org/server/all-provider-config) and
[vendor database guidance](https://www.keycloak.org/server/db). Validate against the exact
approved server, including extension schema behavior.

The [D-16 build recipe](Dockerfile.keycloak) selects Keycloak 26.8.2 for linux/amd64
and compiles the SPI with `-Ppublic-demo-candidate`. With a Docker daemon available,
build from the repository root using `docker buildx build --platform linux/amd64
--load -f deploy/public-demo/Dockerfile.keycloak -t zerotrust-keycloak:26.8.2-public-demo .`.
The candidate uses the vendor `kc.sh` entrypoint with the command in the configuration
contract. Runtime verification requires the isolated synthetic environment approved under D-16-RUNTIME.

Validate the **final rendered Compose JSON** through stdin:

```powershell
# In the future authorized release task; never display/save rendered secrets.
docker compose -f <approved-manifest> config --format json | python -X utf8 scripts/public_demo/validate_configuration.py
```

The check requires all three services, all markers (including when all are missing),
fixed Java launch pins, the correct namespace/TLS URL, separate secret references and
Keycloak schema policy. It does not read secrets or print values. It rejects command
overrides that remove the launcher pins. Final manifests/builds must invoke this preflight;
removing the entire contract and preflight from a manifest cannot be inferred by an app
that is deliberately launched as Lab. Actual manifest enforcement/CI/release acceptance
is still PD-03-03/04 and deployment verification PD-04/05/06.

No successful preflight, H2 test or mocked metadata run means MySQL SELECT-only grants,
server TLS, migrations, Keycloak startup or a public deployment has passed.
