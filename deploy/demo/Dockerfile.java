FROM eclipse-temurin:17.0.10_7-jdk-jammy@sha256:58aead1bf67b0009ce2acb496b7b6220ae0275ae9ade5989e0077c67bb7fbd14 AS build
WORKDIR /source
COPY . .
ARG MODULE=.
ARG RUN_CHECKS=true
RUN --mount=type=cache,target=/root/.m2 chmod +x mvnw && \
    if [ "$MODULE" = "." ] && [ "$RUN_CHECKS" = "true" ]; then ./mvnw --batch-mode --no-transfer-progress -Dtest=ZerotrustApplicationTests,AdminControllerSecurityTest,StudentControllerSecurityTest,ScoreUpdateConcurrencyTest test; fi && \
    ./mvnw --batch-mode --no-transfer-progress -f "$MODULE/pom.xml" -DskipTests package && \
    mkdir -p /out/tools /out/unpacked && cp "$MODULE"/target/*.jar /out/application.jar && \
    javac -d /out/tools deploy/demo/Health.java && \
    if [ "$MODULE" = "risk-scoring-service" ]; then \
      cd /out/unpacked && jar xf /out/application.jar && \
      javac -cp 'BOOT-INF/classes:BOOT-INF/lib/*' -d /out/tools /source/deploy/demo/Migrate.java /source/deploy/legacy/InspectRisk.java /source/deploy/legacy/MigrateLegacyRisk.java; fi
FROM eclipse-temurin:17-jre@sha256:3f28040954c30a9deb5cdd1116f806029c435ac6dca8c228f5b6f1d96f82b827
ARG SOURCE_REVISION=unknown
ARG SOURCE_SNAPSHOT=unknown
LABEL org.opencontainers.image.revision=$SOURCE_REVISION io.zerotrust.source.snapshot=$SOURCE_SNAPSHOT
WORKDIR /app
COPY --from=build /out/application.jar /app/application.jar
COPY --from=build /out/tools /app/tools
COPY --from=build /out/unpacked /app/unpacked
USER 10001:10001
ENTRYPOINT ["java","@/run/demo/jvm.args","-jar","/app/application.jar","--spring.config.additional-location=file:/run/demo/application.properties"]
