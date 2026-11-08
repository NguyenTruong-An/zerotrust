FROM eclipse-temurin:17.0.21_9-jdk-jammy@sha256:057a0daec60e87c96571bf5c9c7792065bcb19e804d584cd37d4144038a35717 AS build
RUN apt-get update && apt-get install -y --no-install-recommends --only-upgrade apt=2.4.15ubuntu0.1 libapt-pkg6.0=2.4.15ubuntu0.1 && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY . .
ARG MODULE=.
ARG RUN_CHECKS=true
RUN --mount=type=cache,target=/root/.m2 chmod +x mvnw && \
    if [ "$RUN_CHECKS" = "true" ]; then \
      ./mvnw --batch-mode --no-transfer-progress -f "$MODULE/pom.xml" verify; \
    else ./mvnw --batch-mode --no-transfer-progress -f "$MODULE/pom.xml" -DskipTests package; fi && \
    mkdir -p /out/tools /out/unpacked && cp "$MODULE"/target/*.jar /out/application.jar && \
    javac -d /out/tools deploy/demo/Health.java && \
    if [ "$MODULE" = "risk-scoring-service" ]; then \
      cd /out/unpacked && jar xf /out/application.jar && \
      javac -cp 'BOOT-INF/classes:BOOT-INF/lib/*' -d /out/tools /source/deploy/demo/Migrate.java /source/deploy/legacy/InspectRisk.java /source/deploy/legacy/MigrateLegacyRisk.java; fi
FROM eclipse-temurin:17.0.21_9-jre-resolute@sha256:d532593b4d17f9455bcc74b4b45046fd0f9799db3b50b3486091e3e33ad99a26
RUN apt-get update && apt-get install -y --no-install-recommends --only-upgrade apt=3.2.1ubuntu0.1 libapt-pkg7.0=3.2.1ubuntu0.1 libbrotli1=1.2.0-3ubuntu0.1 && rm -rf /var/lib/apt/lists/*
ARG SOURCE_REVISION=unknown
ARG SOURCE_SNAPSHOT=unknown
LABEL org.opencontainers.image.revision=$SOURCE_REVISION io.zerotrust.source.snapshot=$SOURCE_SNAPSHOT
WORKDIR /app
COPY --from=build /out/application.jar /app/application.jar
COPY --from=build /out/tools /app/tools
COPY --from=build /out/unpacked /app/unpacked
USER 10001:10001
ENTRYPOINT ["java","@/run/demo/jvm.args","-jar","/app/application.jar","--spring.config.additional-location=file:/run/demo/application.properties"]
