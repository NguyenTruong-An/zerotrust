package com.zerotrust.risk.service;

import com.maxmind.db.CHMCache;
import com.maxmind.db.Reader;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CityResponse;
import com.zerotrust.risk.config.GeoIpProperties;
import com.zerotrust.risk.domain.GeoIpLocation;
import com.zerotrust.risk.domain.GeoIpLookupResult;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
@Slf4j
public class MaxMindGeoIpProvider implements GeoIpProvider {

    private final GeoIpProperties properties;
    private final DatabaseReader cityReader;
    private final DatabaseReader asnReader;
    private final AtomicBoolean lookupFailureLogged = new AtomicBoolean();

    public MaxMindGeoIpProvider(GeoIpProperties properties) {
        this.properties = properties;
        if (!properties.isEnabled()) {
            this.cityReader = null;
            this.asnReader = null;
            return;
        }

        this.cityReader = openRequiredReader(properties.getCityDatabasePath(), "City");
        this.asnReader = openOptionalReader(properties.getAsnDatabasePath(), "ASN");
    }

    @Override
    public GeoIpLookupResult lookup(String ipAddress) {
        if (!properties.isEnabled()) {
            return GeoIpLookupResult.disabled();
        }
        if (cityReader == null) {
            return GeoIpLookupResult.unavailable();
        }

        try {
            InetAddress address = InetAddress.getByName(ipAddress);
            Optional<CityResponse> cityResult = cityReader.tryCity(address);
            if (cityResult.isEmpty()) {
                return GeoIpLookupResult.notFound();
            }

            CityResponse city = cityResult.orElseThrow();
            AsnData asn = lookupAsn(address);
            return GeoIpLookupResult.available(new GeoIpLocation(
                    city.country().isoCode(),
                    city.city().name(),
                    city.location().timeZone(),
                    city.location().accuracyRadius(),
                    asn.number(),
                    asn.organization()
            ));
        } catch (IOException | GeoIp2Exception | RuntimeException exception) {
            if (lookupFailureLogged.compareAndSet(false, true)) {
                log.warn(
                        "Geo-IP lookup became unavailable; raw IP was not logged: reason={}",
                        exception.getClass().getSimpleName()
                );
            }
            return GeoIpLookupResult.unavailable();
        }
    }

    @Override
    public boolean isEnabled() {
        return properties.isEnabled();
    }

    @Override
    public boolean isReady() {
        return !properties.isEnabled() || cityReader != null;
    }

    @PreDestroy
    public void close() {
        closeQuietly(asnReader);
        closeQuietly(cityReader);
    }

    private AsnData lookupAsn(InetAddress address) {
        if (asnReader == null) {
            return AsnData.empty();
        }
        try {
            return asnReader.tryAsn(address)
                    .map(MaxMindGeoIpProvider::toAsnData)
                    .orElseGet(AsnData::empty);
        } catch (IOException | GeoIp2Exception | RuntimeException exception) {
            return AsnData.empty();
        }
    }

    private static AsnData toAsnData(AsnResponse response) {
        return new AsnData(
                response.autonomousSystemNumber(),
                response.autonomousSystemOrganization()
        );
    }

    private static DatabaseReader openRequiredReader(String configuredPath, String databaseType) {
        return openReader(configuredPath, databaseType, true);
    }

    private static DatabaseReader openOptionalReader(String configuredPath, String databaseType) {
        return openReader(configuredPath, databaseType, false);
    }

    private static DatabaseReader openReader(
            String configuredPath,
            String databaseType,
            boolean required
    ) {
        if (configuredPath == null || configuredPath.isBlank()) {
            if (required) {
                log.warn("Geo-IP {} database is not configured", databaseType);
            }
            return null;
        }

        try {
            Path path = Path.of(configuredPath.trim()).toAbsolutePath().normalize();
            if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
                log.warn("Geo-IP {} database is unavailable at the configured path", databaseType);
                return null;
            }
            File databaseFile = path.toFile();
            return new DatabaseReader.Builder(databaseFile)
                    .withCache(new CHMCache())
                    .fileMode(Reader.FileMode.MEMORY)
                    .build();
        } catch (IOException | RuntimeException exception) {
            log.warn(
                    "Geo-IP {} database could not be opened: reason={}",
                    databaseType,
                    exception.getClass().getSimpleName()
            );
            return null;
        }
    }

    private static void closeQuietly(DatabaseReader reader) {
        if (reader == null) {
            return;
        }
        try {
            reader.close();
        } catch (IOException exception) {
            log.warn("Geo-IP database reader could not be closed cleanly");
        }
    }

    private record AsnData(Long number, String organization) {
        private static AsnData empty() {
            return new AsnData(null, null);
        }
    }
}
