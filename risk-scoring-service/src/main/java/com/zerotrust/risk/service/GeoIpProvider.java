package com.zerotrust.risk.service;

import com.zerotrust.risk.domain.GeoIpLookupResult;

public interface GeoIpProvider {

    GeoIpLookupResult lookup(String ipAddress);

    boolean isEnabled();

    boolean isReady();
}
