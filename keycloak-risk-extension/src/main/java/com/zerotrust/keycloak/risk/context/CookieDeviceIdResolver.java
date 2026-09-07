package com.zerotrust.keycloak.risk.context;

import jakarta.ws.rs.core.Cookie;
import org.keycloak.authentication.AuthenticationFlowContext;

import java.util.Map;
import java.util.regex.Pattern;

public final class CookieDeviceIdResolver implements DeviceIdResolver {

    public static final String COOKIE_NAME = "ZT_DEVICE_ID";

    private static final int MIN_LENGTH = 8;
    private static final int MAX_LENGTH = 255;
    private static final Pattern ALLOWED_VALUE = Pattern.compile("[A-Za-z0-9._~-]+");

    @Override
    public String resolve(AuthenticationFlowContext context) {
        Map<String, Cookie> cookies = context.getHttpRequest().getHttpHeaders().getCookies();
        Cookie cookie = cookies.get(COOKIE_NAME);
        if (cookie == null) {
            return null;
        }

        return validatedValue(cookie.getValue());
    }

    static String validatedValue(String value) {
        if (value == null
                || value.length() < MIN_LENGTH
                || value.length() > MAX_LENGTH
                || !ALLOWED_VALUE.matcher(value).matches()) {
            return null;
        }
        return value;
    }
}
