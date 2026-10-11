package com.example.mbff;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "mobile-bff")
public record MobileBffProperties(
        String spaId,
        List<String> allowedOrigins,
        Shell shell,
        Keycloak keycloak,
        Session session) {

    public record Shell(String verifyUrl, String apiKey) {}

    public record Keycloak(String base, String clientId, String clientSecret, String audience) {}

    public record Session(String cookieName, boolean cookieSecure, Duration idleTtl,
                          long refreshSkewSeconds, Duration maxLifetime, boolean requireDeviceId, String keyPrefix) {}
}
