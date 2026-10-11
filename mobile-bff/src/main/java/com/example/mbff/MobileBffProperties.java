package com.example.mbff;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "mobile-bff")
public record MobileBffProperties(
        String spaId,
        List<String> allowedOrigins,
        String apiGatewayUrl,
        String apiGatewayPrefix,
        Shell shell,
        Keycloak keycloak,
        Session session,
        List<Rule> whitelist) {

    public record Shell(String verifyUrl, String apiKey) {}

    public record Keycloak(String base, String clientId, String clientSecret, String audience) {}

    public record Session(String cookieName, boolean cookieSecure, Duration idleTtl,
                          long refreshSkewSeconds, Duration maxLifetime, boolean requireDeviceId, String keyPrefix) {}

    /** 화이트리스트 규칙: 메서드 + path 패턴 + (선택) 응답 필드 allowlist */
    public record Rule(List<String> methods, String path, List<String> fields) {}
}
