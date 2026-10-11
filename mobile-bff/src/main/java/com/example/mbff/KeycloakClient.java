package com.example.mbff;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/** Keycloak token-exchange(impersonation, aud=mobile-api). 만료 시 동일 방식으로 재교환(refresh 대체). */
@Component
public class KeycloakClient {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Tokens(@JsonProperty("access_token") String accessToken,
                         @JsonProperty("expires_in") long expiresIn) {}

    private final WebClient http = WebClient.create();
    private final MobileBffProperties.Keycloak kc;

    public KeycloakClient(MobileBffProperties props) { this.kc = props.keycloak(); }

    private String tokenUrl() { return kc.base() + "/protocol/openid-connect/token"; }

    private MultiValueMap<String, String> base(String grant) {
        MultiValueMap<String, String> f = new LinkedMultiValueMap<>();
        f.add("grant_type", grant);
        f.add("client_id", kc.clientId());
        f.add("client_secret", kc.clientSecret());
        return f;
    }

    /** Shell 티켓 검증이 끝난 사용자에 대해 aud=mobile-api JWT 교환 (Keycloak legacy token-exchange). */
    public Mono<Tokens> exchangeFor(String username) {
        var f = base("urn:ietf:params:oauth:grant-type:token-exchange");
        f.add("requested_subject", username);
        f.add("audience", kc.audience());
        f.add("requested_token_type", "urn:ietf:params:oauth:token-type:access_token");
        return post(f);
    }

    private Mono<Tokens> post(MultiValueMap<String, String> form) {
        return http.post().uri(tokenUrl()).contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(form)).retrieve().bodyToMono(Tokens.class);
    }
}
