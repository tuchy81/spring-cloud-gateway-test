package com.example.mbff;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * /api/** 에 대한 BFF 가드 (필터 체인을 한 곳에 순서대로 정리):
 *  1 경로 정규화 검사 → 2 CSRF(Origin + 커스텀헤더) → 3 세션 조회(Redis) → 4 device_id 바인딩
 *  → 5 화이트리스트(기본 deny) → 6 access token 자동 refresh → 7 Bearer 주입 + 클라이언트 인증헤더 제거
 *  → 8 응답 필드 allowlist
 */
@Component
public class ApiGuardFilter implements GlobalFilter, Ordered {
    private static final Logger log = LoggerFactory.getLogger(ApiGuardFilter.class);

    private final MobileBffProperties props;
    private final SessionStore store;
    private final KeycloakClient keycloak;
    private final ObjectMapper om;

    public ApiGuardFilter(MobileBffProperties props, SessionStore store,
                          KeycloakClient keycloak, ObjectMapper om) {
        this.props = props; this.store = store; this.keycloak = keycloak; this.om = om;
    }

    @Override public int getOrder() { return -100; }

    @Override
    public Mono<Void> filter(ServerWebExchange ex, GatewayFilterChain chain) {
        String path = ex.getRequest().getURI().getRawPath();
        if (!path.startsWith("/api/")) return chain.filter(ex);
        String method = ex.getRequest().getMethod().name();

        if (!Whitelist.isSafePath(path)) return deny(ex, HttpStatus.BAD_REQUEST, "bad_path");
        if (!CsrfGuard.ok(ex, props)) return deny(ex, HttpStatus.FORBIDDEN, "csrf");

        HttpCookie c = ex.getRequest().getCookies().getFirst(props.session().cookieName());
        if (c == null) return deny(ex, HttpStatus.UNAUTHORIZED, "no_session");

        return store.find(c.getValue())
            .switchIfEmpty(Mono.defer(() -> deny(ex, HttpStatus.UNAUTHORIZED, "session_expired").then(Mono.empty())))
            .flatMap(s -> {
                String dev = ex.getRequest().getHeaders().getFirst("X-Device-Id");
                if (props.session().requireDeviceId() && (dev == null || !dev.equals(s.deviceId()))) {
                    log.warn("AUDIT device mismatch spa={} user={}", props.spaId(), s.username());
                    return deny(ex, HttpStatus.FORBIDDEN, "device_mismatch");
                }
                // allowlist = yml 에 정의된 Gateway 라우트. 허용 라우트가 아니면(= 마지막 deny 라우트) 차단
                Route route = ex.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
                if (route == null || "false".equals(String.valueOf(route.getMetadata().get("allow")))) {
                    log.warn("AUDIT blocked(non-whitelisted) spa={} user={} {} {}", props.spaId(), s.username(), method, path);
                    return deny(ex, HttpStatus.FORBIDDEN, "not_whitelisted");
                }
                return freshToken(s)
                  .onErrorResume(org.springframework.web.server.ResponseStatusException.class,
                          e -> deny(ex, HttpStatus.UNAUTHORIZED, "session_expired").then(Mono.empty()))
                  .flatMap(fresh -> {
                    ex.getResponse().getHeaders().add("X-BFF-Spa", props.spaId());
                    var req = ex.getRequest().mutate().headers(h -> {
                        h.remove(HttpHeaders.COOKIE);
                        h.remove(HttpHeaders.AUTHORIZATION);
                        h.remove(HttpHeaders.ACCEPT_ENCODING);          // 응답 본문 가공을 위해 압축 비활성
                        h.remove("X-Device-Id");
                        h.set(HttpHeaders.AUTHORIZATION, "Bearer " + fresh.accessToken());
                    }).build();
                    Object fields = route.getMetadata().get("response-fields");   // 예: "id,item,qty"
                    ServerHttpResponse resp = (fields == null || fields.toString().isBlank()) ? ex.getResponse()
                            : new FieldFilteringResponse(ex.getResponse(), Set.of(fields.toString().trim().split("\\s*,\\s*")));
                    return store.touch(fresh).then(chain.filter(ex.mutate().request(req).response(resp).build()));
                });
            });
    }

    /** access token 만료 임박 시 재교환(refresh 대체). 동일 세션 동시 갱신은 Redis 락으로 직렬화. */
    Mono<Session> freshToken(Session s) {
        long now = System.currentTimeMillis() / 1000;
        if (s.accessExp() - now > props.session().refreshSkewSeconds()) return Mono.just(s);
        return store.lock(s.sid()).flatMap(got -> {
            if (!got) return Mono.delay(Duration.ofMillis(400)).then(store.find(s.sid()));
            if (s.absoluteExp() <= now) return store.delete(s.sid()).then(Mono.<Session>error(
                    new org.springframework.web.server.ResponseStatusException(HttpStatus.UNAUTHORIZED, "session_expired")));
            return keycloak.exchangeFor(s.username())
                .map(t -> s.withAccess(t.accessToken(), now + t.expiresIn()))
                .flatMap(ns -> store.save(ns).thenReturn(ns))
                .onErrorResume(e -> {
                    log.warn("re-exchange failed spa={} user={}: {}", props.spaId(), s.username(), e.toString());
                    return store.delete(s.sid()).then(Mono.<Session>error(
                            new org.springframework.web.server.ResponseStatusException(HttpStatus.UNAUTHORIZED, "session_expired")));
                })
                .doFinally(x -> store.unlock(s.sid()).subscribe());
        });
    }

    private Mono<Void> deny(ServerWebExchange ex, HttpStatus st, String code) {
        var r = ex.getResponse();
        if (r.isCommitted()) return Mono.empty();
        r.setStatusCode(st);
        r.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String action = st == HttpStatus.UNAUTHORIZED ? ",\"action\":\"reauth_shell\"" : "";
        byte[] b = ("{\"error\":\"" + code + "\"" + action + "}").getBytes(StandardCharsets.UTF_8);
        return r.writeWith(Mono.just(r.bufferFactory().wrap(b)));
    }

    /** 응답 필드 allowlist 적용 (JSON 2xx 응답만) */
    private class FieldFilteringResponse extends ServerHttpResponseDecorator {
        private final Set<String> allow;
        FieldFilteringResponse(ServerHttpResponse d, Set<String> allow) { super(d); this.allow = allow; }

        @Override
        public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
            MediaType ct = getHeaders().getContentType();
            var st = getStatusCode();
            if (ct == null || !MediaType.APPLICATION_JSON.isCompatibleWith(ct) || st == null || !st.is2xxSuccessful())
                return super.writeWith(body);
            return DataBufferUtils.join(Flux.from(body)).flatMap(buf -> {
                byte[] in = new byte[buf.readableByteCount()];
                buf.read(in);
                DataBufferUtils.release(buf);
                byte[] out;
                try { out = ResponseFields.filter(om, in, allow); } catch (Exception e) { out = in; }
                getHeaders().remove(HttpHeaders.TRANSFER_ENCODING);
                getHeaders().setContentLength(out.length);
                return super.writeWith(Mono.just(bufferFactory().wrap(out)));
            });
        }
    }
}
