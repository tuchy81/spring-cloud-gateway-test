package com.example.mbff;

import com.example.mbff.KeycloakClient.Tokens;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 인증 변환 엔드포인트 (Shell opaque 티켓 → Keycloak JWT → Redis, 클라이언트에는 세션쿠키만).
 */
@RestController
@RequestMapping("/m")
public class AuthController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final MobileBffProperties props;
    private final ShellTicketClient shell;
    private final KeycloakClient keycloak;
    private final SessionStore store;

    public AuthController(MobileBffProperties props, ShellTicketClient shell, KeycloakClient keycloak, SessionStore store) {
        this.props = props; this.shell = shell; this.keycloak = keycloak; this.store = store;
    }

    @GetMapping("/config")
    public Map<String, Object> config() {
        return Map.of("spaId", props.spaId(), "apiPrefix", "/api", "deviceHeader", "X-Device-Id");
    }

    /** Authorization: Bearer <shell opaque ticket>, X-Device-Id */
    @PostMapping("/auth/bootstrap")
    public Mono<ResponseEntity<Map<String, Object>>> bootstrap(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authz,
            @RequestHeader(value = "X-Device-Id", required = false) String deviceId,
            ServerWebExchange ex) {
        if (!CsrfGuard.ok(ex, props)) return err(HttpStatus.FORBIDDEN, "csrf");
        if (authz == null || !authz.regionMatches(true, 0, "Bearer ", 0, 7) || authz.length() < 12)
            return err(HttpStatus.UNAUTHORIZED, "missing_ticket");
        if (props.session().requireDeviceId() && (deviceId == null || deviceId.isBlank()))
            return err(HttpStatus.BAD_REQUEST, "missing_device_id");
        String ticket = authz.substring(7).trim();

        return shell.verify(ticket, deviceId)
            .flatMap(v -> keycloak.exchangeFor(v.username()).flatMap(t -> create(v, deviceId, t)))
            .map(s -> {
                ResponseCookie ck = ResponseCookie.from(props.session().cookieName(), s.sid())
                        .httpOnly(true).secure(props.session().cookieSecure()).sameSite("Lax").path("/").build();
                log.info("bootstrap ok spa={} user={}", props.spaId(), s.username());
                return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, ck.toString())
                        .<Map<String, Object>>body(Map.of("authenticated", true, "username", s.username(), "spaId", props.spaId()));
            })
            .onErrorResume(e -> {
                log.warn("bootstrap failed spa={}: {}", props.spaId(), e.toString());
                return err(HttpStatus.UNAUTHORIZED, "invalid_ticket");
            });
    }

    private Mono<Session> create(ShellTicketClient.Verified v, String deviceId, Tokens t) {
        long now = System.currentTimeMillis() / 1000;
        String sid = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
        Session s = new Session(sid, v.username(), v.username(), v.deviceId() != null ? v.deviceId() : deviceId,
                t.accessToken(), now + t.expiresIn(), now + props.session().maxLifetime().toSeconds());
        return store.save(s).thenReturn(s);
    }

    @GetMapping("/auth/session")
    public Mono<ResponseEntity<Map<String, Object>>> session(ServerWebExchange ex) {
        var c = ex.getRequest().getCookies().getFirst(props.session().cookieName());
        if (c == null) return err(HttpStatus.UNAUTHORIZED, "no_session");
        return store.find(c.getValue())
            .map(s -> ResponseEntity.ok().<Map<String, Object>>body(Map.of("authenticated", true, "username", s.username(),
                    "accessExpiresAt", s.accessExp(), "spaId", props.spaId())))   // JWT 는 노출하지 않음
            .switchIfEmpty(err(HttpStatus.UNAUTHORIZED, "session_expired"));
    }

    @PostMapping("/auth/refresh")
    public Mono<ResponseEntity<Map<String, Object>>> refresh(ServerWebExchange ex) {
        if (!CsrfGuard.ok(ex, props)) return err(HttpStatus.FORBIDDEN, "csrf");
        var c = ex.getRequest().getCookies().getFirst(props.session().cookieName());
        if (c == null) return err(HttpStatus.UNAUTHORIZED, "no_session");
        return store.find(c.getValue())
            .flatMap(s -> keycloak.exchangeFor(s.username()).flatMap(t -> {
                long now = System.currentTimeMillis() / 1000;
                var ns = s.withAccess(t.accessToken(), now + t.expiresIn());
                return store.save(ns).thenReturn(ResponseEntity.ok().<Map<String, Object>>body(Map.of("refreshed", true)));
            }))
            .switchIfEmpty(err(HttpStatus.UNAUTHORIZED, "session_expired"))
            .onErrorResume(e -> err(HttpStatus.UNAUTHORIZED, "session_expired"));
    }

    @PostMapping("/auth/logout")
    public Mono<ResponseEntity<Map<String, Object>>> logout(ServerWebExchange ex) {
        if (!CsrfGuard.ok(ex, props)) return err(HttpStatus.FORBIDDEN, "csrf");
        var c = ex.getRequest().getCookies().getFirst(props.session().cookieName());
        Mono<Void> del = c == null ? Mono.empty() : store.delete(c.getValue());
        ResponseCookie clear = ResponseCookie.from(props.session().cookieName(), "").path("/").maxAge(Duration.ZERO).build();
        return del.thenReturn(ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, clear.toString())
                .<Map<String, Object>>body(Map.of("loggedOut", true)));
    }

    private static Mono<ResponseEntity<Map<String, Object>>> err(HttpStatus st, String code) {
        return Mono.just(ResponseEntity.status(st).body(Map.of("error", code)));
    }
}
