package com.example.mbff;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/** 키 규칙: {prefix}:{sid}  (prefix 예: session:mobile:spa-a). 웹 세션(session:internal:*)과 네임스페이스 분리. */
@Component
public class SessionStore {
    private final ReactiveStringRedisTemplate redis;
    private final ObjectMapper om;
    private final MobileBffProperties props;

    public SessionStore(ReactiveStringRedisTemplate redis, ObjectMapper om, MobileBffProperties props) {
        this.redis = redis; this.om = om; this.props = props;
    }

    private String key(String sid) { return props.session().keyPrefix() + ":" + sid; }

    public Mono<Void> save(Session s) {
        try {
            return redis.opsForValue().set(key(s.sid()), om.writeValueAsString(s), ttl(s)).then();
        } catch (Exception e) { return Mono.error(e); }
    }

    public Mono<Session> find(String sid) {
        if (sid == null || sid.isBlank() || sid.length() > 128) return Mono.empty();
        return redis.opsForValue().get(key(sid)).flatMap(j -> {
            try { return Mono.just(om.readValue(j, Session.class)); } catch (Exception e) { return Mono.empty(); }
        });
    }

    /** 유휴 TTL 슬라이딩 (refresh 만료를 넘지 않음) */
    public Mono<Boolean> touch(Session s) { return redis.expire(key(s.sid()), ttl(s)); }

    public Mono<Void> delete(String sid) { return redis.delete(key(sid)).then(); }

    /** 동일 세션 동시 refresh 방지용 락 */
    public Mono<Boolean> lock(String sid) {
        return redis.opsForValue().setIfAbsent(key(sid) + ":lock", "1", Duration.ofSeconds(10));
    }

    public Mono<Void> unlock(String sid) { return redis.delete(key(sid) + ":lock").then(); }

    private Duration ttl(Session s) {
        long remain = s.absoluteExp() - (System.currentTimeMillis() / 1000);
        Duration idle = props.session().idleTtl();
        return Duration.ofSeconds(Math.max(5, Math.min(remain, idle.toSeconds())));
    }
}
