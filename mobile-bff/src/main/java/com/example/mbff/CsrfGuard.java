package com.example.mbff;

import org.springframework.http.HttpMethod;
import org.springframework.web.server.ServerWebExchange;

/** 상태변경 요청: 커스텀 헤더(X-Requested-With) 필수 + Origin 이 있으면 allowed-origins 일치. */
public final class CsrfGuard {
    private CsrfGuard() {}

    public static boolean ok(ServerWebExchange ex, MobileBffProperties props) {
        HttpMethod m = ex.getRequest().getMethod();
        if (m == HttpMethod.GET || m == HttpMethod.HEAD || m == HttpMethod.OPTIONS) return true;
        if (!"XMLHttpRequest".equals(ex.getRequest().getHeaders().getFirst("X-Requested-With"))) return false;
        String origin = ex.getRequest().getHeaders().getFirst("Origin");
        return origin == null || (props.allowedOrigins() != null && props.allowedOrigins().contains(origin));
    }
}
