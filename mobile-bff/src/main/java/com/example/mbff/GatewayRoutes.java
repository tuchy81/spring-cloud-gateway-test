package com.example.mbff;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayRoutes {
    /** SPA 의 /api/** → API GW 의 모바일 채널(/mobile/api/**). 가드는 ApiGuardFilter(GlobalFilter). */
    @Bean
    public RouteLocator routes(RouteLocatorBuilder b, MobileBffProperties p) {
        return b.routes()
            .route("api-to-gw-mobile", r -> r.path("/api/**")
                .filters(f -> f.rewritePath("/api/(?<rest>.*)", p.apiGatewayPrefix() + "/api/${rest}"))
                .uri(p.apiGatewayUrl()))
            .build();
    }
}
