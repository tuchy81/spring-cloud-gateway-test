package com.example.mbff;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.http.server.PathContainer;
import org.springframework.stereotype.Component;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

/** 모바일 노출 API allowlist (기본 deny). 경로 우회(정규화) 시도는 매칭 전에 차단. */
@Component
public class Whitelist {
    private static final Pattern UNSAFE = Pattern.compile("(?i)(%2e|%2f|%5c|%00|\\.\\.|//|;|\\\\)");

    private record Compiled(MobileBffProperties.Rule rule, PathPattern pattern) {}

    private final List<Compiled> rules;

    public Whitelist(MobileBffProperties props) {
        var parser = PathPatternParser.defaultInstance;
        List<MobileBffProperties.Rule> src = props.whitelist() == null ? List.of() : props.whitelist();
        this.rules = src.stream().map(r -> new Compiled(r, parser.parse(r.path()))).toList();
    }

    public static boolean isSafePath(String rawPath) { return !UNSAFE.matcher(rawPath).find(); }

    public Optional<MobileBffProperties.Rule> match(String method, String rawPath) {
        var path = PathContainer.parsePath(rawPath);
        return rules.stream()
                .filter(c -> c.rule().methods().stream().anyMatch(m -> m.equalsIgnoreCase(method)))
                .filter(c -> c.pattern().matches(path))
                .map(Compiled::rule).findFirst();
    }
}
