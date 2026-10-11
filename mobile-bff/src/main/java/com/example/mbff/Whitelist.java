package com.example.mbff;

import java.util.regex.Pattern;

/** allowlist 자체는 application-*.yml 의 Gateway 라우트(predicates)로 정의. 여기서는 경로 우회 시도만 사전 차단. */
public final class Whitelist {
    private static final Pattern UNSAFE = Pattern.compile("(?i)(%2e|%2f|%5c|%00|\\.\\.|//|;|\\\\)");

    private Whitelist() {}

    public static boolean isSafePath(String rawPath) { return !UNSAFE.matcher(rawPath).find(); }
}
