package com.example.mbff;

/**
 * Redis 에 저장되는 모바일 세션 (JWT 는 서버측에만 존재).
 * Keycloak impersonation 교환 토큰은 refresh grant 가 불가하므로 refresh token 은 저장하지 않고,
 * access 만료 시 재교환한다. absoluteExp = BFF 가 통제하는 세션 절대 만료(epoch sec).
 */
public record Session(String sid, String sub, String username, String deviceId,
                      String accessToken, long accessExp, long absoluteExp) {

    public Session withAccess(String at, long accessExp) {
        return new Session(sid, sub, username, deviceId, at, accessExp, absoluteExp);
    }
}
