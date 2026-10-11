#!/usr/bin/env python3
"""E2E 시나리오 테스트 (docker compose up 이후 실행).  python3 scripts/e2e.py
표준 라이브러리만 사용. *.localhost 는 127.0.0.1 로 강제 해석한다."""
import base64, json, re, socket, sys, urllib.error, urllib.parse, urllib.request, http.cookiejar, subprocess

_orig = socket.getaddrinfo
socket.getaddrinfo = lambda h, *a, **k: _orig("127.0.0.1" if str(h).endswith(".localhost") else h, *a, **k)

SHELL, A, B, WEB = "http://shell.localhost:8200", "http://spa-a.localhost:9001", "http://spa-b.localhost:9002", "http://web.localhost:8000"
X = {"X-Requested-With": "XMLHttpRequest"}
results = []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class LocalJar(http.cookiejar.CookieJar):
    """브라우저는 *.localhost 를 신뢰 출처로 취급해 http 에서도 Secure 쿠키를 받는다. 테스트 클라이언트도 동일하게 동작."""
    def set_cookie(self, cookie):
        cookie.secure = False
        super().set_cookie(cookie)


def client(follow=True):
    jar = LocalJar()
    hs = [urllib.request.HTTPCookieProcessor(jar)] + ([] if follow else [NoRedirect()])
    return urllib.request.build_opener(*hs), jar


def req(op, method, url, headers=None, body=None, form=None):
    data = None
    h = dict(headers or {})
    if body is not None:
        data, h["Content-Type"] = json.dumps(body).encode(), "application/json"
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with op.open(r, timeout=20) as resp:
            return resp.status, resp.read().decode(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("PASS" if cond else "FAIL"), "-", name, ("| " + str(detail)[:160]) if detail and not cond else "")


def shell_ticket(user, spa, pw=None):
    op, _ = client()
    _, b, _ = req(op, "POST", SHELL + "/shell/login", body={"username": user, "password": pw or user})
    s = json.loads(b)
    _, b, _ = req(op, "POST", SHELL + "/shell/ticket", {"Authorization": "Bearer " + s["shell_session"]}, {"spa": spa})
    return json.loads(b)["ticket"], s


def boot(spa_url, spa, user):
    t, s = shell_ticket(user, spa)
    op, jar = client()
    code, body, hdr = req(op, "POST", spa_url + "/m/auth/bootstrap",
                          {**X, "Authorization": "Bearer " + t, "X-Device-Id": s["device_id"]})
    return op, jar, s["device_id"], t, code, body, hdr


def api(op, base, path, dev, method="GET", body=None, extra=None):
    return req(op, method, base + path, {**X, "X-Device-Id": dev, **(extra or {})}, body)


def redis_cli(*args):
    return subprocess.run(["docker", "compose", "exec", "-T", "redis-mobile", "redis-cli", *args],
                          capture_output=True, text=True).stdout.strip()


def redis_set(key, obj):
    subprocess.run(["docker", "compose", "exec", "-T", "redis-mobile", "redis-cli", "-x", "SET", key],
                   input=json.dumps(obj), capture_output=True, text=True)
    redis_cli("EXPIRE", key, "600")


def main():
    redis_cli("FLUSHALL")  # 재실행 가능하도록 모바일 Redis 초기화
    # ---------- 1. Mobile 정상 플로우 ----------
    op, jar, dev, ticket, code, body, hdr = boot(A, "spa-a", "alice")
    check("M1 bootstrap 200 + 세션쿠키", code == 200 and "MSESSION" in hdr.get("Set-Cookie", ""), body)
    check("M2 쿠키 HttpOnly", "HttpOnly" in hdr.get("Set-Cookie", ""))
    check("M3 응답/쿠키에 JWT 미노출", "eyJ" not in body and "eyJ" not in hdr.get("Set-Cookie", ""))
    code, body, _ = api(op, A, "/api/profile", dev)
    p = json.loads(body) if code == 200 else {}
    check("M4 /api/profile 200 (화이트리스트)", code == 200 and p.get("username") == "alice", body)
    check("M5 응답 필드 allowlist (aud/internalNote/consumer 제거)",
          set(p) == {"sub", "username", "email", "roles"}, sorted(p))
    code, body, _ = api(op, A, "/api/orders", dev)
    o = json.loads(body) if code == 200 else [{}]
    check("M6 /api/orders 200 + internalCost/customerSsn 제거",
          code == 200 and all(set(x) <= {"id", "item", "qty", "price"} for x in o) and len(o) >= 2, body)
    code, body, _ = api(op, A, "/api/orders", dev, "POST", {"item": "pen", "qty": 3, "price": 1000})
    check("M7 POST /api/orders 200", code == 200 and json.loads(body).get("item") == "pen", body)

    # ---------- 2. 화이트리스트(기본 deny) ----------
    for path in ["/api/admin/users", "/api/hr/employees/export", "/api/unknown"]:
        code, body, _ = api(op, A, path, dev)
        check(f"W1 비허용 {path} → 403 not_whitelisted", code == 403 and "not_whitelisted" in body, body)
    code, body, _ = api(op, A, "/api/orders", dev, "DELETE")
    check("W2 허용경로라도 비허용 메서드 → 403", code == 403, body)
    for path in ["/api/orders/../admin/users", "/api//admin/users", "/api/orders/%2e%2e/admin/users"]:
        code, body, _ = api(op, A, path, dev)
        check(f"W3 경로 우회 차단 {path}", code in (400, 403, 404), code)

    # ---------- 3. 티켓 검증 ----------
    code, body, _ = req(client()[0], "POST", A + "/m/auth/bootstrap", {**X, "Authorization": "Bearer " + ticket, "X-Device-Id": dev})
    check("T1 티켓 재사용 거부 (1회용)", code == 401, body)
    code, _, _ = req(client()[0], "POST", A + "/m/auth/bootstrap", {**X, "Authorization": "Bearer forged-ticket-value", "X-Device-Id": "x"})
    check("T2 위조 티켓 거부", code == 401)
    t_b, s_b = shell_ticket("alice", "spa-b")
    code, _, _ = req(client()[0], "POST", A + "/m/auth/bootstrap", {**X, "Authorization": "Bearer " + t_b, "X-Device-Id": s_b["device_id"]})
    check("T3 다른 SPA용 티켓 거부 (spa 바인딩)", code == 401)
    t_d, s_d = shell_ticket("alice", "spa-a")
    code, _, _ = req(client()[0], "POST", A + "/m/auth/bootstrap", {**X, "Authorization": "Bearer " + t_d, "X-Device-Id": "other-device"})
    check("T4 티켓-디바이스 불일치 거부", code == 401)
    code, _, _ = req(client()[0], "POST", A + "/m/auth/bootstrap", {"Authorization": "Bearer " + t_d, "X-Device-Id": s_d["device_id"]})
    check("T5 CSRF 헤더 없는 bootstrap 거부", code == 403)

    # ---------- 4. 세션 / 디바이스 / 인증 헤더 ----------
    code, body, _ = api(op, A, "/api/profile", "other-device")
    check("S1 device_id 불일치 → 403", code == 403 and "device_mismatch" in body, body)
    code, _, _ = req(client()[0], "GET", A + "/api/profile", {"X-Device-Id": dev})
    check("S2 세션쿠키 없음 → 401", code == 401)
    code, body, _ = api(op, A, "/api/profile", dev, extra={"Authorization": "Bearer attacker-token"})
    check("S3 클라이언트가 보낸 Authorization 무시", code == 200, body)
    code, _, _ = api(op, A, "/api/orders", dev, "POST", {"item": "x"}, extra={"Origin": "http://evil.example"})
    check("S4 허용되지 않은 Origin POST 거부", code == 403)
    code, body, _ = req(op, "GET", A + "/m/auth/session")
    check("S5 /m/auth/session 에 토큰 미노출", code == 200 and "eyJ" not in body and "access_token" not in body, body)

    # ---------- 5. Redis 저장 / 네임스페이스 / TTL ----------
    sid_a = next(c.value for c in jar if c.name == "MSESSION")
    keys = redis_cli("--scan", "--pattern", "session:mobile:*").split()
    check("R1 Redis 키 네임스페이스 session:mobile:spa-a:*", keys and all(k.startswith("session:mobile:spa-") for k in keys), keys)
    k = f"session:mobile:spa-a:{sid_a}" if f"session:mobile:spa-a:{sid_a}" in keys else None
    val = redis_cli("GET", k) if k else ""
    check("R2 Redis 세션에 access JWT 저장 (refresh token 은 저장하지 않음)",
          '"accessToken":"eyJ' in val and "refreshToken" not in val)
    ttl = int(redis_cli("TTL", k) or -1) if k else -1
    check("R3 Redis TTL 설정 (≤ idle 30m)", 0 < ttl <= 1800, ttl)
    claims = {}
    if k:
        at = json.loads(val)["accessToken"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(at + "=" * (-len(at) % 4)))
    aud = claims.get("aud")
    check("R4 JWT aud=mobile-api, azp=mobile-bff-spa-a",
          "mobile-api" in (aud if isinstance(aud, list) else [aud]) and claims.get("azp") == "mobile-bff-spa-a", {"aud": aud, "azp": claims.get("azp")})

    # ---------- 6. SPA 격리 ----------
    code, _, _ = req(op, "GET", B + "/api/profile", {"X-Device-Id": dev, "Cookie": "MSESSION=" + (sid_a)})
    check("I1 spa-a 세션쿠키를 spa-b BFF 에서 사용 불가", code == 401)
    op_b, _, dev_b, _, code, _, _ = boot(B, "spa-b", "bob")
    check("I2 spa-b bootstrap 200", code == 200)
    code, body, _ = api(op_b, B, "/api/profile", dev_b)
    check("I3 spa-b 별도 정책: 필드 제한 없음", code == 200 and "consumer" in body and "mobile-bff-spa-b" in body, body)
    code, _, _ = api(op_b, B, "/api/orders", dev_b, "POST", {"item": "x"})
    check("I4 spa-b 는 POST /api/orders 비허용", code == 403)
    code, body, _ = api(op_b, B, "/api/orders", dev_b)
    check("I5 bob 은 본인 주문만 조회 (JWT 사용자 전파)", code == 200 and all(x["owner"] == "bob" for x in json.loads(body)), body)

    # ---------- 7. 로그아웃 ----------
    code, _, _ = req(op, "POST", A + "/m/auth/logout", X)
    check("L1 logout 200", code == 200)
    code, _, _ = api(op, A, "/api/profile", dev)
    check("L2 logout 후 401", code == 401)
    check("L3 Redis 세션 삭제", (not k) or redis_cli("EXISTS", k) == "0")

    # ---------- 8. 자동 refresh ----------
    op3, jar3, dev3, *_ = boot(A, "spa-a", "alice")
    sid = next(c.value for c in jar3 if c.name == "MSESSION")
    key = f"session:mobile:spa-a:{sid}"
    sess = json.loads(redis_cli("GET", key))
    old_at = sess["accessToken"]
    sess["accessExp"] = 1  # access token 만료 강제
    redis_set(key, sess)
    code, body, _ = api(op3, A, "/api/profile", dev3)
    new_at = json.loads(redis_cli("GET", key))["accessToken"]
    check("F1 access 만료 시 자동 재교환 후 200 (새 토큰)", code == 200 and new_at != old_at, body)
    sess = json.loads(redis_cli("GET", key))
    sess["accessExp"] = 1
    sess["username"] = "no-such-user"   # IdP 에서 사용자 비활성/삭제된 상황 모사
    redis_set(key, sess)
    code, body, _ = api(op3, A, "/api/profile", dev3)
    check("F2 재교환 실패(IdP 사용자 무효) → 401 reauth_shell + 세션 삭제", code == 401 and "reauth_shell" in body and redis_cli("EXISTS", key) == "0", body)

    # ---------- 9. API GW 채널 분리 (aud 강제) ----------
    sess_tok = json.loads(redis_cli("GET", next(iter(redis_cli("--scan", "--pattern", "session:mobile:spa-b:*").split()))))["accessToken"]
    GW = "http://api-gw.localhost:8100"
    code, _, _ = req(client()[0], "GET", GW + "/mobile/api/profile", {"Authorization": "Bearer " + sess_tok})
    check("G1 GW /mobile/* : mobile JWT 허용", code == 200)
    code, _, _ = req(client()[0], "GET", GW + "/internal/api/profile", {"Authorization": "Bearer " + sess_tok})
    check("G2 GW /internal/* : mobile JWT(aud=mobile-api) 거부", code == 401)
    code, _, _ = req(client()[0], "GET", GW + "/mobile/api/profile")
    check("G3 GW 토큰 없음 → 401", code == 401)

    # ---------- 10. Web (Apache + mod_auth_openidc) ----------
    wop, wjar = client()
    code, body, _ = req(wop, "GET", WEB + "/api/profile", X)
    check("W-1 미인증 /api → 401 (리다이렉트 아님)", code == 401, code)
    code, body, _ = req(wop, "GET", WEB + "/", {"Accept": "text/html"})
    m = re.search(r'action="([^"]+)"', body)
    ok_login = False
    if m:
        action = m.group(1).replace("&amp;", "&")
        code, body, _ = req(wop, "POST", action, form={"username": "alice", "password": "alice", "credentialId": ""})
        ok_login = code == 200 and "Web SPA" in body
    check("W-2 OIDC 로그인(code flow) 후 Web SPA 로드", ok_login, body[:120])
    code, body, _ = req(wop, "GET", WEB + "/api/profile", X)
    w = json.loads(body) if code == 200 else {}
    check("W-3 Web /api/profile 200 (Bearer 주입)", code == 200 and w.get("username") == "alice", body)
    check("W-4 Web 채널=internal, aud=internal-api, consumer=web-bff",
          w.get("channel") == "internal" and w.get("consumer") == "web-bff" and "internal-api" in (w.get("aud") or []), w)
    code, body, _ = req(wop, "GET", WEB + "/api/admin/users", X)
    check("W-5 Web 은 기존 정책대로 admin API 접근 가능(alice=admin)", code == 200, body)
    names = {c.name for c in wjar if c.domain.startswith("web.")}
    leaked = [c.name for c in wjar if c.domain.startswith("web.") and c.value.count(".") == 2 and c.value.startswith("eyJ")]
    check("W-6 Web 쿠키: 세션 id(web_session)만, JWS(JWT) 없음 (서버측 세션)", "web_session" in names and not leaked, (names, leaked))
    code, _, _ = req(wop, "POST", WEB + "/api/orders", {"Content-Type": "application/json"}, {"item": "x"})
    check("W-7 Web 상태변경 API CSRF 헤더 없으면 403", code == 403, code)

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n{passed}/{len(results)} passed")
    json.dump([{"name": n, "pass": ok} for n, ok, _ in results], open("scripts/e2e-result.json", "w"), ensure_ascii=False, indent=1)
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
