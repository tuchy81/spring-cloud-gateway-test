# 모바일 SPA BFF 목업 (Spring Cloud Gateway)

기존 **Web 인증체계(OIDC + BFF 토큰핸들러)는 그대로 유지**하면서, 모바일 Shell(mocean) 내부 하이브리드 SPA를
위한 **SPA별 모바일 BFF**를 추가하는 구조의 동작 목업입니다.

- Shell 의 1회용 opaque 티켓(`Authorization: Bearer`) → **Keycloak token-exchange** 로 `aud=mobile-api` JWT 발급
- JWT 는 **모바일 전용 Redis**(`session:mobile:*`)에만 저장, SPA 에는 **HttpOnly 세션쿠키**만 전달
- 모바일 BFF 의 **화이트리스트(allowlist)에 정의된 API 만** 호출 가능 (기본 deny) + 응답 필드 allowlist
- API GW 는 채널별 라우트(`/internal/*`, `/mobile/*`)로 `aud` 를 강제하고 consumer 별 rate-limit 적용

> 설계 근거: `모바일앱_BFF구조_검토보고서.pdf` (사내 문서, 저장소에는 미포함). 작업계획: [PLAN.md](PLAN.md), 테스트 결과: [TEST_RESULTS.md](TEST_RESULTS.md)

## 1. 구성

```
[Web 브라우저] ─► web.localhost:8000  Apache + mod_auth_openidc (Web BFF, 토큰핸들러)
                      │  Authorization: Bearer (aud=internal-api)
                      ▼
                  api-gw (FastAPI) :8100  ── /internal/** ─► 목업 내부 API
                      ▲                    └─ /mobile/**   (aud=mobile-api, 별도 quota)
                      │  Authorization: Bearer (aud=mobile-api)
[모바일 Shell] ─ticket─► spa-a.localhost:9001  Mobile BFF (Spring Cloud Gateway) ─┬─ Redis (session:mobile:spa-a:*)
  (shell-auth-mock)     spa-b.localhost:9002  Mobile BFF (동일 코드, 설정만 다름) ─┤
                                                                                 └─ Keycloak (token-exchange)
```

| 디렉토리 | 역할 | 기술 |
|---|---|---|
| `mobile-bff/` | **모바일 BFF** (SPA별 인스턴스: profile `spa-a`, `spa-b`) | Java 21, Spring Boot 3.3, Spring Cloud Gateway(WebFlux), Reactive Redis |
| `web-bff-apache/` | 기존 Web BFF 목업 | Apache 2.4 + mod_auth_openidc 2.4.12 |
| `api-gateway-py/` | API GW + 목업 내부 API | Python 3.12, FastAPI, PyJWT(JWKS) |
| `shell-auth-mock/` | Shell 인증 목업 (티켓 발급/검증) + Shell 시뮬레이터 UI | FastAPI |
| `infra/keycloak/` | realm import + token-exchange 권한 초기화 스크립트 | Keycloak 26.0.8 |
| `spa-samples/mobile/` | 샘플 모바일 SPA (두 BFF 가 같은 파일을 각자 도메인에서 서빙) | 정적 HTML/JS |
| `scripts/e2e.py` | E2E 시나리오 테스트 (48개) | Python 표준 라이브러리 |

## 2. 실행

필요: Docker / Docker Compose, Python 3 (e2e 용). `*.localhost` 는 브라우저/curl 이 127.0.0.1 로 해석하므로 **hosts 수정 불필요**.

```bash
docker compose up -d --build          # 최초 빌드 수 분 소요 (mobile-bff 는 Maven 빌드+단위테스트 포함)
python3 scripts/e2e.py                # 전체 시나리오 검증 (48 PASS 기대)
```

| URL | 설명 |
|---|---|
| http://web.localhost:8000 | Web SPA (로그인: `alice/alice` 관리자, `bob/bob` 일반) |
| http://shell.localhost:8200 | **Shell 시뮬레이터**: 로그인 후 "SPA A/B 열기" → 1회용 티켓이 fragment 로 전달되어 SPA 가 bootstrap |
| http://spa-a.localhost:9001 , http://spa-b.localhost:9002 | 모바일 SPA (Shell 시뮬레이터에서 열기) |
| http://keycloak.localhost:8080 | Keycloak (admin/admin), realm `corp` |

> Keycloak 이 http 에서도 `Secure` 쿠키를 내려주므로, 브라우저는 `*.localhost` 를 신뢰 출처로 취급하는 Chrome/Firefox 를 사용하세요.

## 3. 모바일 BFF 상세

### 3.1 인증 변환 흐름

```
Shell ── ticket(1회용 opaque) ─► SPA(WebView) ── POST /m/auth/bootstrap
                                  Authorization: Bearer <ticket>, X-Device-Id: <id>
  Mobile BFF ─ ① 티켓 검증 ─► shell-auth (소진, spa·device 바인딩 확인)
             ─ ② token-exchange(requested_subject=user, audience=mobile-api) ─► Keycloak
             ─ ③ JWT(access) 를 Redis `session:mobile:<spa>:<sid>` 에 저장 (TTL = min(idle 30m, 절대수명 7d))
             ─ ④ Set-Cookie MSESSION=<opaque sid>; HttpOnly; SameSite=Lax   ← JWT 는 클라이언트에 노출되지 않음
SPA ── GET /api/** (쿠키 + X-Device-Id) ─► Mobile BFF ─► [가드 체인] ─► API GW /mobile/api/** (Bearer JWT)
```

### 3.2 BFF 자체 엔드포인트

| Method | Path | 설명 |
|---|---|---|
| POST | `/m/auth/bootstrap` | 티켓 → 세션 생성 (Shell 티켓은 `Authorization: Bearer`) |
| GET | `/m/auth/session` | 세션 유효 여부(토큰 미노출) |
| POST | `/m/auth/refresh` | access 수동 갱신(재교환) |
| POST | `/m/auth/logout` | Redis 세션 삭제 + 쿠키 제거 |
| GET | `/m/config` | SPA 용 공개 설정 |
| ANY | `/api/**` | 가드 통과 시 API GW `/mobile/api/**` 로 프록시 |

### 3.3 가드 체인 (`ApiGuardFilter`, GlobalFilter)

1. **경로 정규화 검사** – `..`, `//`, `%2e/%2f/%5c`, `;`, `\` 포함 시 400
2. **CSRF** – 상태변경 메서드는 `X-Requested-With: XMLHttpRequest` 필수, `Origin` 이 있으면 `allowed-origins` 일치
3. **세션 조회** – 쿠키 → Redis. 없으면 `401 {"action":"reauth_shell"}`
4. **device_id 바인딩** – `X-Device-Id` 가 세션 생성 시 값과 다르면 403
5. **화이트리스트** – (method, path 패턴) 불일치 시 **403 `not_whitelisted`** + 감사로그 (기본 deny)
6. **자동 재교환** – access 만료 임박 시 Keycloak 재교환 (Redis 락으로 동시 갱신 직렬화). 실패/절대수명 초과 시 세션 삭제 후 401
7. **Bearer 주입** – 클라이언트가 보낸 `Authorization`/`Cookie`/`X-Device-Id`/`Accept-Encoding` 제거 후 `Authorization: Bearer <JWT>` 설정
8. **응답 필드 allowlist** – 규칙의 `fields` 에 있는 최상위 필드만 응답 (객체/배열). 내부 필드(`internalCost`, `customerSsn` 등) 차단

### 3.4 SPA별 설정 (`application-spa-a.yml` / `-spa-b.yml`)

하나의 코드베이스 + Spring profile 로 인스턴스를 구분합니다. SPA 별로 `spa-id`, 허용 Origin, Keycloak `client_id`
(`mobile-bff-spa-a/b`), Redis key prefix, **화이트리스트**가 다릅니다.

```yaml
mobile-bff:
  spa-id: spa-a
  whitelist:                   # 목록 외 경로는 전부 403
    - { methods: [GET],  path: /api/profile, fields: [sub, username, email, roles] }
    - { methods: [GET],  path: /api/orders,  fields: [id, item, qty, price] }
    - { methods: [POST], path: /api/orders,  fields: [id, item, qty, price] }
```

### 3.5 주요 소스

| 파일 | 내용 |
|---|---|
| `AuthController` | bootstrap / session / refresh / logout / config |
| `ApiGuardFilter` | 가드 체인 8단계 + 응답 필드 필터 |
| `Whitelist`, `ResponseFields`, `CsrfGuard` | 매칭(PathPattern)·경로검사, 필드 allowlist, CSRF |
| `SessionStore`, `Session` | Reactive Redis 세션 저장 (슬라이딩 TTL, refresh 락) |
| `KeycloakClient`, `ShellTicketClient` | token-exchange 호출 / 티켓 검증 호출 |
| `GatewayRoutes` | `/api/**` → GW `/mobile/api/**` 라우트 |

## 4. Keycloak 설정 요점 (`infra/keycloak`)

- realm `corp`, 서버 옵션 `--features=token-exchange,admin-fine-grained-authz` (**legacy token-exchange(preview)**: impersonation 지원)
- clients: `web-bff`(code flow, 오디언스 매퍼 `internal-api`), `mobile-bff-spa-a/b`(exchange 전용, 인터랙티브 로그인 불가), `internal-api`/`mobile-api`(audience 대상)
- `init_exchange.py` (kc-init 컨테이너): 사용자 **impersonate** 권한과 `mobile-api` 대상 **token-exchange** 권한을 `mobile-bff-spa-*` 클라이언트에만 부여 (idempotent)
- 웹 JWT `aud=internal-api`, 모바일 JWT `aud=mobile-api` → API GW 가 채널을 `aud` 클레임으로 구분

## 5. 알게 된 점 / 설계상 결정 (실측 기반)

1. **impersonation 교환 토큰은 refresh grant 불가**: Keycloak 이 `Session doesn't have required client` 로 거부.
   → refresh token 을 저장하지 않고, access 만료 시 **BFF 가 같은 사용자로 재교환**. 세션 절대수명은 BFF(`max-lifetime`)가 통제.
   IdP 에서 사용자를 비활성화하면 다음 재교환이 실패해 세션이 종료됨(테스트 F2).
2. **libcurl(mod_auth_openidc)은 `*.localhost` 를 컨테이너 루프백으로 강제 해석** → Apache 는 내부 주소(`keycloak:8080`)로 메타데이터를 조회하고,
   Keycloak 은 `KC_HOSTNAME`(issuer 고정) + `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true` 로 설정. (운영은 실도메인이므로 해당 없음)
3. mod_auth_openidc 2.4.12 에는 `OIDCPassAccessToken` 지시어가 없음 → 지시어 없이 `OIDC_access_token` 환경변수를 `RequestHeader set Authorization` 에 사용.

## 6. 목업의 한계 / 운영 전환 시 과제

- 모든 통신 http (운영: https, `cookie-secure: true`, Secure/`__Host-` 쿠키)
- Redis 값 암호화, 세션 pub/sub 즉시 무효화, DPoP(디바이스 바인딩 토큰), 장애 격리용 quota 는 미구현 (보고서 §4 의 TO-BE 항목)
- device_id 는 헤더 값 비교 수준 (실제로는 Shell 이 발급·서명한 값/OS 보안저장소 연계 필요)
- token-exchange 는 Keycloak **legacy(preview) 기능**: 운영 Keycloak 버전/정책에서 impersonation 허용 범위(보고서 §3.1)를 반드시 검토
- 응답 필드 필터는 최상위 필드만 지원(중첩 경로 미지원), 대용량/스트리밍 응답은 버퍼링 방식
- `usercontext-lib` 공통 라이브러리 연계, API GW 의 scope 검사, 운영 감사로그 체계는 범위 외
