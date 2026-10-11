# 모바일 SPA BFF 목업 작업계획

## 1. 목표

| # | 목표 |
|---|------|
| G1 | 기존 Web 인증체계 유지: **OIDC + BFF(Token Handler) 패턴** (Apache + mod_auth_openidc) |
| G2 | 기존 모바일 Shell 인증 유지 (Shell이 발급하는 티켓/토큰을 **HTTP 헤더**로 전송) |
| G3 | Shell 내부 개별 SPA는 하이브리드(WebView) 웹앱이며 **SPA별 도메인**을 가짐 → **SPA별 모바일 BFF** 필요 |
| G4 | 모바일 BFF는 Shell 티켓을 **Web 인증체계로 변환**: 인증서버(OIDC)에서 JWT 발급 → **별도 Redis에 저장** → JWT로 기존 Web API(API GW) 호출 |
| G5 | 기존 API 중 **모바일 BFF 화이트리스트에 정의된 것만** 모바일에서 호출 가능 (기본 거부) |

비목표: 실제 운영 인프라 연동, 실제 Shell 앱(네이티브) 구현, UI 완성도. 목업은 **흐름과 경계의 검증**이 목적.

## 2. 기술 스택 (확정 요청 사항)

| 구성요소 | 구현 | 비고 |
|---|---|---|
| 인증서버 (IdP) | Keycloak (dev 모드, realm import) | 대안: Python 목업 IdP. Token Exchange(RFC 8693) 지원 필요 → 아래 §6 결정사항 참고 |
| Web BFF | **Apache httpd 2.4 + mod_auth_openidc** | 브라우저 세션 쿠키, 토큰은 서버측 보관, 업스트림에 `Authorization: Bearer` 주입 |
| API Gateway | **Python (FastAPI)** | JWT 검증(JWKS), scope/audience 검사, 하위 목업 API 라우팅 |
| 목업 백엔드 API | Python (FastAPI) – API GW 내 라우터 또는 별도 컨테이너 | `/api/profile`, `/api/orders`, `/api/admin/*` 등 |
| **모바일 BFF** | **Spring Cloud Gateway (WebFlux, Java 21, Spring Boot 3.x)** | SPA별 인스턴스 (동일 코드, 설정만 다름) |
| 세션/토큰 저장소 | Redis 7 (모바일 BFF 전용, 웹과 분리) | Spring Data Redis Reactive |
| Shell 인증 목업 | Python (FastAPI) `shell-auth-mock` | 티켓 발급/검증 API 제공 |
| 샘플 SPA | 정적 HTML/JS 2개 (spa-a, spa-b) | 각기 다른 도메인, BFF 경유 |
| 오케스트레이션 | docker-compose + nginx/hosts 로컬 도메인 | `*.local.test` |

## 3. 목표 아키텍처

```
[Web 브라우저] ──► web.local.test (Apache + mod_auth_openidc) ──┐
                       │ OIDC code flow / 세션쿠키               │ Bearer JWT
                       ▼                                          ▼
                   Keycloak (IdP)                         api-gw.local.test (FastAPI)
                       ▲                                          ▲   ▲
                       │ token exchange / refresh                 │   │ Bearer JWT
[모바일 Shell] ─ticket(헤더)─► WebView ──► spa-a.local.test ──►   │   │
  (shell-auth-mock)                         Mobile BFF (SCG) ─────┘   │
                                            ├─ Redis (JWT 저장)       │
                                            └─ 화이트리스트 필터      │
                                      spa-b.local.test ► Mobile BFF(B)┘
```

핵심: **API GW 입장에서 Web 요청과 Mobile 요청은 동일한 JWT 소비자**. 차이는 BFF 앞단 인증 방식과 화이트리스트뿐.

## 4. 모바일 BFF 상세 설계

### 4.1 인증 변환 흐름 (Shell 티켓 → OIDC JWT)

1. Shell이 SPA WebView를 열며 **티켓을 헤더로 전달** (`X-Shell-Ticket`, 최초 부트스트랩 요청).
2. SPA → `POST https://spa-a.local.test/m/auth/bootstrap` (헤더에 티켓).
3. 모바일 BFF가 Shell 인증서버(`shell-auth-mock`)에 티켓 검증 요청 → 사용자 식별자/클레임 획득.
4. BFF가 Keycloak에 **Token Exchange**(subject_token=티켓 검증 결과 기반) 또는 신뢰 클라이언트 방식으로 **JWT(access/refresh/id)** 발급.
5. BFF가 JWT를 **Redis에 저장** (키: `mbff:{spaId}:sess:{sid}`, TTL=refresh 만료).
6. BFF가 **HttpOnly/Secure/SameSite 세션 쿠키**(sid)만 SPA에 발급 → **브라우저/WebView에 JWT 노출 없음** (Token Handler 유지).
7. 이후 `/api/**` 호출: 쿠키 → Redis 조회 → 만료 임박 시 refresh → 화이트리스트 검사 → `Authorization: Bearer` 주입 → API GW 프록시.

> 티켓은 1회용(nonce) + 짧은 TTL로 가정. 재사용 시 거부(리플레이 방지)는 Shell mock과 BFF 양쪽에서 검증.

### 4.2 필요한 엔드포인트 (BFF 자체 제공)

| Method | Path | 설명 |
|---|---|---|
| POST | `/m/auth/bootstrap` | 티켓(헤더) → JWT 발급·Redis 저장·세션쿠키 발급 |
| GET | `/m/auth/session` | 세션 유효 여부 및 사용자 기본정보(JWT 미노출) |
| POST | `/m/auth/refresh` | 수동 refresh (자동 refresh는 필터에서 처리) |
| POST | `/m/auth/logout` | Redis 세션 삭제, (선택) IdP revoke |
| GET | `/m/config` | SPA용 공개 설정(spaId, API prefix 등) |
| GET | `/actuator/health` | 헬스체크 |
| ANY | `/api/**` | 화이트리스트 통과 시 API GW로 프록시 |

### 4.3 Gateway 필터 체인 (SCG GlobalFilter)

1. `CorrelationIdFilter` – 요청 추적 ID
2. `CsrfGuardFilter` – 변경성 메서드에 커스텀 헤더(`X-Requested-With`) + Origin 검사
3. `SessionResolveFilter` – 쿠키 → Redis에서 토큰 로드, 없으면 401
4. `TokenRefreshFilter` – 만료 임박 시 refresh (동일 sid 동시 refresh 방지: Redis 락)
5. `WhitelistFilter` – (method, path pattern) 불일치 시 **403** (기본 거부), 감사로그
6. `BearerRelayFilter` – `Authorization: Bearer <access_token>` 주입, 클라이언트가 보낸 Authorization/Cookie 헤더는 제거
7. 라우트 → API GW

### 4.4 SPA별 BFF 구성

- 하나의 코드베이스, **Spring profile / 설정 파일로 SPA별 인스턴스** (`application-spa-a.yml`, `application-spa-b.yml`).
- SPA별 설정: `spaId`, 허용 Origin(도메인), Keycloak client_id, Redis key prefix, **화이트리스트 룰**, 쿠키 도메인/이름.
- 화이트리스트 예 (`whitelist-spa-a.yml`):
  ```yaml
  mobile-bff:
    whitelist:
      - { methods: [GET],  path: /api/profile }
      - { methods: [GET],  path: /api/orders/** }
      - { methods: [POST], path: /api/orders }
    # 목록에 없는 경로(/api/admin/** 등)는 403
  ```

## 5. Web 측 목업 상세

### 5.1 Web BFF (Apache + mod_auth_openidc)
- `OIDCProviderMetadataURL` = Keycloak, `OIDCCryptoPassphrase`, 세션은 서버측 캐시(shm/redis).
- `/` 보호(`AuthType openid-connect`), `/api/` → API GW로 `ProxyPass` + `OIDCPassAccessToken On` / `OIDCPassClaimsAs`로 Bearer 전달.
- 샘플 웹 SPA 정적 파일 서빙, `/redirect_uri`, 로그아웃 경로 설정.

### 5.2 API GW (Python)
- FastAPI + `python-jose`/`PyJWT`, JWKS 캐시, `iss`/`aud`/`exp`/scope 검사.
- 목업 API: `/api/profile`, `/api/orders`(GET/POST), `/api/admin/users`(role=admin 필요).
- 호출 주체(`azp`/client_id)를 로그에 남겨 web vs mobile 구분 가능하게 함.

### 5.3 Shell 인증 목업
- `POST /shell/login` → 티켓 발급 (1회용, TTL 60s), `POST /shell/ticket/verify` → 사용자 정보 반환 (BFF 전용 API key).
- 테스트용 최소 CLI/HTML "Shell 시뮬레이터": 티켓을 받아 헤더로 SPA 부트스트랩을 호출하는 페이지.

## 6. 결정이 필요한 사항 (기본값 제안)

| # | 질문 | 기본 제안 |
|---|---|---|
| Q1 | 티켓 → JWT 변환 방식 | Keycloak **Token Exchange**(RFC 8693) 우선. 불가 시 BFF가 신뢰 클라이언트(client credentials + impersonation)로 사용자 토큰 발급 |
| Q2 | IdP | Keycloak 컨테이너 (Python 목업 IdP는 대안) |
| Q3 | 모바일 후속 요청 인증 | 최초 티켓 → **세션쿠키**(Token Handler). 매 요청 티켓 헤더 방식이 필요하면 알려주세요 |
| Q4 | 티켓 형식 | 불투명 1회용 문자열(서버 검증). JWT 서명형이면 검증 로직 변경 |
| Q5 | JWT 클라이언트 구분 | 모바일은 별도 `client_id`(spa별)로 발급 → API GW에서 구분 |
| Q6 | WebView 쿠키 | SameSite 정책 이슈 확인 필요(SPA 도메인 == BFF 도메인이므로 first-party 가정) |

## 7. 디렉토리 구조

```
mobile+web/
├─ PLAN.md
├─ docker-compose.yml
├─ README.md                    # 실행/시연 방법
├─ infra/
│  ├─ keycloak/realm-export.json   # realm, clients(web, mobile-spa-a/b), users
│  ├─ hosts.sample                 # *.local.test
│  └─ certs/                       # 로컬 TLS (mkcert)
├─ web-bff-apache/              # Dockerfile, httpd.conf, openidc.conf, html/
├─ api-gateway-py/              # FastAPI, JWT 검증, 목업 API
├─ shell-auth-mock/             # FastAPI, 티켓 발급/검증 + Shell 시뮬레이터
├─ mobile-bff/                  # Spring Cloud Gateway
│  ├─ src/main/java/.../{config,filter,auth,session,whitelist}
│  ├─ src/main/resources/{application.yml,application-spa-a.yml,application-spa-b.yml,whitelist-*.yml}
│  └─ src/test/
└─ spa-samples/{spa-a,spa-b,web}/
```

## 8. 작업 단계

| 단계 | 내용 | 산출물 / 완료 기준 |
|---|---|---|
| P0 | 기존 문서 검토, Q1~Q6 확정 | 확정된 결정사항 (본 문서 §6 갱신) |
| P1 | 인프라 골격: docker-compose, Keycloak realm, hosts/TLS | `docker compose up`으로 Keycloak, Redis 기동 |
| P2 | API GW(Python) + 목업 API | JWT 없으면 401, scope 부족 403, curl 테스트 통과 |
| P3 | Web BFF(Apache+mod_auth_openidc) | 브라우저 로그인 → `/api/profile` 호출 성공 (G1) |
| P4 | Shell 인증 목업 | 티켓 발급/검증/1회용 동작 |
| P5 | 모바일 BFF 코어: SCG 프록시, Redis 세션, bootstrap 엔드포인트(티켓→JWT) | 티켓으로 세션쿠키 획득, Redis에 JWT 저장 확인 (G2,G4) |
| P6 | 모바일 BFF 필터: 자동 refresh, CSRF, **화이트리스트**, Bearer 주입 | 허용 경로 200 / 비허용 403 (G5) |
| P7 | SPA별 인스턴스화 (spa-a, spa-b 도메인·설정 분리) | 두 SPA가 각자 세션/화이트리스트로 동작 (G3) |
| P8 | 샘플 SPA + Shell 시뮬레이터로 E2E 시연 | 시나리오 스크립트 통과 |
| P9 | 문서화(README, 시퀀스 다이어그램), 보안 점검 | 실행/구조 문서 완성 |

## 9. 테스트 / 검증 시나리오

1. **Web**: 로그인 → 세션쿠키 → API 200, 로그아웃 후 401/리다이렉트.
2. **Mobile 정상**: 유효 티켓 → bootstrap 200 + 쿠키 → 화이트리스트 API 200.
3. **티켓 재사용 / 만료 / 위조** → bootstrap 401.
4. **비화이트리스트**(`/api/admin/users`) → 모바일 BFF에서 403 (API GW 도달 안 함), 웹에서는 권한에 따라 접근 가능.
5. **JWT 노출 없음**: 응답 본문/헤더/쿠키에 access/refresh 토큰이 없음.
6. **Refresh**: access 만료 시 자동 갱신, refresh 만료 시 401 → Shell 재인증 유도.
7. **SPA 격리**: spa-a 세션쿠키로 spa-b BFF 호출 불가, Redis 키 prefix 분리.
8. **클라이언트 헤더 위조**: 클라이언트가 보낸 `Authorization` 무시/제거 확인.
9. 자동화: mobile-bff는 JUnit + WebTestClient + Testcontainers(Redis), 전체는 `scripts/e2e.sh`(curl).

## 10. 보안 고려 (목업이라도 반영할 것)
- 토큰은 서버측(Redis)에만 보관, 쿠키는 opaque sid (HttpOnly, Secure, SameSite).
- Redis 값 암호화 여부는 목업에서는 생략 가능하나 확장 포인트로 명시.
- 화이트리스트는 **기본 거부**, path normalization(`..`, 이중 슬래시, 대소문자) 우회 방지.
- 티켓 검증 호출은 BFF↔Shell 서버 간 인증(API key/mTLS 목업).
- 로그에 토큰/티켓 마스킹.

## 12. 확정 사항 및 구현 결과 (2026-10-11)

- 확정: 티켓→JWT 는 **Keycloak token-exchange**, 후속 요청은 세션쿠키, 티켓은 **1회용 임의 문자열**.
- 검토보고서(`모바일앱_BFF구조_검토보고서.pdf`) 반영: Redis `session:mobile:*` 분리, `aud=mobile-api` + 짧은 TTL, API GW `/mobile/*`·`/internal/*` 라우트 분리 및 채널별 quota, device_id 바인딩, allowlist + 응답 필드 allowlist.
- 계획 대비 변경: impersonation 교환 토큰은 refresh 불가 → **재교환 방식**으로 대체 (README §5).
- 구현 완료(P1~P9) 및 검증: [README.md](README.md), [TEST_RESULTS.md](TEST_RESULTS.md) (단위 4/4, E2E 48/48).

## 11. 다음 액션 (계획 당시)
1. 본 계획 검토 및 §6 결정사항 회신 (특히 Q1, Q3, Q4).
2. 기존 문서(요구/아키텍처) 경로를 알려주시면 P0에서 대조하여 계획을 보정합니다.
3. 승인 후 P1부터 순차 구현.
