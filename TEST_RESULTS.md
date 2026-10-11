# 테스트 결과

- 실행 일시: 2026-10-11 (WSL2 / Docker 28.5.0, Compose v2.40)
- 대상: `docker compose up -d --build` 로 기동한 전체 스택 (Keycloak 26.0.8, Apache 2.4.68 + mod_auth_openidc 2.4.12, FastAPI GW, Spring Cloud Gateway BFF ×2, Redis 7)
- 원본 출력: [scripts/e2e-output.txt](scripts/e2e-output.txt)

## 요약

| 구분 | 결과 |
|---|---|
| 단위 테스트 (mobile-bff, JUnit5 `WhitelistTest`) | **4/4 PASS** |
| E2E 시나리오 (`python3 scripts/e2e.py`) | **48/48 PASS** |

## E2E 시나리오별 결과

| ID | 검증 내용 | 결과 |
|---|---|---|
| M1 | 유효 티켓 bootstrap 200 + 세션쿠키 발급 | PASS |
| M2 | 세션쿠키 HttpOnly | PASS |
| M3 | 응답 본문/쿠키에 JWT 미노출 | PASS |
| M4 | 화이트리스트 `/api/profile` 200 | PASS |
| M5 | 응답 필드 allowlist (`aud`, `internalNote`, `consumer` 제거) | PASS |
| M6 | `/api/orders` 200, `internalCost`/`customerSsn` 제거 | PASS |
| M7 | `POST /api/orders` 200 | PASS |
| W1 ×3 | 비허용 `/api/admin/users`, `/api/hr/employees/export`, `/api/unknown` → 403 `not_whitelisted` | PASS |
| W2 | 허용 경로라도 비허용 메서드(DELETE) → 403 | PASS |
| W3 ×3 | 경로 우회(`..`, `//`, `%2e%2e`) 차단 | PASS |
| T1 | 티켓 재사용 거부 (1회용) | PASS |
| T2 | 위조 티켓 거부 | PASS |
| T3 | 다른 SPA 용 티켓 거부 (spa 바인딩) | PASS |
| T4 | 티켓-디바이스 불일치 거부 | PASS |
| T5 | CSRF 헤더 없는 bootstrap 거부 | PASS |
| S1 | `X-Device-Id` 불일치 → 403 | PASS |
| S2 | 세션쿠키 없음 → 401 | PASS |
| S3 | 클라이언트가 보낸 `Authorization` 무시 | PASS |
| S4 | 허용되지 않은 Origin 의 POST 거부 | PASS |
| S5 | `/m/auth/session` 응답에 토큰 미노출 | PASS |
| R1 | Redis 키 네임스페이스 `session:mobile:spa-a:*` | PASS |
| R2 | Redis 에 access JWT 저장, refresh token 미저장 | PASS |
| R3 | Redis TTL 설정 (0 < TTL ≤ 30m) | PASS |
| R4 | JWT `aud=mobile-api`, `azp=mobile-bff-spa-a` | PASS |
| I1 | spa-a 세션쿠키를 spa-b BFF 에서 사용 불가 | PASS |
| I2 | spa-b bootstrap 200 | PASS |
| I3 | spa-b 별도 정책(필드 제한 없음) 적용 | PASS |
| I4 | spa-b 는 `POST /api/orders` 비허용 | PASS |
| I5 | bob 은 본인 주문만 조회 (JWT 사용자 전파) | PASS |
| L1–L3 | logout 200 / 이후 401 / Redis 세션 삭제 | PASS |
| F1 | access 만료 시 자동 재교환 후 200 (새 토큰으로 교체) | PASS |
| F2 | 재교환 실패(IdP 사용자 무효) → 401 `reauth_shell` + 세션 삭제 | PASS |
| G1 | GW `/mobile/*` : mobile JWT 허용 | PASS |
| G2 | GW `/internal/*` : mobile JWT(`aud=mobile-api`) 거부 | PASS |
| G3 | GW 토큰 없음 → 401 | PASS |
| W-1 | Web 미인증 `/api` → 401 (리다이렉트 아님) | PASS |
| W-2 | Web OIDC code flow 로그인 후 SPA 로드 | PASS |
| W-3 | Web `/api/profile` 200 (Apache 가 Bearer 주입) | PASS |
| W-4 | Web 채널=internal, `aud=internal-api`, consumer=web-bff | PASS |
| W-5 | Web 은 기존 정책대로 admin API 접근 가능 (alice=admin) | PASS |
| W-6 | Web 쿠키는 세션 id(`web_session`)만, JWT 없음 | PASS |
| W-7 | Web 상태변경 API 는 CSRF 헤더 없으면 403 | PASS |

## 테스트 중 발견·수정한 문제

| # | 현상 | 원인 | 조치 |
|---|---|---|---|
| 1 | kc-init 404 | fine-grained permission 활성화 전에는 `realm-management` resource server 가 없음 | 활성화 후 policy 생성하도록 순서 변경 |
| 2 | Apache 기동 실패 | `OIDCCookieSameSite` 값 형식, 2.4.12 에 `OIDCPassAccessToken` 없음 | 지시어 정리 |
| 3 | **access 만료 후 갱신 실패 (400 invalid_grant)** | Keycloak impersonation 교환 토큰은 refresh grant 불가 | refresh 대신 **재교환** 방식으로 설계 변경 (제품 결함 수정) |
| 4 | 재교환 실패 시 `reauth_shell` 바디 없이 Spring 기본 401 | `ResponseStatusException` 미변환 | 가드 필터에서 JSON 401 로 변환 (제품 결함 수정) |
| 5 | Web 로그인 500 | libcurl 이 `*.localhost` 를 루프백으로 해석 → 컨테이너 내부에서 Keycloak 접속 불가 | Apache 는 내부 주소로 메타데이터 조회 + Keycloak dynamic backchannel |
| 6 | (테스트 하네스) 로그인 400 `cookie_not_found` | Python cookiejar 가 http 에서 Secure 쿠키 미전송 (브라우저는 `*.localhost` 신뢰) | 테스트 클라이언트에서 Secure 플래그 무시 |

## 검증하지 못한 항목

- 실제 모바일 WebView / Cordova Shell 에서의 쿠키·Origin 동작 (iOS ITP 등) – 목업은 데스크톱 브라우저/HTTP 클라이언트 기준
- https 환경(Secure 쿠키), 부하·동시성(동일 세션 동시 재교환 락은 코드 구현만, 별도 부하 테스트 미수행)
- 브라우저 UI 수동 확인(Shell 시뮬레이터 → SPA 열기 흐름)은 e2e 에서 동일 API 호출로 대체하여 검증
