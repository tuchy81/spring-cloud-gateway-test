"""API Gateway 목업 (FastAPI).

- 라우트 단위 채널 분리 (검토보고서 §4)
    /internal/**  : web consumer    (aud=internal-api)
    /mobile/**    : mobile consumer (aud=mobile-api, 별도 quota)
- JWT 서명(JWKS) / iss / aud / exp 검증, consumer(azp)별 rate-limit
- 하위 "내부 API" 는 같은 프로세스의 목업 라우터로 대체
"""
import os, time, logging, threading
from collections import defaultdict, deque

import jwt
from jwt import PyJWKClient
from fastapi import FastAPI, Request, HTTPException

ISSUER = os.environ["OIDC_ISSUER"]
JWKS_URL = os.environ.get("JWKS_URL", ISSUER + "/protocol/openid-connect/certs")

CHANNELS = {
    "internal": {"aud": "internal-api", "azp": {"web-bff"}, "rate_per_min": 600},
    "mobile": {"aud": "mobile-api", "azp": {"mobile-bff-spa-a", "mobile-bff-spa-b"}, "rate_per_min": 60},
}

log = logging.getLogger("api-gw")
logging.basicConfig(level=logging.INFO)
app = FastAPI(title="api-gw-mock")
jwks = PyJWKClient(JWKS_URL, cache_keys=True, lifespan=300)

_hits: dict = defaultdict(deque)
_lock = threading.Lock()


def rate_limit(key: str, limit: int):
    now = time.time()
    with _lock:
        q = _hits[key]
        while q and q[0] < now - 60:
            q.popleft()
        if len(q) >= limit:
            raise HTTPException(429, "rate limit exceeded")
        q.append(now)


def authenticate(request: Request) -> dict:
    channel = request.path_params["channel"]
    cfg = CHANNELS.get(channel)
    if not cfg:
        raise HTTPException(404, "unknown channel")
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    token = auth[7:].strip()
    try:
        key = jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=cfg["aud"], issuer=ISSUER,
                            options={"require": ["exp", "iss", "aud"]})
    except Exception as e:  # noqa: BLE001
        log.warning("jwt rejected on %s: %s", channel, e)
        raise HTTPException(401, "invalid token")
    if claims.get("azp") not in cfg["azp"]:
        raise HTTPException(403, "consumer not allowed on this channel")
    rate_limit(f"{channel}:{claims.get('azp')}:{claims.get('sub')}", cfg["rate_per_min"])
    claims["_channel"] = channel
    log.info("channel=%s consumer=%s user=%s %s %s", channel, claims.get("azp"),
             claims.get("preferred_username"), request.method, request.url.path)
    return claims


def roles(c: dict):
    return set(c.get("realm_access", {}).get("roles", []))


# ---------------- 목업 내부 API ---------------- #
ORDERS = [
    {"id": 1, "item": "keyboard", "qty": 2, "price": 30000, "owner": "alice", "internalCost": 21000, "customerSsn": "800101-1234567"},
    {"id": 2, "item": "monitor", "qty": 1, "price": 250000, "owner": "bob", "internalCost": 190000, "customerSsn": "900202-2345678"},
]


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.api_route("/{channel}/api/profile", methods=["GET"])
def profile(request: Request):
    c = authenticate(request)
    return {"sub": c["sub"], "username": c.get("preferred_username"), "email": c.get("email"),
            "roles": sorted(roles(c)), "channel": c["_channel"], "consumer": c.get("azp"),
            "aud": c.get("aud"), "internalNote": "hr-grade=S3"}


@app.get("/{channel}/api/orders")
def list_orders(request: Request):
    c = authenticate(request)
    return ORDERS if "admin" in roles(c) else [o for o in ORDERS if o["owner"] == c.get("preferred_username")]


@app.get("/{channel}/api/orders/{oid}")
def get_order(oid: int, request: Request):
    authenticate(request)
    for o in ORDERS:
        if o["id"] == oid:
            return o
    raise HTTPException(404, "not found")


@app.post("/{channel}/api/orders")
async def create_order(request: Request):
    c = authenticate(request)
    body = await request.json()
    o = {"id": len(ORDERS) + 1, "item": body.get("item", "?"), "qty": body.get("qty", 1), "price": body.get("price", 0),
         "owner": c.get("preferred_username"), "internalCost": 0, "customerSsn": "000000-0000000"}
    ORDERS.append(o)
    return o


@app.get("/{channel}/api/admin/users")
def admin_users(request: Request):
    c = authenticate(request)
    if "admin" not in roles(c):
        raise HTTPException(403, "admin only")
    return [{"username": "alice", "role": "admin"}, {"username": "bob", "role": "user"}]


@app.get("/{channel}/api/hr/employees/export")
def hr_export(request: Request):
    c = authenticate(request)
    if "admin" not in roles(c):
        raise HTTPException(403, "admin only")
    return {"rows": 12345, "note": "대량 다운로드 API (모바일 비노출 대상)"}
