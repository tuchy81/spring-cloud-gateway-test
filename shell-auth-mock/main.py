"""mocean Shell 인증 목업.

Shell 은 로그인 후 opaque 토큰(=티켓)을 발급하고, 각 SPA 웹앱에 헤더(Authorization: Bearer)로 전달한다.
티켓 = 1회용 임의 문자열 (TTL 60s, 대상 spa 바인딩). 검증은 mobile-bff 만 호출(API key).
"""
import os, secrets, time
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

API_KEY = os.environ.get("SHELL_BFF_API_KEY", "shell-bff-key")
USERS = {"alice": "alice", "bob": "bob"}
TICKET_TTL = 60

app = FastAPI(title="shell-auth-mock")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
shell_sessions: dict = {}   # shell session token -> {username, device_id}
tickets: dict = {}          # ticket -> {username, spa, device_id, exp}


class Login(BaseModel):
    username: str
    password: str
    device_id: str | None = None


class Issue(BaseModel):
    spa: str


class Verify(BaseModel):
    ticket: str
    spa: str
    device_id: str | None = None


@app.post("/shell/login")
def login(b: Login):
    if USERS.get(b.username) != b.password:
        raise HTTPException(401, "bad credentials")
    tok = secrets.token_urlsafe(24)
    shell_sessions[tok] = {"username": b.username, "device_id": b.device_id or "dev-" + secrets.token_hex(4)}
    return {"shell_session": tok, "device_id": shell_sessions[tok]["device_id"]}


@app.post("/shell/ticket")
def issue(b: Issue, authorization: str = Header("")):
    s = shell_sessions.get(authorization.removeprefix("Bearer ").strip())
    if not s:
        raise HTTPException(401, "no shell session")
    t = secrets.token_urlsafe(32)
    tickets[t] = {"username": s["username"], "spa": b.spa, "device_id": s["device_id"], "exp": time.time() + TICKET_TTL}
    return {"ticket": t, "device_id": s["device_id"], "expires_in": TICKET_TTL}


@app.post("/shell/ticket/verify")
def verify(b: Verify, x_api_key: str = Header("")):
    if x_api_key != API_KEY:
        raise HTTPException(401, "bad api key")
    t = tickets.pop(b.ticket, None)           # 1회용: 조회 즉시 소진
    if not t or t["exp"] < time.time():
        raise HTTPException(401, "invalid or expired ticket")
    if t["spa"] != b.spa or (b.device_id and t["device_id"] != b.device_id):
        raise HTTPException(401, "ticket binding mismatch")
    return {"username": t["username"], "device_id": t["device_id"]}


@app.get("/")
def sim():
    return FileResponse("static/shell.html")
