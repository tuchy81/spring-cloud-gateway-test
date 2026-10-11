"""Keycloak legacy token-exchange(impersonation) 권한 설정.

mobile-bff-spa-* 클라이언트가
  - 사용자 impersonate 권한
  - audience=mobile-api 대상 token-exchange 권한
을 갖도록 fine-grained permission 을 구성한다. (idempotent)
"""
import json, os, sys, time, urllib.parse, urllib.request, urllib.error

KC = os.environ.get("KC_URL", "http://keycloak:8080")
REALM = os.environ.get("REALM", "corp")
EXCHANGERS = ["mobile-bff-spa-a", "mobile-bff-spa-b"]
TARGETS = ["mobile-api"]


def call(method, path, token=None, body=None, form=None):
    url = KC + path
    data, headers = None, {}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code} {method} {path}: {e.read().decode()[:400]}", file=sys.stderr)
        raise


def wait_ready():
    for _ in range(120):
        try:
            urllib.request.urlopen(KC + f"/realms/{REALM}/.well-known/openid-configuration", timeout=3)
            return
        except Exception:
            time.sleep(2)
    sys.exit("keycloak not ready")


def main():
    wait_ready()
    tok = call("POST", "/realms/master/protocol/openid-connect/token", form={
        "grant_type": "password", "client_id": "admin-cli",
        "username": os.environ.get("KC_ADMIN", "admin"), "password": os.environ.get("KC_ADMIN_PW", "admin")})["access_token"]
    adm = f"/admin/realms/{REALM}"
    clients = {c["clientId"]: c["id"] for c in call("GET", adm + "/clients?max=200", tok)}
    rm = clients["realm-management"]
    ex_ids = [clients[c] for c in EXCHANGERS]

    # fine-grained permission 활성화 → realm-management resource server 초기화 (policy 생성의 선행조건)
    up = call("PUT", adm + "/users-management-permissions", tok, {"enabled": True})

    pol_name = "mobile-bff-exchangers"
    base = f"{adm}/clients/{rm}/authz/resource-server"
    existing = call("GET", f"{base}/policy?name={pol_name}", tok)
    if existing:
        pid = existing[0]["id"]
        call("PUT", f"{base}/policy/client/{pid}", tok, {"id": pid, "name": pol_name, "type": "client",
             "logic": "POSITIVE", "decisionStrategy": "UNANIMOUS", "clients": ex_ids})
    else:
        pid = call("POST", f"{base}/policy/client", tok, {"name": pol_name, "type": "client",
                   "logic": "POSITIVE", "decisionStrategy": "UNANIMOUS", "clients": ex_ids})["id"]

    def attach(perm_id):
        p = call("GET", f"{base}/policy/{perm_id}", tok)
        res = [r["_id"] for r in call("GET", f"{base}/policy/{perm_id}/resources", tok)]
        scp = [s["id"] for s in call("GET", f"{base}/policy/{perm_id}/scopes", tok)]
        cur = [x["id"] for x in call("GET", f"{base}/policy/{perm_id}/associatedPolicies", tok)]
        if pid in cur:
            return
        call("PUT", f"{base}/policy/scope/{perm_id}", tok, {
            "id": perm_id, "name": p["name"], "type": "scope", "logic": p.get("logic", "POSITIVE"),
            "decisionStrategy": p.get("decisionStrategy", "UNANIMOUS"),
            "resources": res, "scopes": scp, "policies": cur + [pid]})

    # 1) users impersonate permission
    attach(up["scopePermissions"]["impersonate"])
    # 2) audience(target) client token-exchange permission
    for t in TARGETS:
        cp = call("PUT", f"{adm}/clients/{clients[t]}/management/permissions", tok, {"enabled": True})
        attach(cp["scopePermissions"]["token-exchange"])
    print("token-exchange permissions configured")


if __name__ == "__main__":
    main()
