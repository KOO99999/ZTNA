"""
auth_gate.py(nginx auth_request가 묻는 판단 서비스)를 실제 AWS/네트워크 없이 검증.
Cloudflare 공개키와 Lambda 호출은 가짜로 대체한다. (nginx 자체의 동작은 이 파일이 아니라
실제 nginx로 따로 시험함 - 설정 문법/장애 시 차단/헤더 위조는 그쪽에서 확인)
"""
import os
import sys
import io
import contextlib
import time as _time
import jwt as pyjwt
from unittest.mock import MagicMock
from cryptography.hazmat.primitives.asymmetric import rsa

os.environ["PDP_EVALUATE_URL"] = "https://pdp.test/evaluate"
os.environ["EVALUATE_SHARED_SECRET"] = "test-secret-local-only"
os.environ["AUTH_DOMAIN"] = "auth.xmcda.store"
os.environ["CF_TEAM_DOMAIN"] = "team-test.cloudflareaccess.com"
os.environ["CF_ACCESS_AUDS"] = "aud-portal,aud-admin"
sys.path.insert(0, '.')
import zt_jwt as zj
import zt_risk as zr
import auth_gate as ag

fails = 0
def check(name, cond, detail=""):
    global fails
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f"\n    -> {detail}" if detail else ""))
    if not cond:
        fails += 1

GOOD = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EVIL = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ISS = "https://team-test.cloudflareaccess.com"
zj._fetch_jwks = lambda: {"kid-good": GOOD.public_key()}
zj._jwks.update({"keys": {}, "fetched_at": 0.0})

def token(email="hana@test.com", key=None, exp_delta=300, aud=("aud-portal",), drop=()):
    now = int(_time.time())
    c = {"email": email, "iss": ISS, "aud": list(aud), "iat": now, "exp": now + exp_delta}
    for d in drop:
        c.pop(d, None)
    return pyjwt.encode(c, key or GOOD, algorithm="RS256", headers={"kid": "kid-good"})

calls = []
reply = {"allow": True, "action": "allow", "score": 0, "resource_threshold": 40, "resource_tier": "confidential"}
status = 200
boom = False
def fake_post(url, headers=None, json=None, timeout=None):
    calls.append(json)
    if boom:
        raise RuntimeError("network down")
    r = MagicMock(); r.status_code = status; r.json.return_value = dict(reply)
    return r
zr.requests.post = fake_post

def reset(resp=None, st=200, err=False):
    global reply, status, boom
    calls.clear(); zr._cache.clear()
    reply = resp or {"allow": True, "action": "allow", "score": 0, "resource_threshold": 40, "resource_tier": "confidential"}
    status, boom = st, err

client = ag.app.test_client()
def ask(tok="__good__", country="KR", uri="/hr", host="xmcda.store", extra=None):
    h = {"X-Original-URI": uri, "X-Original-Host": host}
    if country:
        h["CF-IPCountry"] = country
    if tok == "__good__":
        tok = token()
    if tok:
        h["Cf-Access-Jwt-Assertion"] = tok
    h.update(extra or {})
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = client.get("/auth", headers=h)
    return r, buf.getvalue()

# ---------- /auth: 통과 ----------
reset()
r, _ = ask()
check("정상 토큰 + 위험도 통과 -> 200", r.status_code == 200, r.status_code)
check("통과 응답에 검증된 신원(X-ZT-Identity)", r.headers.get("X-ZT-Identity") == "hana@test.com")
check("Lambda에 보내는 identity는 JWT의 email, 국가는 CF-IPCountry 헤더",
      calls[0]["identity"] == "hana@test.com" and calls[0]["geo_country"] == "KR" and calls[0]["source"] == "B", calls[0])

reset(); ask(uri="/api/db-data?type=admin_logs", host="admin.xmcda.store")
check("admin 서브도메인 + /api/db-data -> resource_path=/api/db-data (쿼리 제거)", calls[0]["resource_path"] == "/api/db-data", calls[0]["resource_path"])
reset(); ask(uri="/", host="admin.xmcda.store")
check("admin 서브도메인 / -> resource_path=/admin", calls[0]["resource_path"] == "/admin")
reset(); ask(uri="/hr/?x=1")
check("끝 슬래시와 쿼리는 판단 경로에서 제거 (/hr)", calls[0]["resource_path"] == "/hr", calls[0]["resource_path"])
reset(); ask(uri="/%68r")
check("퍼센트 인코딩 경로도 앱과 같은 경로(/hr)로 판단", calls[0]["resource_path"] == "/hr", calls[0]["resource_path"])

reset(); ask(); ask()
check("같은 사용자/경로 재요청은 캐시 사용 (Lambda 1회)", len(calls) == 1, len(calls))
reset(); ask(country="KR"); ask(country="US")
check("국가가 바뀌면 캐시 무시하고 즉시 재평가", len(calls) == 2, len(calls))

# ---------- /auth: JWT 실패 = 기록 + 차단, Lambda 호출 없음 ----------
cases = [
    ("JWT 없음", None, "token_missing"),
    ("깨진 토큰", "not.a.jwt", "malformed"),
    ("위조 서명", token(key=EVIL), "bad_signature"),
    ("만료 토큰", token(exp_delta=-10), "expired"),
    ("다른 앱 aud", token(aud=("aud-other",)), "bad_aud"),
    ("email 없는 토큰", token(drop=("email",)), "no_email_claim"),
]
for name, tok, reason in cases:
    reset()
    r, log = ask(tok=tok)
    check(f"{name} -> 403 + X-ZT-Action=jwt_invalid + 기록({reason}), Lambda 호출 없음",
          r.status_code == 403 and r.headers.get("X-ZT-Action") == "jwt_invalid"
          and f"reason={reason}" in log and len(calls) == 0, f"{r.status_code} {log!r}")

reset()
r, log = ask(tok=None, extra={"Cf-Access-Authenticated-User-Email": "admin@test.com"})
check("평문 이메일 헤더만 있는 위조 요청 -> 차단 (평문 헤더는 판단에 쓰지 않음)", r.status_code == 403 and len(calls) == 0)

reset()
r, _ = ask(tok="not.a.jwt", extra={"X-ZT-Action": "allow"})
check("클라이언트가 보낸 X-ZT-Action 헤더는 판단에 영향 없음", r.status_code == 403 and r.headers["X-ZT-Action"] == "jwt_invalid")

reset()
r, log = ask(tok=token(key=EVIL))
check("실패 기록에 토큰 원문이 없음", "eyJ" not in log, log)

# ---------- /auth: 위험도 차단 (200이 나오면 안 됨) ----------
reset(resp={"allow": False, "action": "step_up_mfa_required", "score": 60, "resource_threshold": 40, "resource_tier": "confidential"})
r, _ = ask()
check("step-up 필요 -> 403 + X-ZT-Action=step_up_mfa_required", r.status_code == 403 and r.headers["X-ZT-Action"] == "step_up_mfa_required")
reset(resp={"allow": False, "action": "block", "score": 100, "resource_threshold": 40, "resource_tier": "confidential"})
r, log = ask()
check("차단 -> 403 + X-ZT-Action=block, 차단 기록(점수는 기록하지 않음)", r.status_code == 403 and r.headers["X-ZT-Action"] == "block" and "ZT_DENY" in log and "100" not in log, log)
reset(err=True)
r, _ = ask()
check("Lambda 장애 -> 403 + pdp_unavailable (절대 통과하지 않음)", r.status_code == 403 and r.headers["X-ZT-Action"] == "pdp_unavailable")
reset(st=500)
r, _ = ask()
check("Lambda가 200이 아니면 차단", r.status_code == 403 and r.headers["X-ZT-Action"] == "pdp_unavailable")
reset(resp={"allow": "true", "action": "allow"})
r, _ = ask()
check("allow가 정확히 True가 아니면(문자열 등) 통과시키지 않음", r.status_code == 403)
reset(resp={"allow": False, "action": "block", "resource_tier": "confidential"})
ask(); ask()
check("차단 결과는 캐시하지 않음(재인증 후 바로 풀려야 함)", len(calls) == 2, len(calls))

# ---------- /deny: 차단 응답 만들기 ----------
def deny(action, uri="/hr?x=1", host="xmcda.store"):
    return client.get("/deny", headers={"X-ZT-Action": action, "X-Original-URI": uri, "X-Original-Host": host})

r = deny("step_up_mfa_required")
loc = r.headers.get("Location", "")
check("step-up(페이지) -> 302, 인증 페이지로 이동 + 원래 주소(쿼리 포함) 보존",
      r.status_code == 302 and loc.startswith("https://auth.xmcda.store/stepup?return_url=")
      and "return_url=https%3A%2F%2Fxmcda.store%2Fhr%3Fx%3D1" in loc, loc)
r = deny("step_up_mfa_required", uri="/api/db-data?type=admin_logs", host="admin.xmcda.store")
body = r.get_json()
check("step-up(API) -> 403 JSON StepUpRequired, 돌아올 곳은 관리자 페이지",
      r.status_code == 403 and body["status"] == "StepUpRequired"
      and "return_url=https%3A%2F%2Fadmin.xmcda.store%2F" in body["stepup_url"], body)
r = deny("pdp_unavailable")
check("판단 서버 장애(페이지) -> 503", r.status_code == 503)
r = deny("pdp_unavailable", uri="/api/db-data", host="admin.xmcda.store")
check("판단 서버 장애(API) -> 503 JSON", r.status_code == 503 and r.get_json()["status"] == "Error")
r = deny("jwt_invalid")
check("JWT 검증 실패(페이지) -> 403 '인증 정보를 확인할 수 없는 요청'", r.status_code == 403 and "인증 정보를 확인할 수 없는 요청" in r.get_data(as_text=True))
r = deny("jwt_invalid", uri="/api/db-data", host="admin.xmcda.store")
check("JWT 검증 실패(API) -> 403 JSON Denied", r.status_code == 403 and r.get_json()["status"] == "Denied")
r = deny("block")
text = r.get_data(as_text=True)
check("차단(페이지) -> 403, 점수/사유 노출 없음", r.status_code == 403 and "score" not in text and "confidential" not in text)
r = deny("block", uri="/api/db-data", host="admin.xmcda.store")
check("차단(API) -> 403 JSON Denied", r.status_code == 403 and r.get_json()["status"] == "Denied")
r = client.get("/deny", headers={"X-Original-URI": "/hr", "X-Original-Host": "xmcda.store"})
check("차단 이유 헤더가 없거나 모르는 값이어도 안전하게 403", r.status_code == 403)
r = deny("some-unknown-action")
check("모르는 action 값 -> 403 (통과로 해석되지 않음)", r.status_code == 403)

# ---------- 기타 ----------
r = client.get("/healthz")
check("/healthz -> 200", r.status_code == 200)

print()
print("실패 수:", fails)
sys.exit(1 if fails else 0)
