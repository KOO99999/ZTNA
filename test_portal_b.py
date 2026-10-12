"""
portal_app.py(앱)의 신원 확인(Cloudflare Access JWT 서명 검증)과 화면을 실제 AWS/네트워크 없이 검증.
위험도 판단(Lambda 호출/캐시/차단 응답)은 nginx 앞단의 판단 서비스(auth_gate.py, test_auth_gate.py가 검증)로
옮겨졌으므로, 이 앱은 Lambda를 부르지 않는다. requests.post를 가짜로 바꿔 두고 "호출이 한 번도 없음"도 확인한다.
"""
import os
import sys
import json
import time as _time
import jwt as pyjwt
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from unittest.mock import MagicMock

os.environ["AUTH_DOMAIN"] = "auth.xmcda.store"
os.environ["CF_TEAM_DOMAIN"] = "team-test.cloudflareaccess.com"
os.environ["CF_ACCESS_AUDS"] = "aud-portal,aud-admin"
# 앱 서버에는 Lambda 주소/비밀키를 배포하지 않으므로, 일부러 환경변수를 세팅하지 않는다.
os.environ["ADMIN_EMAILS"] = "hana@test.com,root@test.com"
os.environ["RISK_ADMIN_FUNCTION"] = "risk_admin"
os.environ["CSRF_SECRET"] = "test-csrf-secret"
os.environ.pop("PDP_EVALUATE_URL", None)
os.environ.pop("EVALUATE_SHARED_SECRET", None)
sys.modules['boto3'] = MagicMock()
sys.path.insert(0, '.')
import portal_app as pa
import zt_jwt as zj

fails = 0

def check(name, cond, detail=""):
    global fails
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f"\n    -> {detail}" if detail else ""))
    if not cond:
        fails += 1

# ---- 네트워크 호출 감시: 앱이 어디로든 requests.post를 부르면 기록된다 ----
calls = []

def fake_post(url, headers=None, json=None, timeout=None):
    calls.append({"url": url, "headers": headers, "json": json})
    raise RuntimeError("앱은 외부 호출을 하면 안 됨")

def reset():
    calls.clear()

requests.post = fake_post
client = pa.app.test_client()

import io as _io
from urllib.parse import urlencode

ADM = {"Host": "admin.xmcda.store"}
pa.table = MagicMock()
pa.table.scan.return_value = {"Items": []}
invoked = []
risk_state = {"list": {"ok": True, "items": [], "truncated": False}, "release": {"ok": True, "audit": True}}

def fake_invoke(FunctionName=None, InvocationType=None, Payload=None):
    ev = json.loads(Payload)
    invoked.append((FunctionName, ev))
    body = risk_state.get(ev["action"])
    if isinstance(body, Exception):
        raise body
    return {"Payload": _io.BytesIO(json.dumps(body).encode())}

pa.lambda_client = MagicMock()
pa.lambda_client.invoke.side_effect = fake_invoke


# ---- Cloudflare JWT 가짜 발급 환경: 테스트용 RSA 키 2개(정상 키 / 위조자 키) ----
GOOD_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EVIL_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ISS = "https://team-test.cloudflareaccess.com"
jwks_fetches = []

def fake_fetch_jwks():
    jwks_fetches.append(1)
    return {"kid-good": GOOD_KEY.public_key()}

zj._fetch_jwks = fake_fetch_jwks

def make_token(email="hana@test.com", key=None, kid="kid-good", alg="RS256", iss=ISS,
               aud=("aud-portal",), exp_delta=300, drop=(), extra=None):
    now = int(_time.time())
    claims = {"email": email, "iss": iss, "aud": list(aud), "iat": now, "exp": now + exp_delta}
    if extra:
        claims.update(extra)
    for d in drop:
        claims.pop(d, None)
    return pyjwt.encode(claims, key or GOOD_KEY, algorithm=alg, headers={"kid": kid})

def hdr(email="hana@test.com", country="KR", **kw):
    return {"Cf-Access-Jwt-Assertion": make_token(email, **kw), "CF-IPCountry": country}

H = hdr()

# ---------- 1. 앱은 위험도 판단을 하지 않는다 (앞단 판단 서비스로 이관됨) ----------
src = open("portal_app.py", encoding="utf-8").read()
check("portal_app.py가 zt_risk를 import하지 않음", "zt_risk" not in src and "zt_risk" not in sys.modules)
check("portal_app.py 코드에 Lambda 비밀키/주소 참조가 없음", "EVALUATE_SHARED_SECRET" not in src and "PDP_EVALUATE_URL" not in src)
check("portal_app.py에 check_risk 호출이 남아 있지 않음", "check_risk" not in src)

reset()
for path, host in [("/", "xmcda.store"), ("/dev", "xmcda.store"), ("/hr", "xmcda.store"),
                   ("/marketing", "xmcda.store"), ("/", "admin.xmcda.store")]:
    r = client.get(path, headers={**H, "Host": host})
    check(f"통과: {host}{path} -> 200, 외부 호출 없음", r.status_code == 200 and len(calls) == 0, f"status={r.status_code} calls={len(calls)}")

reset()
r = client.get("/no-such-page", headers=H)
check("등록되지 않은 경로는 404", r.status_code == 404, f"status={r.status_code}")

# ---------- 2. 화면의 임계값은 판단 서비스가 넘겨준 헤더에서 읽는다 ----------
def page(path="/hr", host="xmcda.store", **extra_headers):
    return client.get(path, headers={**H, "Host": host, **extra_headers}).get_data(as_text=True)

check("X-ZT-Threshold: 40 -> '40점' 표시", "40점" in page(**{"X-ZT-Threshold": "40"}))
check("X-ZT-Threshold: 20 (관리자 콘솔) -> '20점' 표시, 옛 문구('신뢰 점수') 없음",
      "20점" in page("/", "admin.xmcda.store", **{"X-ZT-Threshold": "20"}) and "신뢰 점수" not in page("/", "admin.xmcda.store", **{"X-ZT-Threshold": "20"}))
check("X-ZT-Threshold: 60 -> '60점' 표시", "60점" in page("/", **{"X-ZT-Threshold": "60"}))
check("헤더가 없으면 '확인 불가' 표시", "확인 불가" in page())
t = page(**{"X-ZT-Threshold": "40<script>alert(1)</script>"})
check("숫자가 아닌 헤더 값은 표시하지 않고(XSS 방지) '확인 불가'", "확인 불가" in t and "alert(1)" not in t)
check("음수/소수/공백이 섞인 값은 '확인 불가'", all("확인 불가" in page(**{"X-ZT-Threshold": v}) for v in ("-5", "4.5", " 40", "")))
check("자리수가 비정상적으로 긴 값은 '확인 불가'", "확인 불가" in page(**{"X-ZT-Threshold": "9" * 50}))

# ---------- 3. 관리자 콘솔 (서버가 직접 그림) / 해제 ----------
def admin_get(path="/", email="hana@test.com"):
    return client.get(path, headers={**hdr(email), **ADM})

def tok(email="hana@test.com"):
    return pa._csrf_token(email)

def admin_post(form, email="hana@test.com", origin="https://admin.xmcda.store", with_origin=True):
    h = {**hdr(email), **ADM}
    if with_origin:
        h["Origin"] = origin
    return client.post("/risk/release", data=form, headers=h)

r = client.get("/api/db-data?type=admin_logs", headers={**hdr(), **ADM})
check("옛 /api/db-data 라우트는 없어짐(404)", r.status_code == 404, r.status_code)

# 로그: 최근 순 정렬 + 50건 제한 + 이스케이프
pa.table.scan.return_value = {"Items": [{"session_id": f"s{i}", "timestamp": i, "identity": "kim@test.com", "resource_path": "/hr",
                                        "risk_score": 10, "resource_threshold": 40, "action": "allow", "source": "A", "reasons": ["night_access"]} for i in range(1, 121)]}
r = admin_get()
t = r.get_data(as_text=True)
check("관리자: 콘솔이 서버에서 그려져 200, fetch 스크립트 없음", r.status_code == 200 and "fetch(" not in t and "/api/db-data" not in t)
check("로그 50건만 표시, 가장 최근(timestamp 120)이 먼저", t.count("<tr><td>") == 50 and t.index("1970-01-01 09:02:00") < t.index("1970-01-01 09:01:59"), t.count("<tr><td>"))

pa.table.scan.return_value = {"Items": [{"timestamp": 5, "identity": "<img src=x onerror=alert(1)>", "resource_path": "/x<script>alert(2)</script>?a=\"'",
                                        "risk_score": 1, "reasons": ["<b>r</b>"], "action": "deny", "source": "B"}]}
t = admin_get().get_data(as_text=True)
check("저장된 값(identity/resource_path/reasons)의 HTML이 이스케이프됨(XSS 방지)",
      "<script>alert(2)" not in t and "<img src=x" not in t and "<b>r</b>" not in t and "&lt;script&gt;alert(2)" in t, t[-600:])

pa.table.scan.side_effect = RuntimeError("db secret detail")
t = admin_get().get_data(as_text=True)
check("로그 조회 실패 시 내부 오류 문구 노출 없이 안내만", "불러오지 못했습니다" in t and "db secret detail" not in t)
pa.table.scan.side_effect = None
pa.table.scan.return_value = {"Items": []}

# 위험 상태 목록
risk_state["list"] = {"ok": True, "items": [{"identity": "kim@test.com", "signal": "waf_sqli", "set_at": 100, "last_seen": 200, "source": "B"},
                                             {"identity": "<x>@t.com", "signal": "threat_intel_match", "set_at": 50, "last_seen": 60, "source": "A"}], "truncated": False}
invoked.clear()
t = admin_get().get_data(as_text=True)
check("위험 상태 목록을 risk_admin(list, actor=JWT 이메일)으로 조회", invoked and invoked[0] == ("risk_admin", {"action": "list", "actor": "hana@test.com"}), invoked)
check("목록에 사용자/신호와 해제 폼, CSRF 토큰이 있음", "kim@test.com" in t and "waf_sqli" in t and 'action="/risk/release"' in t and 'name="csrf"' in t)
check("목록 값도 이스케이프됨", "<x>@t.com" not in t and "&lt;x&gt;@t.com" in t)
risk_state["list"] = {"ok": True, "items": [], "truncated": False}
check("목록이 비면 안내 문구", "위험 상태가 걸린 사용자는 없습니다" in admin_get().get_data(as_text=True))
risk_state["list"] = RuntimeError("lambda down")
t = admin_get().get_data(as_text=True)
check("risk_admin 호출 실패 시에도 페이지는 뜨고 오류 안내(내부 문구 없음)", "위험 상태 목록을 불러오지 못했습니다" in t and "lambda down" not in t)
risk_state["list"] = {"ok": False, "error": "forbidden"}
check("risk_admin이 거부해도 오류 안내", "위험 상태 목록을 불러오지 못했습니다" in admin_get().get_data(as_text=True))
risk_state["list"] = {"ok": True, "items": [], "truncated": False}

# 권한: 관리자가 아니면
invoked.clear()
r = admin_get(email="kim@test.com")
check("관리자가 아닌 계정은 콘솔 403, risk_admin 호출 없음", r.status_code == 403 and len(invoked) == 0, r.status_code)
r = admin_post({"csrf": tok("kim@test.com"), "identity": "x@test.com", "signal": "waf_sqli"}, email="kim@test.com")
check("관리자가 아닌 계정의 해제 요청 403, 호출 없음", r.status_code == 403 and len(invoked) == 0, r.status_code)
r = client.post("/risk/release", data={}, headers={**hdr(), "Host": "xmcda.store", "Origin": "https://xmcda.store"})
check("포털 도메인(admin 아님)의 /risk/release는 404", r.status_code == 404)
r = client.get("/risk/release", headers={**hdr(), **ADM})
check("GET으로는 해제 불가(405)", r.status_code == 405)

# 해제: 정상 / CSRF / Origin
form = {"csrf": tok(), "identity": "kim@test.com", "signal": "waf_sqli"}
invoked.clear()
r = admin_post(form)
check("정상 해제: risk_admin(release) 호출 후 /?msg=released 로 303", r.status_code == 303 and r.headers["Location"].endswith("/?msg=released")
      and invoked == [("risk_admin", {"action": "release", "actor": "hana@test.com", "identity": "kim@test.com", "signal": "waf_sqli"})], (r.status_code, r.headers.get("Location"), invoked))
check("결과 메시지가 화면에 표시됨", "해제했습니다" in admin_get("/?msg=released").get_data(as_text=True))
_t = admin_get("/?msg=%3Cscript%3E").get_data(as_text=True)
check("알 수 없는 msg 코드는 무시(반사 방지)", 'class="msg msg-' not in _t and "%3Cscript" not in _t and "<script>alert" not in _t)

for label, f, kw in [
    ("CSRF 토큰 없음", {"identity": "kim@test.com", "signal": "waf_sqli"}, {}),
    ("CSRF 토큰 위조", {**form, "csrf": "123.abc"}, {}),
    ("다른 사용자 이름으로 만든 토큰", {**form, "csrf": tok("root@test.com")}, {}),
    ("Origin이 다른 사이트", form, {"origin": "https://evil.example"}),
    ("Origin/Referer 없음", form, {"with_origin": False}),
]:
    invoked.clear()
    r = admin_post(f, **kw)
    check(f"해제 거부: {label}", r.status_code == 303 and r.headers["Location"].endswith("msg=csrf") and len(invoked) == 0, (r.status_code, r.headers.get("Location")))

old = pa._csrf_token("hana@test.com", ts=int(_time.time()) - pa.CSRF_TTL_SECONDS - 5)
invoked.clear()
r = admin_post({**form, "csrf": old})
check("해제 거부: 만료된 CSRF 토큰", r.headers["Location"].endswith("msg=csrf") and len(invoked) == 0)

# Referer만 있어도 같은 사이트면 허용
h = {**hdr(), **ADM, "Referer": "https://admin.xmcda.store/"}
invoked.clear()
r = client.post("/risk/release", data=form, headers=h)
check("Origin이 없고 Referer가 같은 사이트면 허용", r.headers["Location"].endswith("msg=released") and len(invoked) == 1)

# Lambda 결과 → 메시지 코드
for res, code in [({"ok": False, "error": "self_release"}, "self_release"), ({"ok": False, "error": "not_active"}, "not_active"),
                  ({"ok": False, "error": "weird<script>"}, "failed"), ({"ok": True, "audit": False}, "released_noaudit"),
                  (RuntimeError("down"), "failed")]:
    risk_state["release"] = res
    r = admin_post(form)
    check(f"해제 결과 {res if not isinstance(res, Exception) else 'Lambda 호출 실패'} -> msg={code}", r.headers["Location"].endswith("msg=" + code), r.headers.get("Location"))
risk_state["release"] = {"ok": True, "audit": True}

# 보안 헤더
r = admin_get()
check("보안 헤더(nosniff, DENY, frame-ancestors, no-store)", r.headers.get("X-Content-Type-Options") == "nosniff" and r.headers.get("X-Frame-Options") == "DENY"
      and "frame-ancestors 'none'" in r.headers.get("Content-Security-Policy", "") and r.headers.get("Cache-Control") == "no-store", dict(r.headers))
check("ADMIN_EMAILS가 비어 있으면 모두 관리자 아님", not pa._is_admin("") and not pa._is_admin(None) and pa._is_admin("HANA@test.com"))

reset()
r = client.get("/dev", headers={"CF-IPCountry": "KR"})
check("인증 헤더 없음 -> 403", r.status_code == 403, f"status={r.status_code}")
r = client.get("/", headers={"CF-IPCountry": "KR", "Host": "admin.xmcda.store"})
check("인증 헤더 없음(관리자 콘솔) -> 403", r.status_code == 403, r.status_code)
invoked.clear()
r = client.post("/risk/release", data={}, headers={"CF-IPCountry": "KR", "Host": "admin.xmcda.store", "Origin": "https://admin.xmcda.store"})
check("인증 헤더 없음(해제 요청) -> 403, 해제 호출 없음", r.status_code == 403 and len(invoked) == 0, r.status_code)

# ---------- 4. Cloudflare JWT 서명 검증 (검증 실패 = 기록 + 즉시 차단) ----------
import io, contextlib

def blocked_with_log(headers, path="/dev", host="xmcda.store"):
    """요청을 보내고 (상태코드, 응답, 출력된 로그, Lambda 호출 수)를 돌려준다."""
    reset()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = client.get(path, headers={**headers, "Host": host})
    return r, buf.getvalue(), len(calls)

r, log, n = blocked_with_log({"CF-IPCountry": "KR"})
check("JWT 없음 -> 403, Lambda 호출 없음, 실패 기록(token_missing)",
      r.status_code == 403 and n == 0 and "[JWT_VERIFY_FAILED] reason=token_missing" in log, f"{r.status_code} {log!r}")

r, log, n = blocked_with_log({"Cf-Access-Authenticated-User-Email": "hana@test.com", "CF-IPCountry": "KR"})
check("평문 이메일 헤더만 있고 JWT 없음(위조 시나리오) -> 차단", r.status_code == 403 and n == 0 and "token_missing" in log)

r, log, n = blocked_with_log({**hdr(), "Cf-Access-Authenticated-User-Email": "admin@test.com"}, path="/hr")
_txt = r.get_data(as_text=True)
check("JWT는 hana인데 평문 헤더만 admin으로 바꿔도 신원은 hana(JWT)로 표시됨",
      r.status_code == 200 and "hana@test.com" in _txt and "admin@test.com" not in _txt, f"status={r.status_code}")

r, log, n = blocked_with_log({"Cf-Access-Jwt-Assertion": "not.a.jwt", "CF-IPCountry": "KR"})
check("형식이 깨진 토큰 -> 차단 + 기록(malformed)", r.status_code == 403 and n == 0 and "reason=malformed" in log, log)

r, log, n = blocked_with_log(hdr(key=EVIL_KEY))
check("위조 서명(다른 개인키로 서명, kid만 정상) -> 차단 + 기록(bad_signature)",
      r.status_code == 403 and n == 0 and "reason=bad_signature" in log, log)

r, log, n = blocked_with_log(hdr(kid="kid-unknown"))
check("모르는 kid -> 차단 + 기록(unknown_kid)", r.status_code == 403 and n == 0 and "reason=unknown_kid" in log, log)

r, log, n = blocked_with_log(hdr(exp_delta=-10))
check("만료된 토큰 -> 차단 + 기록(expired)", r.status_code == 403 and n == 0 and "reason=expired" in log, log)

r, log, n = blocked_with_log(hdr(aud=("aud-other",)))
check("다른 앱의 aud -> 차단 + 기록(bad_aud)", r.status_code == 403 and n == 0 and "reason=bad_aud" in log, log)

r, log, n = blocked_with_log(hdr(iss="https://evil.cloudflareaccess.com"))
check("다른 발급자(iss) -> 차단 + 기록(bad_iss)", r.status_code == 403 and n == 0 and "reason=bad_iss" in log, log)

r, log, n = blocked_with_log(hdr(drop=("exp",)))
check("exp 없는 토큰 -> 차단(영구 토큰 방지)", r.status_code == 403 and n == 0 and "reason=missing_claim" in log, log)

r, log, n = blocked_with_log(hdr(drop=("email",)))
check("email 클레임 없는 토큰(서비스 토큰 등) -> 차단 + 기록(no_email_claim)",
      r.status_code == 403 and n == 0 and "reason=no_email_claim" in log, log)

none_token = pyjwt.encode({"email": "hana@test.com", "iss": ISS, "aud": ["aud-portal"], "iat": int(_time.time()), "exp": int(_time.time()) + 300},
                          key=None, algorithm="none", headers={"kid": "kid-good"})
r, log, n = blocked_with_log({"Cf-Access-Jwt-Assertion": none_token, "CF-IPCountry": "KR"})
check("alg=none 토큰 -> 차단", r.status_code == 403 and n == 0 and "reason=bad_alg_or_kid" in log, log)

import hmac as _hmac, hashlib as _hashlib, base64 as _b64
def b64(b): return _b64.urlsafe_b64encode(b).rstrip(b"=")
pub_pem = GOOD_KEY.public_key().public_bytes(
    __import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).Encoding.PEM,
    __import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).PublicFormat.SubjectPublicKeyInfo)
hs_head = b64(json.dumps({"alg": "HS256", "kid": "kid-good", "typ": "JWT"}).encode())
hs_body = b64(json.dumps({"email": "hana@test.com", "iss": ISS, "aud": ["aud-portal"], "iat": int(_time.time()), "exp": int(_time.time()) + 300}).encode())
hs_sig = b64(_hmac.new(pub_pem, hs_head + b"." + hs_body, _hashlib.sha256).digest())
r, log, n = blocked_with_log({"Cf-Access-Jwt-Assertion": (hs_head + b"." + hs_body + b"." + hs_sig).decode(), "CF-IPCountry": "KR"})
check("HS256 혼동 공격(공개키를 HMAC 비밀로 사용) -> 차단", r.status_code == 403 and n == 0 and "reason=bad_alg_or_kid" in log, log)

invoked.clear()
r, log, n = blocked_with_log({**hdr(key=EVIL_KEY)}, path="/", host="admin.xmcda.store")
check("JWT 검증 실패(관리자 콘솔) -> 403, 호출 없음", r.status_code == 403 and n == 0 and len(invoked) == 0)

r, log, n = blocked_with_log(hdr(key=EVIL_KEY))
check("검증 실패 로그에 토큰 원문이 없음", make_token()[:20] not in log and "eyJ" not in log, log)

# 정상 토큰
r, log, n = blocked_with_log(hdr(aud=("aud-admin",)), path="/dev")
check("정상 토큰(두 번째 허용 aud) -> 통과, 로그에 실패 기록 없음", r.status_code == 200 and "JWT_VERIFY_FAILED" not in log, f"{r.status_code} {log!r}")

r, log, n = blocked_with_log(hdr(aud=("aud-other", "aud-portal")))
check("aud 목록 중 하나라도 허용 목록에 있으면 통과", r.status_code == 200, r.status_code)

r = client.get("/hr", headers=hdr(email="kim@test.com"))
check("화면에 표시되는 계정도 JWT의 email", "kim@test.com" in r.get_data(as_text=True))

# 설정 누락 -> fail-closed
saved = (zj.CF_ISSUER, zj.CF_ACCESS_AUDS)
zj.CF_ISSUER, zj.CF_ACCESS_AUDS = None, []
r, log, n = blocked_with_log(hdr())
check("팀 도메인/AUD 설정이 없으면 모두 차단(fail-closed) + 기록(config_missing)",
      r.status_code == 403 and n == 0 and "reason=config_missing" in log, log)
zj.CF_ISSUER, zj.CF_ACCESS_AUDS = saved

# 공개키 가져오기: 캐시 / 실패 / 키 교체
zj._jwks.update({"keys": {}, "fetched_at": 0.0})
jwks_fetches.clear()
client.get("/dev", headers=hdr()); client.get("/dev", headers=hdr()); client.get("/dev", headers=hdr())
check("공개키 목록은 캐시되어 요청마다 받지 않음(1회)", len(jwks_fetches) == 1, len(jwks_fetches))

def failing_fetch():
    raise RuntimeError("cloudflare unreachable")
orig_fetch = zj._fetch_jwks
zj._jwks.update({"keys": {}, "fetched_at": 0.0})
zj._fetch_jwks = failing_fetch
r, log, n = blocked_with_log(hdr())
check("공개키를 못 받고 아는 키도 없으면 차단 + 기록(jwks_unavailable)",
      r.status_code == 403 and n == 0 and "reason=jwks_unavailable" in log, log)
zj._fetch_jwks = orig_fetch

zj._jwks.update({"keys": {"kid-good": GOOD_KEY.public_key()}, "fetched_at": _time.time() - zj.JWKS_CACHE_SECONDS - 5})
zj._fetch_jwks = failing_fetch
r, log, n = blocked_with_log(hdr())
check("캐시가 오래됐고 새로 못 받아도, 이미 아는 키로는 계속 검증(Cloudflare 일시 장애 대응)", r.status_code == 200, f"{r.status_code} {log!r}")
zj._fetch_jwks = orig_fetch

zj._jwks.update({"keys": {"kid-good": GOOD_KEY.public_key()}, "fetched_at": _time.time()})
jwks_fetches.clear()
for _ in range(5):
    client.get("/dev", headers=hdr(kid="kid-unknown"))
check("모르는 kid가 반복돼도 공개키 재요청 폭주 없음(1분 최소 간격)", len(jwks_fetches) == 0, len(jwks_fetches))

# 키 교체: 캐시에 없는 새 kid가 나타나면(1분 이상 지났을 때) 다시 받아서 통과
NEW_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
def rotated_fetch():
    return {"kid-good": GOOD_KEY.public_key(), "kid-new": NEW_KEY.public_key()}
zj._fetch_jwks = rotated_fetch
zj._jwks.update({"keys": {"kid-good": GOOD_KEY.public_key()}, "fetched_at": _time.time() - 120})
reset()
r = client.get("/dev", headers=hdr(key=NEW_KEY, kid="kid-new"))
check("Cloudflare 키 교체: 새 kid가 나오면 공개키를 다시 받아 통과", r.status_code == 200, r.status_code)
zj._fetch_jwks = orig_fetch

# ---------- 5. 디버그 라우트는 기본으로 꺼져 있음 ----------
reset()
r = client.get("/debug-headers", headers=H)
check("ZT_DEBUG_HEADERS 미설정이면 /debug-headers 없음(404)", r.status_code == 404, f"status={r.status_code}")

print()
print("실패 수:", fails)
sys.exit(1 if fails else 0)
