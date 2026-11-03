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
os.environ["ACCOUNT_DEPARTMENTS"] = "kim@test.com=dev;lee@test.com=hr;hana@test.com=admin;bad-item;=x"
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
pa.table.query.return_value = {"Items": []}
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
TEAM_TEXT = {"dev": "개발팀 전용", "marketing": "마케팅팀 전용", "hr": "인사팀 전용"}
for path, host in [("/", "xmcda.store"), ("/", "dev.xmcda.store"), ("/", "hr.xmcda.store"),
                   ("/", "marketing.xmcda.store"), ("/", "admin.xmcda.store")]:
    r = client.get(path, headers={**H, "Host": host})
    check(f"통과: {host}{path} -> 200, 외부 호출 없음", r.status_code == 200 and len(calls) == 0, f"status={r.status_code} calls={len(calls)}")
# [서브도메인 분리] 호스트가 곧 앱: 각 서브도메인의 첫 화면이 그 팀 페이지, 포털 홈에는 팀 페이지 내용 없음
for team, text in TEAM_TEXT.items():
    check(f"{team}.xmcda.store/ -> {team} 팀 페이지", text in client.get("/", headers={**H, "Host": f"{team}.xmcda.store"}).get_data(as_text=True))
check("포털 홈(xmcda.store/)에는 팀 페이지 내용 없음",
      not any(t in client.get("/", headers={**H, "Host": "xmcda.store"}).get_data(as_text=True) for t in TEAM_TEXT.values()))
# 모든 화면 no-store (로그아웃 후 뒤로 가기로 이전 화면이 보이지 않게)
for host in ("xmcda.store", "dev.xmcda.store", "admin.xmcda.store"):
    check(f"{host}/ 응답에 Cache-Control: no-store", client.get("/", headers={**H, "Host": host}).headers.get("Cache-Control") == "no-store")
# 포털 홈 "내 업무 앱": 내 소속 앱만 링크
def home(email):
    return client.get("/", headers={**hdr(email=email), "Host": "xmcda.store"}).get_data(as_text=True)
t = home("kim@test.com")
check("dev 소속: 개발팀 링크만", 'href="https://dev.xmcda.store/"' in t and "hr.xmcda.store" not in t and "admin.xmcda.store" not in t and "marketing.xmcda.store" not in t)
t = home("lee@test.com")
check("hr 소속: 인사팀 링크만", 'href="https://hr.xmcda.store/"' in t and "dev.xmcda.store" not in t and "admin.xmcda.store" not in t)
t = home("hana@test.com")
check("admin 소속: 관리자 콘솔 링크", 'href="https://admin.xmcda.store/"' in t and "dev.xmcda.store" not in t)
t = home("nobody@test.com")
check("소속 표에 없는 계정: 앱 링크 없음 + 안내", "사용할 수 있는 업무 앱이 없습니다" in t and ".xmcda.store/\"" not in t)
check("소속 표의 깨진 항목은 무시", set(pa.ACCOUNT_DEPARTMENTS) == {"kim@test.com", "lee@test.com", "hana@test.com"}, pa.ACCOUNT_DEPARTMENTS)
check("다른 도메인의 dev.* 호스트는 팀 페이지로 취급하지 않음",
      "개발팀 전용" not in client.get("/", headers={**H, "Host": "dev.evil.com"}).get_data(as_text=True))
# 옛 경로 주소(xmcda.store/dev)는 포털 앱(전 직원) 범위라 라우트를 지움 -> 404, 내용 노출 없음
for team, text in TEAM_TEXT.items():
    r = client.get(f"/{team}", headers={**H, "Host": "xmcda.store"})
    check(f"옛 주소 xmcda.store/{team} -> 404, 내용 노출 없음", r.status_code == 404 and text not in r.get_data(as_text=True), r.status_code)

reset()
r = client.get("/no-such-page", headers=H)
check("등록되지 않은 경로는 404", r.status_code == 404, f"status={r.status_code}")

# ---------- 2. 화면의 임계값은 판단 서비스가 넘겨준 헤더에서 읽는다 ----------
def page(path="/", host="hr.xmcda.store", **extra_headers):
    return client.get(path, headers={**H, "Host": host, **extra_headers}).get_data(as_text=True)

# 허용 위험점수는 관리자 콘솔에서만 보여 준다(직원 화면에 판단 기준/점수를 노출하지 않음 - 실제 제품도 보여 주지 않음)
ADMH = {"Host": "admin.xmcda.store"}
def admin_page(**extra):
    return client.get("/", headers={**hdr("hana@test.com"), **ADMH, **extra}).get_data(as_text=True)
check("관리자 콘솔: X-ZT-Threshold 20 -> '20점 이하' 표시, 옛 문구('신뢰 점수') 없음",
      "20점 이하" in admin_page(**{"X-ZT-Threshold": "20"}) and "신뢰 점수" not in admin_page(**{"X-ZT-Threshold": "20"}))
check("직원 화면(팀 앱/포털)에는 허용 위험점수를 표시하지 않음",
      "40점" not in page(**{"X-ZT-Threshold": "40"}) and "60점" not in page("/", "xmcda.store", **{"X-ZT-Threshold": "60"})
      and "위험점수" not in page(**{"X-ZT-Threshold": "40"}) and "위험점수" not in page("/", "xmcda.store", **{"X-ZT-Threshold": "60"}))
check("직원 화면에 판단 기준(위치·시간·기기·IP로 계산) 문구 없음",
      "IP 평판" not in page("/", "xmcda.store") and "접근 정책" not in page() and "다시 계산" not in page("/", "xmcda.store"))
check("관리자 콘솔: 헤더가 없으면 '확인 불가' 표시", "확인 불가" in admin_page())
t = admin_page(**{"X-ZT-Threshold": "40<script>alert(1)</script>"})
check("숫자가 아닌 헤더 값은 표시하지 않고(XSS 방지) '확인 불가'", "확인 불가" in t and "alert(1)" not in t)
check("음수/소수/공백이 섞인 값은 '확인 불가'", all("확인 불가" in admin_page(**{"X-ZT-Threshold": v}) for v in ("-5", "4.5", " 40", "")))
check("자리수가 비정상적으로 긴 값은 '확인 불가'", "확인 불가" in admin_page(**{"X-ZT-Threshold": "9" * 50}))
# 업무 앱 가상 데이터: 인사팀 검색(목록에서만 거름, 값은 이스케이프)
t = page("/?q=개발팀")
check("인사팀 명부 검색: 부서로 거름 + 연락처 가림", "김하나" in t and "최유나" not in t and "010-****-" in t and "시연용 가상 데이터" in t)
t = page("/?q=%22%3E%3Cscript%3Ealert(9)%3C/script%3E")
check("인사팀 검색어는 이스케이프(반사형 XSS 방지) + 결과 없음 안내", "<script>alert(9)" not in t and "&lt;script&gt;alert(9)" in t and "검색 결과가 없습니다" in t)
check("검색어 길이 제한(50자)", 'maxlength="50"' in page() )
t = home("kim@test.com")
check("포털 홈: 권한 없는 앱은 잠긴 타일(링크·주소 없음)", t.count('class="app-tile locked"') == 3 and t.count('class="app-tile"') == 1 and "권한 없음" in t)
check("모든 업무 화면에 자동 로그아웃 카운트다운", 'id="zt-left"' in t and "시간 연장" in t and 'id="zt-left"' in page())

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
pa.table.scan.reset_mock()
r0 = admin_get()
t0 = r0.get_data(as_text=True)
check("처음 접속: 로그는 안 보이고 버튼만 있음, 기록 저장소 조회 안 함", r0.status_code == 200 and "판정 로그 불러오기" in t0 and 'href="/?logs=1"' in t0
      and "<th>시각(KST)</th>" not in t0 and pa.table.scan.call_count == 0, pa.table.scan.call_count)
r = admin_get("/?logs=1")
t = r.get_data(as_text=True)
check("버튼(/?logs=1): 스크립트 없이도 서버가 그린 표가 보임(200), 옛 /api/db-data 호출 없음", r.status_code == 200 and "<th>시각(KST)</th>" in t and "/api/db-data" not in t)
check("버튼은 같은 주소의 /logs만 불러와 아래에 펼침(다른 주소/외부 호출 없음)", "fetch('/logs'" in t and t.count("fetch(") == 1)
rf = client.get("/logs", headers={**hdr("hana@test.com"), **ADM})
check("/logs: 관리자 -> 표 조각만(전체 페이지 아님), 저장 안 함", rf.status_code == 200 and "<th>시각(KST)</th>" in rf.get_data(as_text=True)
      and "<!DOCTYPE" not in rf.get_data(as_text=True) and rf.headers.get("Cache-Control") == "no-store")
check("/logs: 관리자가 아니면 403", client.get("/logs", headers={**hdr("kim@test.com"), **ADM}).status_code == 403)
check("/logs: 관리자 콘솔 주소가 아니면 404", client.get("/logs", headers={**hdr("hana@test.com"), "Host": "dev.xmcda.store"}).status_code == 404)
check("로그 50건만 표시, 가장 최근(timestamp 120)이 먼저", t.count("<tr><td>") == 50 and t.index("1970-01-01 09:02:00") < t.index("1970-01-01 09:01:59"), t.count("<tr><td>"))

pa.table.scan.return_value = {"Items": [{"timestamp": 5, "identity": "<img src=x onerror=alert(1)>", "resource_path": "/x<script>alert(2)</script>?a=\"'",
                                        "risk_score": 1, "reasons": ["<b>r</b>"], "action": "deny", "source": "B"}]}
t = admin_get("/?logs=1").get_data(as_text=True)
check("저장된 값(identity/resource_path/reasons)의 HTML이 이스케이프됨(XSS 방지)",
      "<script>alert(2)" not in t and "<img src=x" not in t and "<b>r</b>" not in t and "&lt;script&gt;alert(2)" in t, t[-600:])

pa.table.scan.side_effect = RuntimeError("db secret detail")
t = admin_get("/?logs=1").get_data(as_text=True)
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
r = client.get("/", headers={"CF-IPCountry": "KR", "Host": "dev.xmcda.store"})
check("인증 헤더 없음 -> 403", r.status_code == 403, f"status={r.status_code}")
r = client.get("/", headers={"CF-IPCountry": "KR", "Host": "admin.xmcda.store"})
check("인증 헤더 없음(관리자 콘솔) -> 403", r.status_code == 403, r.status_code)
invoked.clear()
r = client.post("/risk/release", data={}, headers={"CF-IPCountry": "KR", "Host": "admin.xmcda.store", "Origin": "https://admin.xmcda.store"})
check("인증 헤더 없음(해제 요청) -> 403, 해제 호출 없음", r.status_code == 403 and len(invoked) == 0, r.status_code)

# ---------- 4. Cloudflare JWT 서명 검증 (검증 실패 = 기록 + 즉시 차단) ----------
import io, contextlib

def blocked_with_log(headers, path="/", host="dev.xmcda.store"):
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

r, log, n = blocked_with_log({**hdr(), "Cf-Access-Authenticated-User-Email": "admin@test.com"}, host="hr.xmcda.store")
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
r, log, n = blocked_with_log(hdr(aud=("aud-admin",)))
check("정상 토큰(두 번째 허용 aud) -> 통과, 로그에 실패 기록 없음", r.status_code == 200 and "JWT_VERIFY_FAILED" not in log, f"{r.status_code} {log!r}")

r, log, n = blocked_with_log(hdr(aud=("aud-other", "aud-portal")))
check("aud 목록 중 하나라도 허용 목록에 있으면 통과", r.status_code == 200, r.status_code)

r = client.get("/", headers={**hdr(email="kim@test.com"), "Host": "hr.xmcda.store"})
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
DH = lambda **kw: {**hdr(**kw), "Host": "dev.xmcda.store"}
client.get("/", headers=DH()); client.get("/", headers=DH()); client.get("/", headers=DH())
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
    client.get("/", headers=DH(kid="kid-unknown"))
check("모르는 kid가 반복돼도 공개키 재요청 폭주 없음(1분 최소 간격)", len(jwks_fetches) == 0, len(jwks_fetches))

# 키 교체: 캐시에 없는 새 kid가 나타나면(1분 이상 지났을 때) 다시 받아서 통과
NEW_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
def rotated_fetch():
    return {"kid-good": GOOD_KEY.public_key(), "kid-new": NEW_KEY.public_key()}
zj._fetch_jwks = rotated_fetch
zj._jwks.update({"keys": {"kid-good": GOOD_KEY.public_key()}, "fetched_at": _time.time() - 120})
reset()
r = client.get("/", headers={**hdr(key=NEW_KEY, kid="kid-new"), "Host": "dev.xmcda.store"})
check("Cloudflare 키 교체: 새 kid가 나오면 공개키를 다시 받아 통과", r.status_code == 200, r.status_code)
zj._fetch_jwks = orig_fetch

# ---------- 4b. 내 보안 기록(포털 /security) + 홈 한 줄 요약 ----------
def sec_page(email="kim@test.com", host="xmcda.store", path="/security"):
    return client.get(path, headers={**hdr(email=email), "Host": host})

NOW = int(_time.time())
ITEMS = [
    {"timestamp": NOW - 10, "action": "step_up_mfa_verified", "resource_path": "dev.xmcda.store", "country": "JP", "source": "A"},
    {"timestamp": NOW - 60, "action": "allow", "resource_path": "xmcda.store", "country": "KR", "source": "B"},          # 재확인 통과, 로그인(NOW-100)과 같은 나라: 숨김
    {"timestamp": NOW - 70, "action": "step_up_mfa_report_only", "resource_path": "dev.xmcda.store", "country": "KR"},     # 모르는 동작: 숨김
    {"timestamp": NOW - 100, "action": "allow", "resource_path": "xmcda.store", "country": "KR", "source": "A"},
    {"timestamp": NOW - 200, "action": "allow", "resource_path": "xmcda.store", "country": "KR", "source": "A"},           # 10분 안 반복: 한 줄로
    {"timestamp": NOW - 3000, "action": "block", "resource_path": "hr.xmcda.store", "country": "<b>X</b>", "source": "B"},  # 차단은 B여도 보임
    {"timestamp": NOW - 4000, "action": "allow", "resource_path": "auth.xmcda.store/authorize", "source": "login"},
    {"timestamp": NOW - 5000, "action": "device_session_revoked", "resource_path": "all-apps", "source": "sweep"},
    {"timestamp": NOW - 6000, "action": "risk_release", "resource_path": "user_risk", "source": "ADMIN"},
]
pa.table.query.reset_mock(); pa.table.scan.reset_mock(); pa.table.query.side_effect = None
pa.table.query.return_value = {"Items": ITEMS}
r = sec_page()
t = r.get_data(as_text=True)
qk = pa.table.query.call_args.kwargs if pa.table.query.call_args else {}
check("내 보안 기록: 200, 사람별 색인을 최신순 Query(전체 Scan 아님)",
      r.status_code == 200 and qk.get("IndexName") == "identity-timestamp-index" and qk.get("ScanIndexForward") is False
      and pa.table.scan.call_count == 0, (r.status_code, qk))
check("조회 키는 로그인한 본인 이메일(요청 값으로 바꿀 수 없음)",
      qk.get("KeyConditionExpression") == "#id = :me" and qk.get("ExpressionAttributeNames") == {"#id": "identity"}
      and qk.get("ExpressionAttributeValues") == {":me": "kim@test.com"}, qk)
sec_page(path="/security?identity=lee@test.com&user=lee@test.com")
check("주소에 다른 사람 이메일을 넣어도 본인 기록만 조회",
      pa.table.query.call_args.kwargs.get("ExpressionAttributeValues") == {":me": "kim@test.com"})
check("내 보안 기록: 접속 정보 + 최근 활동 + 안내 문장", all(x in t for x in ("내 접속 정보", "최근 보안 활동", "본인 아님", "kim@test.com")))
check("서비스/나라/결과가 사람이 읽는 말로", all(x in t for x in ("개발팀", "일본", "추가 인증 완료", "사내 포털", "대한민국", "정상 접속", "인사팀", "접속 차단", "보안 관리자 확인 완료")))
check("점수/신호/임계값 코드가 없음", not any(x in t for x in ("risk_score", "reasons", "임계", "step_up_mfa_verified", "night_access", "점수")))
check("이상한 나라 값은 이스케이프", "<b>X</b>" not in t and "&lt;b&gt;X&lt;/b&gt;" in t)
for h in ("dev.xmcda.store", "admin.xmcda.store"):
    check(f"/security는 포털에서만({h} -> 404)", sec_page(host=h).status_code == 404)
rows = pa._my_activity("kim@test.com")
check("_my_activity: 재확인 통과(같은 나라)/모르는 동작/10분 안 반복 제외, 나머지는 최신순",
      [(r["app"], r["action"]) for r in rows] == [("개발팀", "step_up_mfa_verified"), ("사내 포털", "allow"), ("인사팀", "block"),
                                                ("로그인", "allow"), ("전체 서비스", "device_session_revoked"), ("전체 서비스", "risk_release")], rows)
check("_my_activity(limit=2): 줄 수 제한", len(pa._my_activity("kim@test.com", limit=2)) == 2)
# 재확인(B) '정상'이라도 로그인 때와 나라가 다르면 보여야 함(세션 탈취 의심)
pa.table.query.return_value = {"Items": [
    {"timestamp": NOW - 10, "action": "allow", "resource_path": "dev.xmcda.store", "country": "CN", "source": "B"},
    {"timestamp": NOW - 20, "action": "allow", "resource_path": "dev.xmcda.store", "country": "KR", "source": "B"},
    {"timestamp": NOW - 900, "action": "allow", "resource_path": "dev.xmcda.store", "country": "KR", "source": "A"},
    {"timestamp": NOW - 950, "action": "allow", "resource_path": "hr.xmcda.store", "country": "JP", "source": "B"},
]}
rows2 = pa._my_activity("kim@test.com")
check("재확인 '정상': 로그인 때와 나라가 같으면 숨김, 다르면(CN) 표시, 로그인 기록을 못 찾으면 표시",
      [(r["app"], r["country"]) for r in rows2] == [("개발팀", "CN"), ("개발팀", "KR"), ("인사팀", "JP")], rows2)

# 홈: 평소엔 맨 아래 한 줄, 확인할 기록이 있을 때만 맨 위 주황 안내. 홈에는 표/접속 정보 칸이 없다.
t = home("kim@test.com")   # 위 rows2: 중국 접속(다른 나라) -> 안내
check("홈: 다른 나라 접속이 있으면 오른쪽 보안 카드가 주황(확인 필요) + 확인하기 링크(업무 앱 칸 아래, 공지 옆)",
      "확인이 필요한 보안 활동 2건" in t and 'sec-card wn' in t and 'href="/security"' in t and "확인하기" in t
      and t.index('class="app-grid"') < t.index("sec-card wn"), t[t.find("sec-card"):][:300])
check("홈: 보안 표/접속 정보 칸은 홈에 없음(별도 페이지)", "<table" not in t and "내 접속 정보" not in t)
pa.table.query.return_value = {"Items": [
    {"timestamp": NOW - 10, "action": "allow", "resource_path": "xmcda.store", "country": "KR", "source": "A"},
    {"timestamp": NOW - 9 * 86400, "action": "block", "resource_path": "hr.xmcda.store", "country": "KR", "source": "A"},  # 7일 지난 차단: 안내 안 함
    {"timestamp": NOW - 20, "action": "step_up_mfa_required", "resource_path": "dev.xmcda.store", "country": "KR", "source": "A"},  # 추가 인증 요청: 일상적
]}
t = home("kim@test.com")
check("홈: 평소엔 맨 아래 '보안 상태 정상' + 최근 접속 + 내 보안 기록 링크(7일 지난 차단/추가 인증 요청은 안내 안 함)",
      "보안 상태 정상" in t and "최근 접속" in t and "내 보안 기록" in t and "확인이 필요한" not in t
      and "sec-card ok" in t and t.index("전사 공지") < t.index("보안 상태 정상"))
pa.table.query.return_value = {"Items": [{"timestamp": NOW - 10, "action": "session_reauth_required", "resource_path": "xmcda.store", "country": "KR", "source": "B"}]}
check("홈: 다시 로그인 요청(세션 나라 변경 등)도 안내", "확인이 필요한 보안 활동 1건" in home("kim@test.com"))
pa.table.query.side_effect = RuntimeError("db secret detail")
t, t2 = home("kim@test.com"), sec_page().get_data(as_text=True)
check("조회 실패: 홈/페이지 모두 안내 문구만, 내부 오류 노출 없음", "불러올 수 없습니다" in t and "불러올 수 없습니다" in t2
      and "db secret detail" not in t + t2 and 'class="app-grid"' in t)
pa.table.query.side_effect = None
pa.table.query.return_value = {"Items": []}
check("기록 없음: 홈은 정상 표시, 페이지는 빈 안내", "보안 상태 정상" in home("kim@test.com")
      and "아직 기록된 보안 활동이 없습니다" in sec_page().get_data(as_text=True))
eng = open("risk_score_engine.py", encoding="utf-8").read()
check("엔진: 판정 기록에 나라(country) 저장 + identity는 항상 문자열(색인 키)",
      "item['country'] = log_country" in eng and "'identity': str(body.get('identity') or 'unknown')" in eng)
tf = open("main.tf", encoding="utf-8").read()
check("main.tf: 색인은 INCLUDE로 점수/신호를 복사하지 않음",
      'name               = "identity-timestamp-index"' in tf and 'projection_type    = "INCLUDE"' in tf
      and 'non_key_attributes = ["action", "resource_path", "country", "source"]' in tf)
ra = open("risk_admin.tf", encoding="utf-8").read()
check("risk_admin.tf: 앱 역할은 색인 Query만(테이블 Query 아님)",
      '"${aws_dynamodb_table.risk_score_log.arn}/index/identity-timestamp-index"' in ra and "QueryMyActivityIndex" in ra)

# ---------- 4c. 내 급여명세서 + IDOR(주인 확인) ----------
def pay(path, email="employee01@xmcda.store", host="xmcda.store"):
    return client.get(path, headers={**hdr(email=email), "Host": host})

r = pay("/payslip")
t = r.get_data(as_text=True)
check("명세서 목록: 본인 것 3개만(다른 사람 번호 없음)", r.status_code == 200 and all(f'/payslip/{i}"' in t for i in (108, 109, 110))
      and "/payslip/2" not in t, t[-1500:])
r = pay("/payslip/110")
t = r.get_data(as_text=True)
check("본인 명세서: 200, 실수령액 표시, 거부 표시 헤더 없음", r.status_code == 200 and "실수령액" in t and "김하나" in t
      and "X-ZT-Authz" not in r.headers)
r = pay("/payslip/210")
t = r.get_data(as_text=True)
check("남의 명세서(employee02의 210): 404 + 내용 없음 + X-ZT-Authz: owner_mismatch(nginx가 기록하고 지움)",
      r.status_code == 404 and r.headers.get("X-ZT-Authz") == "owner_mismatch" and "이도윤" not in t and "실수령액" not in t, (r.status_code, dict(r.headers)))
r2 = pay("/payslip/999")
check("없는 명세서: 같은 404 화면(존재 여부를 알려 주지 않음), 거부 표시 헤더 없음",
      r2.status_code == 404 and "X-ZT-Authz" not in r2.headers and r2.get_data(as_text=True) == t)
check("엔진을 끈 것과 무관하게 앱이 직접 막음(포털은 엔진을 부르지 않음)", "check_risk" not in open("portal_app.py", encoding="utf-8").read())
r = pay("/payslip/110", email="EMPLOYEE01@xmcda.store")
check("이메일 대소문자가 달라도 본인으로 인정", r.status_code == 200)
r = pay("/payslip/110", email="hana@test.com")
check("관리자라도 남의 명세서는 거부", r.status_code == 404 and r.headers.get("X-ZT-Authz") == "owner_mismatch")
for h in ("dev.xmcda.store", "admin.xmcda.store"):
    check(f"명세서는 포털에서만({h} -> 404, 거부 표시 없음)", pay("/payslip/110", host=h).status_code == 404
          and "X-ZT-Authz" not in pay("/payslip/110", host=h).headers)
check("포털 홈에 '내 급여명세서' 바로가기", 'href="/payslip"' in home("kim@test.com"))

# ---------- 4d. 확인이 필요한 활동: 본인 맞음 / 본인 아님(서버 저장) ----------
import io as _io2, contextlib as _cl2
NOW2 = int(_time.time())
CN_ROW = {"timestamp": NOW2 - 30, "action": "allow", "resource_path": "xmcda.store", "country": "CN", "source": "B"}
KR_ROW = {"timestamp": NOW2 - 9000, "action": "allow", "resource_path": "xmcda.store", "country": "KR", "source": "A"}
pa.table.query.side_effect = None
pa.table.query.return_value = {"Items": [CN_ROW, KR_ROW]}
pa.ack_table = MagicMock()
pa.ack_table.query.return_value = {"Items": []}
t = home("kim@test.com")
check("확인 전: 홈에 주황 카드(확인이 필요한 보안 활동 1건)", "확인이 필요한 보안 활동 1건" in t and "sec-card wn" in t)
t = sec_page().get_data(as_text=True)
check("내 보안 기록: 확인이 필요한 줄에만 [본인 맞음][본인 아님] 버튼(평범한 한국 접속 줄에는 없음)",
      t.count('action="/security/ack"') == 1 and f'name="ts" value="{NOW2 - 30}"' in t and "본인 맞음" in t, t.count('action="/security/ack"'))

def ack_post(form, email="kim@test.com", origin="https://xmcda.store", with_origin=True):
    h = {**hdr(email=email), "Host": "xmcda.store"}
    if with_origin:
        h["Origin"] = origin
    return client.post("/security/ack", data=form, headers=h)

tokk = pa._csrf_token("kim@test.com")
pa.ack_table.put_item.reset_mock()
r = ack_post({"csrf": tokk, "ts": str(NOW2 - 30), "verdict": "mine"})
it = pa.ack_table.put_item.call_args.kwargs["Item"] if pa.ack_table.put_item.called else {}
check("본인 맞음: 서버에 저장(본인 이메일, 활동 시각, mine, 8일 뒤 자동 삭제) 후 /security로", r.status_code == 303
      and "msg=ack_mine" in r.headers["Location"] and it.get("identity") == "kim@test.com" and it.get("ts") == NOW2 - 30
      and it.get("verdict") == "mine" and it.get("expires_at") == NOW2 - 30 + 8 * 86400, (r.status_code, it))
pa.ack_table.query.return_value = {"Items": [{"identity": "kim@test.com", "ts": NOW2 - 30, "verdict": "mine"}]}
t = home("kim@test.com")
check("확인 후: 홈 경고가 사라지고 초록 '보안 상태 정상'(서버 기록 기준이라 어느 기기에서든 같음)",
      "확인이 필요한" not in t and "sec-card ok" in t)
t = sec_page().get_data(as_text=True)
check("확인 후: 그 줄에는 버튼 대신 '본인 확인' 표시", 'action="/security/ack"' not in t and "본인 확인" in t)

pa.ack_table.query.return_value = {"Items": []}
pa.ack_table.put_item.reset_mock()
buf = _io2.StringIO()
with _cl2.redirect_stdout(buf):
    r = ack_post({"csrf": tokk, "ts": str(NOW2 - 30), "verdict": "not_mine"})
ev = [l for l in buf.getvalue().splitlines() if l.startswith("ZT_EVENT ")]
check("본인 아님: 저장 + 관제에 user_reported_not_me(관리자 Discord 알림 대상)",
      r.status_code == 303 and "msg=ack_report" in r.headers["Location"] and pa.ack_table.put_item.called
      and ev and '"event": "user_reported_not_me"' in ev[-1] and '"country": "CN"' in ev[-1], buf.getvalue())
for name, form, kw in [
    ("CSRF 토큰 없음", {"ts": str(NOW2 - 30), "verdict": "mine"}, {}),
    ("다른 사람 토큰", {"csrf": pa._csrf_token("lee@test.com"), "ts": str(NOW2 - 30), "verdict": "mine"}, {}),
    ("다른 사이트에서 보낸 요청(Origin)", {"csrf": tokk, "ts": str(NOW2 - 30), "verdict": "mine"}, {"origin": "https://evil.com"}),
    ("확인 대상이 아닌 평범한 접속", {"csrf": tokk, "ts": str(NOW2 - 9000), "verdict": "mine"}, {}),
    ("내 기록에 없는 시각", {"csrf": tokk, "ts": "123", "verdict": "mine"}, {}),
    ("이상한 선택 값", {"csrf": tokk, "ts": str(NOW2 - 30), "verdict": "delete"}, {}),
]:
    pa.ack_table.put_item.reset_mock()
    r = ack_post(form, **kw)
    check(f"거부: {name} -> 저장 안 함", r.status_code == 303 and "msg=ack_invalid" in r.headers["Location"]
          and not pa.ack_table.put_item.called, (r.status_code, r.headers.get("Location")))
pa.ack_table.query.side_effect = RuntimeError("ddb")
check("확인 기록 조회 실패: 경고를 계속 보여 줌(안전한 쪽), 홈은 정상", "확인이 필요한 보안 활동" in home("kim@test.com"))
pa.ack_table.query.side_effect = None
r = client.post("/security/ack", data={"csrf": tokk, "ts": str(NOW2 - 30), "verdict": "mine"},
                headers={**hdr(email="kim@test.com"), "Host": "dev.xmcda.store", "Origin": "https://dev.xmcda.store"})
check("확인은 포털에서만(dev 호스트 -> 404)", r.status_code == 404)
pa.table.query.return_value = {"Items": []}

# ---------- 5. 디버그 라우트는 기본으로 꺼져 있음 ----------
reset()
r = client.get("/debug-headers", headers=H)
check("ZT_DEBUG_HEADERS 미설정이면 /debug-headers 없음(404)", r.status_code == 404, f"status={r.status_code}")

print()
print("실패 수:", fails)
sys.exit(1 if fails else 0)
