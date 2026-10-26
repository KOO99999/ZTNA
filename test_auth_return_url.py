"""auth_app.py의 복귀 주소 해석(_safe_return_url/_original_url_candidate/_resolve_return_url)과
소속(department) 기반 "접근 권한 없음" 안내(check_department_access/render_no_permission) 테스트.

1부(함수 단위)는 해당 함수 소스만 추출해 실행하므로 추가 패키지 없이 돌아간다.
2부(/stepup, /token 화면 흐름)는 auth_app 전체를 import해야 해서 flask-sqlalchemy, pymysql, pyotp가 필요하다
(없으면 건너뛴다고 표시하고 1부만 실행). 전체를 보려면: pip install flask-sqlalchemy pymysql pyotp
"""
import ast, os, sys
from html import escape
from urllib.parse import urlparse
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "auth_app.py"), encoding="utf-8").read()
tree = ast.parse(src)
want = ["_app_hosts", "_safe_return_url", "_original_url_candidate", "_resolve_return_url",
        "_parse_path_permissions", "_parse_account_departments", "_resource_key", "check_department_access", "render_no_permission"]
funcs = {n.name: ast.get_source_segment(src, n) for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in want}
assert sorted(funcs) == sorted(want), f"함수를 찾지 못함: {set(want) - set(funcs)}"

os.environ["DOMAIN_NAME"] = "auth.xmcda.store"
req = SimpleNamespace(args={}, referrer=None)
import re
ns = {"os": os, "urlparse": urlparse, "request": req, "escape": escape, "re": re}
exec("\n\n".join(funcs[n] for n in want), ns)
ns["PATH_PERMISSIONS"] = ns["_parse_path_permissions"]("dev.xmcda.store=dev;marketing.xmcda.store=marketing;hr.xmcda.store=hr;admin.xmcda.store=admin")
resolve = ns["_resolve_return_url"]

def run(args=None, referrer=None):
    req.args = args or {}
    req.referrer = referrer
    return resolve()

fails = 0
def check(name, got, exp):
    global fails
    ok = got == exp
    fails += (not ok)
    print(("[PASS] " if ok else "[FAIL] ") + name + ("" if ok else f"  got={got!r} exp={exp!r}"))

def ok(name, cond, detail=""):
    """조건식 하나로 판정하는 검사(실패 시 detail 출력)."""
    check(name + ("" if cond else f"  detail={detail!r}"), bool(cond), True)

pad = ns["_parse_account_departments"]
check("소속 목록 파싱", pad("A@x.com=dev;b@x.com=hr"), {"a@x.com": "dev", "b@x.com": "hr"})
check("소속 목록 비어 있음/None", (pad(""), pad(None)), ({}, {}))
check("소속 목록 이상한 항목 건너뜀", pad("noequals;=dev;c@x.com=;d@x.com=admin"), {"d@x.com": "admin"})
check("소속 목록 공백 제거", pad(" e@x.com = dev ; "), {"e@x.com": "dev"})

H = "https://xmcda.store"
DEV = "https://dev.xmcda.store"
HR = "https://hr.xmcda.store"
# [서브도메인 분리] 앱 호스트 목록: 환경변수 APP_HOSTS(Terraform locals.app_hosts), 없으면 기본 구성
os.environ.pop("APP_HOSTS", None)
check("APP_HOSTS 없으면 기본 5개 호스트", ns["_app_hosts"](),
      ["xmcda.store", "dev.xmcda.store", "marketing.xmcda.store", "hr.xmcda.store", "admin.xmcda.store"])
os.environ["APP_HOSTS"] = "xmcda.store, DEV.xmcda.store,bad host,<x>,hr.xmcda.store"
check("APP_HOSTS: 소문자/공백 정리, 호스트에 못 쓰는 문자가 든 항목은 버림", ns["_app_hosts"](), ["xmcda.store", "dev.xmcda.store", "hr.xmcda.store"])
os.environ["APP_HOSTS"] = "xmcda.store,dev.xmcda.store,marketing.xmcda.store,hr.xmcda.store,admin.xmcda.store"

check("original_url dev 서브도메인(새 주소)", run({"original_url": "dev.xmcda.store/"}), DEV + "/")
check("original_url hr 하위 경로", run({"original_url": "hr.xmcda.store/a"}), HR + "/a")
check("original_url admin", run({"original_url": "admin.xmcda.store/"}), "https://admin.xmcda.store/")
check("original_url 쿼리 포함", run({"original_url": "dev.xmcda.store/?a=1&b=2"}), DEV + "/?a=1&b=2")
check("original_url https:// 이미 있음", run({"original_url": "https://dev.xmcda.store/"}), DEV + "/")
check("original_url 포털 홈", run({"original_url": "xmcda.store/"}), H + "/")
check("없으면 홈", run({}), H)
check("목록에 없는 서브도메인 거부(auth 등)", run({"original_url": "auth.xmcda.store/x"}), H)
check("외부 도메인 거부", run({"original_url": "evil.com/login"}), H)
check("비슷한 도메인 거부", run({"original_url": "dev.xmcda.store.evil.com/"}), H)
check("앞부분만 같은 도메인 거부", run({"original_url": "evilxmcda.store/dev"}), H)
check("@ 우회 거부", run({"original_url": "dev.xmcda.store@evil.com/x"}), H)
check("// 시작 거부", run({"original_url": "//evil.com/x"}), H)
check("http 거부", run({"original_url": "http://dev.xmcda.store/"}), H)
check("javascript: 거부", run({"original_url": "javascript:alert(1)"}), H)
check("따옴표 포함 거부(XSS)", run({"original_url": 'dev.xmcda.store/"onload="x'}), H)
check("역슬래시 거부", run({"original_url": "dev.xmcda.store\\@evil.com"}), H)
check("공백/개행 거부", run({"original_url": "dev.xmcda.store/\r\nX: y"}), H)
check("포트 거부", run({"original_url": "dev.xmcda.store:8443/"}), H)
check("return_url이 original_url보다 우선", run({"return_url": "https://marketing.xmcda.store/", "original_url": "dev.xmcda.store/"}), "https://marketing.xmcda.store/")
check("잘못된 return_url이면 original_url 사용", run({"return_url": "https://evil.com", "original_url": "dev.xmcda.store/"}), DEV + "/")
check("original_url 없으면 Referer의 호스트 사용", run({}, "https://hr.xmcda.store/page"), HR)
check("original_url이 이상하면 Referer로", run({"original_url": "evil.com"}, "https://admin.xmcda.store/x"), "https://admin.xmcda.store")
check("Referer가 비슷한 다른 도메인이면 무시(부분 문자열 비교 아님)", run({}, "https://dev.xmcda.store.evil.com/"), H)
check("Referer에 우리 주소가 경로로만 들어 있으면 무시", run({}, "https://evil.com/dev.xmcda.store"), H)

# ---------- 소속 기반 권한 안내 (함수 단위) ----------
parse = ns["_parse_path_permissions"]
check("권한표 파싱", parse("dev.xmcda.store=dev;hr.xmcda.store=hr,legal;admin.xmcda.store=admin"),
      {"dev.xmcda.store": ["dev"], "hr.xmcda.store": ["hr", "legal"], "admin.xmcda.store": ["admin"]})
check("권한표가 비어 있으면 빈 표", parse(""), {})
check("권한표가 None이어도 빈 표", parse(None), {})
check("형식이 깨진 조각은 무시", parse("garbage;dev.xmcda.store=dev;=x;hr.xmcda.store"), {"dev.xmcda.store": ["dev"]})
check("공백은 정리", parse(" dev.xmcda.store = dev , qa ; admin.xmcda.store=admin "), {"dev.xmcda.store": ["dev", "qa"], "admin.xmcda.store": ["admin"]})

rk = ns["_resource_key"]
check("자원 키 = 호스트: dev 서브도메인", rk(DEV + "/"), "dev.xmcda.store")
check("자원 키: 하위 경로/쿼리와 무관하게 호스트", rk(DEV + "/a/b?x=1"), "dev.xmcda.store")
check("자원 키: 포털 홈", rk(H), "xmcda.store")
check("자원 키: 대문자 호스트는 소문자로", rk("https://ADMIN.xmcda.store/anything"), "admin.xmcda.store")

acc = ns["check_department_access"]
check("dev 소속이 dev 서브도메인 -> 허용", acc("dev", DEV + "/"), True)
check("admin 소속이 dev 서브도메인 -> 거부", acc("admin", DEV + "/"), False)
check("marketing 소속이 hr 서브도메인 -> 거부", acc("marketing", HR + "/"), False)
check("소속이 비어 있으면(None) 보호 자원은 거부", acc(None, HR + "/"), False)
check("소속이 빈 문자열이어도 거부", acc("", HR + "/"), False)
check("admin 소속이 admin 서브도메인 -> 허용", acc("admin", "https://admin.xmcda.store/"), True)
check("dev 소속이 admin 서브도메인 -> 거부", acc("dev", "https://admin.xmcda.store/"), False)
check("권한표에 없는 자원(포털 홈)은 판단 불가(None) -> 기존 흐름 유지", acc("dev", H), None)
check("옛 경로 주소(xmcda.store/dev)는 포털 호스트라 판단 불가(None)", acc("admin", H + "/dev"), None)
check("대소문자가 다르면 같은 소속이 아님(정확히 일치만)", acc("DEV", DEV + "/"), False)
ns["PATH_PERMISSIONS"] = {}
check("권한표가 비어 있으면 판단 불가(None) -> 기존 흐름 유지", acc("dev", DEV + "/"), None)
ns["PATH_PERMISSIONS"] = parse("dev.xmcda.store=dev;marketing.xmcda.store=marketing;hr.xmcda.store=hr;admin.xmcda.store=admin")

html = ns["render_no_permission"]("kim@xmcda.store", "marketing", HR + "/")
check("권한 없음 화면: 계정/소속/필요 소속/홈/로그아웃 링크 포함",
      all(x in html for x in ("kim@xmcda.store", ">marketing<", ">hr<", 'href="https://xmcda.store/"', 'href="/logout"')), True)
check("권한 없음 화면에 TOTP 입력 폼이 없음", ("totp" not in html.lower()) and ("<form" not in html), True)
evil = ns["render_no_permission"]("<script>alert(1)</script>@x.com", '"><img src=x onerror=alert(2)>', HR + "/")
check("권한 없음 화면은 계정/소속 값을 HTML 이스케이프(XSS 방지)", ("<script>alert(1)" not in evil) and ("<img src=x" not in evil), True)
nodept = ns["render_no_permission"]("kim@xmcda.store", None, HR + "/")
check("소속이 없으면 '(지정되지 않음)' 표시", "(지정되지 않음)" in nodept, True)

# ==========================================================================
# 2부: /stepup, /token 화면 흐름 (auth_app 전체 import 필요)
# ==========================================================================
try:
    import flask_sqlalchemy, pymysql, pyotp   # noqa: F401
    HAVE_FULL = True
except ImportError:
    HAVE_FULL = False

if not HAVE_FULL:
    print("[SKIP] 2부(/stepup, /token 흐름) 건너뜀 - pip install flask-sqlalchemy pymysql pyotp 후 다시 실행하면 검사됩니다")
else:
    from unittest.mock import patch, MagicMock
    import jwt as pyjwt
    os.environ.update(DB_HOST="h", DB_NAME="n", DB_USER="u", DB_PASSWORD="p", OIDC_CLIENT_ID="cid",
                      OIDC_CLIENT_SECRET="sec", PDP_EVALUATE_URL="https://pdp.test/evaluate",
                      EVALUATE_SHARED_SECRET="test-secret-local-only",
                      PATH_PERMISSIONS="dev.xmcda.store=dev;marketing.xmcda.store=marketing;hr.xmcda.store=hr;admin.xmcda.store=admin",
                      AUTO_MIGRATE_SCHEMA="0")   # 자동 마이그레이션은 실제 DB가 필요해서 끔(별도 검증)
    flask_sqlalchemy.SQLAlchemy.create_all = lambda self, *a, **k: None   # 테스트에서는 실제 DB에 연결하지 않음
    sys.path.insert(0, HERE)
    import auth_app as aa

    ACCOUNTS = {}
    def acct(email, dept, role="employee"):
        a = SimpleNamespace(email=email, department=dept, role=role, totp_secret=pyotp.random_base32(), id=len(ACCOUNTS) + 1)
        ACCOUNTS[email] = a
        return a
    acct("dev1@xmcda.store", "dev"); acct("mkt1@xmcda.store", "marketing"); acct("admin1@xmcda.store", "admin", "admin")
    acct("nodept@xmcda.store", None)

    class FakeQuery:
        def filter_by(self, **kw):
            em = kw.get("email")
            return SimpleNamespace(first=lambda: ACCOUNTS.get(em))
    totp_checks = []
    risk_calls = []
    def login_cookie(email):
        return aa.create_sso_session(email)

    c = aa.app.test_client()
    import time as _time
    DECISION = {"value": {"found": False}}   # 엔진의 마지막 판단(기본: 기록 없음 -> 기존처럼 재인증 화면)
    with aa.app.app_context(), \
         patch.object(aa.Account, "query", FakeQuery(), create=True), \
         patch.object(aa, "check_brute_force", lambda e: False), \
         patch.object(aa, "evaluate_login_risk", lambda i, s: risk_calls.append((i, s)) or {"recorded": True}), \
         patch.object(aa, "lookup_access_decision", lambda e, u: DECISION["value"]):

        def stepup_get(email, original="dev.xmcda.store/", extra=None):
            c.set_cookie(aa.SSO_COOKIE_NAME, login_cookie(email), domain="localhost")
            q = {"original_url": original}
            q.update(extra or {})
            return c.get("/stepup", query_string=q)

        r = stepup_get("dev1@xmcda.store")
        t = r.get_data(as_text=True)
        check("dev 소속이 /dev의 step-up -> TOTP 입력 화면(200)", (r.status_code, "totp_code" in t, "접근 권한이 없습니다" in t), (200, True, False))
        r = stepup_get("admin1@xmcda.store")
        t = r.get_data(as_text=True)
        check("admin 계정이 /dev로 막힘 -> TOTP를 묻지 않고 '권한 없음'(403)", (r.status_code, "totp_code" in t, "접근 권한이 없습니다" in t), (403, False, True))
        ok("권한 없음 화면에 계정의 소속(admin)과 필요한 소속(dev)이 보임", ">admin<" in t and ">dev<" in t)
        r = stepup_get("mkt1@xmcda.store", original="hr.xmcda.store/")
        check("marketing 계정이 /hr -> '권한 없음'(403)", (r.status_code, "접근 권한이 없습니다" in r.get_data(as_text=True)), (403, True))
        r = stepup_get("dev1@xmcda.store", original="admin.xmcda.store/")
        check("dev 계정이 admin 콘솔 -> '권한 없음'(403)", (r.status_code, "접근 권한이 없습니다" in r.get_data(as_text=True)), (403, True))
        r = stepup_get("admin1@xmcda.store", original="admin.xmcda.store/")
        check("admin 계정이 admin 콘솔 step-up -> TOTP 화면(200)", (r.status_code, "totp_code" in r.get_data(as_text=True)), (200, True))
        r = stepup_get("nodept@xmcda.store")
        check("소속이 지정되지 않은 계정이 보호 자원 -> '권한 없음'(403)", (r.status_code, "(지정되지 않음)" in r.get_data(as_text=True)), (403, True))
        r = stepup_get("admin1@xmcda.store", original="xmcda.store/")
        check("권한표에 없는 자원(홈)은 기존대로 TOTP 화면", (r.status_code, "totp_code" in r.get_data(as_text=True)), (200, True))
        r = stepup_get("admin1@xmcda.store", original=None, extra={"return_url": "https://dev.xmcda.store/"})
        ok("게이트가 보낸 ?return_url= 로 와도 같은 권한 확인", r.status_code == 403, r.status_code)

        # POST 직접 호출 우회: 소속이 맞지 않으면 TOTP 검증도, Lambda 기록도 하지 않는다
        risk_calls.clear()
        c.set_cookie(aa.SSO_COOKIE_NAME, login_cookie("admin1@xmcda.store"), domain="localhost")
        good_code = pyotp.TOTP(ACCOUNTS["admin1@xmcda.store"].totp_secret).now()
        r = c.post("/stepup", data={"return_url": "https://dev.xmcda.store/", "totp_code": good_code})
        ok("올바른 TOTP를 직접 POST해도 소속이 다르면 403, MFA 기록 없음",
              r.status_code == 403 and "접근 권한이 없습니다" in r.get_data(as_text=True) and not risk_calls, (r.status_code, risk_calls))
        c.set_cookie(aa.SSO_COOKIE_NAME, login_cookie("dev1@xmcda.store"), domain="localhost")
        good_code = pyotp.TOTP(ACCOUNTS["dev1@xmcda.store"].totp_secret).now()
        r = c.post("/stepup", data={"return_url": "https://dev.xmcda.store/", "totp_code": good_code})
        ok("소속이 맞는 사용자의 올바른 TOTP -> 인증 완료 + MFA 기록 + 원래 페이지(dev 서브도메인)로 이동",
              r.status_code == 200 and "인증되었습니다" in r.get_data(as_text=True) and 'https://dev.xmcda.store/' in r.get_data(as_text=True)
              and risk_calls and risk_calls[0][1] == {"mfa_reauth": True}, (r.status_code, risk_calls))

        # [차단 화면] 엔진의 마지막 판단이 차단이면 TOTP를 묻지 않고 차단 화면(재인증 반복 방지)
        DECISION["value"] = {"found": True, "action": "block_device", "device_reasons": ["device_unmanaged"]}
        r = stepup_get("dev1@xmcda.store"); t = r.get_data(as_text=True)
        ok("기기 때문에 차단(block_device) -> 403 차단 화면, TOTP 입력 없음, 기기 사유와 푸는 방법",
           r.status_code == 403 and "totp_code" not in t and "회사에 등록된 기기가 아닙니다" in t and "WARP" in t, (r.status_code, t[:300]))
        ok("차단 화면의 '다시 시도'는 원래 앱 주소", 'href="https://dev.xmcda.store/"' in t, t[-600:])
        DECISION["value"] = {"found": True, "action": "block_device", "device_reasons": ["device_posture_failed"]}
        t = stepup_get("admin1@xmcda.store", original="admin.xmcda.store/").get_data(as_text=True)
        ok("방화벽 검사 실패 -> '방화벽을 켜고 몇 분 뒤' 안내", "Windows 방화벽을 켜고 몇 분 뒤" in t)
        DECISION["value"] = {"found": True, "action": "block", "device_reasons": []}
        r = stepup_get("dev1@xmcda.store"); t = r.get_data(as_text=True)
        ok("기기 외 이유로 차단(block) -> 일반 차단 화면(사유/점수 비공개), TOTP 없음",
           r.status_code == 403 and "totp_code" not in t and "보안 정책에 따라 접근이 차단" in t and "+45" not in t, (r.status_code, t[:200]))
        DECISION["value"] = {"found": True, "action": "block_until_mfa", "device_reasons": []}
        r = stepup_get("dev1@xmcda.store")
        ok("보안 신호로 차단(block_until_mfa, 관리자 해제 대상) -> 차단 화면, TOTP 없음",
           r.status_code == 403 and "totp_code" not in r.get_data(as_text=True))
        DECISION["value"] = {"found": True, "action": "block", "device_reasons": ["<script>", "device_owner_mismatch"]}
        t = stepup_get("dev1@xmcda.store").get_data(as_text=True)
        ok("모르는 사유 이름은 표시하지 않음, 아는 기기 사유만", "<script>" not in t and "다른 사람 계정으로 등록된 기기" in t)
        DECISION["value"] = {"found": True, "action": "step_up_mfa_required", "device_reasons": []}
        ok("재인증 필요(step_up_mfa_required) -> TOTP 화면", "totp_code" in stepup_get("dev1@xmcda.store").get_data(as_text=True))
        DECISION["value"] = {"found": True, "action": "block_device", "device_reasons": ["device_unmanaged"]}
        ok("소속이 다르면 차단 판단보다 '권한 없음'이 먼저", "접근 권한이 없습니다" in stepup_get("admin1@xmcda.store").get_data(as_text=True))
        risk_calls.clear()
        c.set_cookie(aa.SSO_COOKIE_NAME, login_cookie("dev1@xmcda.store"), domain="localhost")
        good_code = pyotp.TOTP(ACCOUNTS["dev1@xmcda.store"].totp_secret).now()
        r = c.post("/stepup", data={"return_url": "https://dev.xmcda.store/", "totp_code": good_code})
        ok("차단 상태에서 올바른 TOTP를 직접 POST해도 403, MFA 기록 없음",
           r.status_code == 403 and not risk_calls, (r.status_code, risk_calls))
        DECISION["value"] = {"found": False}

        # 로그인 안 한 상태
        c.delete_cookie(aa.SSO_COOKIE_NAME, domain="localhost")
        r = c.get("/stepup", query_string={"original_url": "dev.xmcda.store/"})
        ok("로그인(SSO) 없으면 권한 판단 전에 로그인 안내", "로그인이 필요합니다" in r.get_data(as_text=True), r.status_code)

        # 토큰의 department 클레임
        for email, dept in [("dev1@xmcda.store", "dev"), ("nodept@xmcda.store", "")]:
            code = "code-" + email
            aa.AUTH_CODES[code] = {"email": email, "expires_at": _time.time() + 60}
            r = c.post("/token", data={"code": code, "grant_type": "authorization_code", "client_id": "cid", "client_secret": "sec"})
            claims = pyjwt.decode(r.get_json()["id_token"], options={"verify_signature": False})
            check(f"id_token에 department 클레임({dept!r})", (r.status_code, claims.get("department"), claims.get("email")), (200, dept, email))
        aa.ACCESS_TOKENS["tok"] = {"email": "dev1@xmcda.store", "expires_at": _time.time() + 60}
        r = c.get("/userinfo", headers={"Authorization": "Bearer tok"})
        check("/userinfo에도 department 포함", r.get_json().get("department"), "dev")

if HAVE_FULL:
    # lookup_access_decision 자체: 엔진에 보내는 내용과 실패 처리
    sent = []
    class _R:
        def __init__(self, v): self.v = v
        def json(self): return self.v
    def fake_post(url, **kw):
        sent.append((url, kw))
        return _R({"found": True, "action": "block", "device_reasons": []})
    with patch.object(aa.requests, "post", fake_post):
        res = aa.lookup_access_decision("dev1@xmcda.store", "https://dev.xmcda.store/a?b=1")
    body = sent[0][1]["json"] if sent else {}
    ok("판단 조회: 같은 PDP 주소 + 공유 비밀키 + decision_lookup/신원/앱 호스트만 보냄",
       sent and sent[0][0] == "https://pdp.test/evaluate" and sent[0][1]["headers"]["X-Evaluate-Secret"] == "test-secret-local-only"
       and body == {"decision_lookup": True, "identity": "dev1@xmcda.store", "resource_host": "dev.xmcda.store"}
       and res["action"] == "block", (sent, res))
    def boom(url, **kw): raise OSError("down")
    with patch.object(aa.requests, "post", boom):
        ok("판단 조회 실패 -> found=False(기존처럼 재인증 화면)", aa.lookup_access_decision("a@b", "https://dev.xmcda.store/") == {"found": False})
    with patch.object(aa.requests, "post", lambda url, **kw: _R(["not", "dict"])):
        ok("판단 조회 응답이 이상하면 found=False", aa.lookup_access_decision("a@b", "https://dev.xmcda.store/") == {"found": False})
    sent.clear()
    with patch.object(aa.requests, "post", fake_post), aa.app.test_request_context("/authorize", headers={"CF-Connecting-IP": "45.155.205.9"}):
        aa.evaluate_login_risk("dev1@xmcda.store", {})
    ok("[위협IP] 로그인 평가에 접속 IP(CF-Connecting-IP)를 같이 보냄",
       sent and sent[0][1]["json"].get("client_ip") == "45.155.205.9" and sent[0][1]["json"].get("source") == "login", sent)
    sent.clear()
    with patch.object(aa.requests, "post", fake_post):
        aa.evaluate_login_risk("dev1@xmcda.store", {"mfa_reauth": True})
    ok("[위협IP] 요청 밖에서 불려도 오류 없이 client_ip=None", sent and sent[0][1]["json"].get("client_ip") is None, sent)
    t = aa.render_blocked('x"<b>@xmcda.store', "https://dev.xmcda.store/", ["device_unmanaged"])
    ok("차단 화면은 계정 이름을 이스케이프", "<b>@" not in t and "&lt;b&gt;" in t)

print(f"\n{'ALL PASS' if not fails else str(fails)+' FAILED'}")
sys.exit(1 if fails else 0)
