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
want = ["_safe_return_url", "_original_url_candidate", "_resolve_return_url",
        "_parse_path_permissions", "_parse_account_departments", "_resource_key", "check_department_access", "render_no_permission"]
funcs = {n.name: ast.get_source_segment(src, n) for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in want}
assert sorted(funcs) == sorted(want), f"함수를 찾지 못함: {set(want) - set(funcs)}"

os.environ["DOMAIN_NAME"] = "auth.xmcda.store"
req = SimpleNamespace(args={}, referrer=None)
ns = {"os": os, "urlparse": urlparse, "request": req, "escape": escape}
exec("\n\n".join(funcs[n] for n in want), ns)
ns["PATH_PERMISSIONS"] = ns["_parse_path_permissions"]("/dev=dev;/marketing=marketing;/hr=hr;admin=admin")
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
check("original_url /dev (실제 관찰값)", run({"original_url": "xmcda.store/dev"}), H + "/dev")
check("original_url /hr", run({"original_url": "xmcda.store/hr"}), H + "/hr")
check("original_url admin", run({"original_url": "admin.xmcda.store/"}), "https://admin.xmcda.store/")
check("original_url 쿼리 포함", run({"original_url": "xmcda.store/dev?a=1&b=2"}), H + "/dev?a=1&b=2")
check("original_url https:// 이미 있음", run({"original_url": "https://xmcda.store/dev"}), H + "/dev")
check("없으면 홈", run({}), H)
check("외부 도메인 거부", run({"original_url": "evil.com/login"}), H)
check("비슷한 도메인 거부", run({"original_url": "xmcda.store.evil.com/dev"}), H)
check("앞부분만 같은 도메인 거부", run({"original_url": "evilxmcda.store/dev"}), H)
check("@ 우회 거부", run({"original_url": "xmcda.store@evil.com/x"}), H)
check("// 시작 거부", run({"original_url": "//evil.com/x"}), H)
check("http 거부", run({"original_url": "http://xmcda.store/dev"}), H)
check("javascript: 거부", run({"original_url": "javascript:alert(1)"}), H)
check("따옴표 포함 거부(XSS)", run({"original_url": 'xmcda.store/dev"onload="x'}), H)
check("역슬래시 거부", run({"original_url": "xmcda.store\\@evil.com"}), H)
check("공백/개행 거부", run({"original_url": "xmcda.store/dev\r\nX: y"}), H)
check("포트 거부", run({"original_url": "xmcda.store:8443/dev"}), H)
check("return_url이 original_url보다 우선", run({"return_url": "https://xmcda.store/marketing", "original_url": "xmcda.store/dev"}), H + "/marketing")
check("잘못된 return_url이면 original_url 사용", run({"return_url": "https://evil.com", "original_url": "xmcda.store/dev"}), H + "/dev")
check("original_url 없으면 Referer 사용", run({}, "https://xmcda.store/hr/page"), H + "/hr")
check("original_url이 이상하면 Referer로", run({"original_url": "evil.com"}, "https://admin.xmcda.store/x"), "https://admin.xmcda.store")

# ---------- 소속 기반 권한 안내 (함수 단위) ----------
parse = ns["_parse_path_permissions"]
check("권한표 파싱", parse("/dev=dev;/hr=hr,legal;admin=admin"), {"/dev": ["dev"], "/hr": ["hr", "legal"], "admin": ["admin"]})
check("권한표가 비어 있으면 빈 표", parse(""), {})
check("권한표가 None이어도 빈 표", parse(None), {})
check("형식이 깨진 조각은 무시", parse("garbage;/dev=dev;=x;/hr"), {"/dev": ["dev"]})
check("공백은 정리", parse(" /dev = dev , qa ; admin=admin "), {"/dev": ["dev", "qa"], "admin": ["admin"]})

rk = ns["_resource_key"]
check("자원 키: https://xmcda.store/dev", rk("https://xmcda.store/dev"), "/dev")
check("자원 키: 하위 경로 /dev/a/b -> /dev", rk("https://xmcda.store/dev/a/b?x=1"), "/dev")
check("자원 키: 홈", rk("https://xmcda.store"), "/")
check("자원 키: admin 서브도메인은 경로와 무관하게 admin", rk("https://admin.xmcda.store/anything"), "admin")

acc = ns["check_department_access"]
check("dev 소속이 /dev -> 허용", acc("dev", H + "/dev"), True)
check("admin 소속이 /dev -> 거부", acc("admin", H + "/dev"), False)
check("marketing 소속이 /hr -> 거부", acc("marketing", H + "/hr"), False)
check("소속이 비어 있으면(None) 보호 자원은 거부", acc(None, H + "/hr"), False)
check("소속이 빈 문자열이어도 거부", acc("", H + "/hr"), False)
check("admin 소속이 admin 서브도메인 -> 허용", acc("admin", "https://admin.xmcda.store/"), True)
check("dev 소속이 admin 서브도메인 -> 거부", acc("dev", "https://admin.xmcda.store/"), False)
check("권한표에 없는 자원(홈)은 판단 불가(None) -> 기존 흐름 유지", acc("dev", H), None)
check("대소문자가 다르면 같은 소속이 아님(정확히 일치만)", acc("DEV", H + "/dev"), False)
ns["PATH_PERMISSIONS"] = {}
check("권한표가 비어 있으면 판단 불가(None) -> 기존 흐름 유지", acc("dev", H + "/dev"), None)
ns["PATH_PERMISSIONS"] = parse("/dev=dev;/marketing=marketing;/hr=hr;admin=admin")

html = ns["render_no_permission"]("kim@xmcda.store", "marketing", H + "/hr")
check("권한 없음 화면: 계정/소속/필요 소속/홈/로그아웃 링크 포함",
      all(x in html for x in ("kim@xmcda.store", ">marketing<", ">hr<", 'href="https://xmcda.store/"', 'href="/logout"')), True)
check("권한 없음 화면에 TOTP 입력 폼이 없음", ("totp" not in html.lower()) and ("<form" not in html), True)
evil = ns["render_no_permission"]("<script>alert(1)</script>@x.com", '"><img src=x onerror=alert(2)>', H + "/hr")
check("권한 없음 화면은 계정/소속 값을 HTML 이스케이프(XSS 방지)", ("<script>alert(1)" not in evil) and ("<img src=x" not in evil), True)
nodept = ns["render_no_permission"]("kim@xmcda.store", None, H + "/hr")
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
                      PATH_PERMISSIONS="/dev=dev;/marketing=marketing;/hr=hr;admin=admin",
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
    with aa.app.app_context(), \
         patch.object(aa.Account, "query", FakeQuery(), create=True), \
         patch.object(aa, "check_brute_force", lambda e: False), \
         patch.object(aa, "evaluate_login_risk", lambda i, s: risk_calls.append((i, s)) or {"recorded": True}):

        def stepup_get(email, original="xmcda.store/dev", extra=None):
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
        r = stepup_get("mkt1@xmcda.store", original="xmcda.store/hr")
        check("marketing 계정이 /hr -> '권한 없음'(403)", (r.status_code, "접근 권한이 없습니다" in r.get_data(as_text=True)), (403, True))
        r = stepup_get("dev1@xmcda.store", original="admin.xmcda.store/")
        check("dev 계정이 admin 콘솔 -> '권한 없음'(403)", (r.status_code, "접근 권한이 없습니다" in r.get_data(as_text=True)), (403, True))
        r = stepup_get("admin1@xmcda.store", original="admin.xmcda.store/")
        check("admin 계정이 admin 콘솔 step-up -> TOTP 화면(200)", (r.status_code, "totp_code" in r.get_data(as_text=True)), (200, True))
        r = stepup_get("nodept@xmcda.store")
        check("소속이 지정되지 않은 계정이 보호 자원 -> '권한 없음'(403)", (r.status_code, "(지정되지 않음)" in r.get_data(as_text=True)), (403, True))
        r = stepup_get("admin1@xmcda.store", original="xmcda.store/")
        check("권한표에 없는 자원(홈)은 기존대로 TOTP 화면", (r.status_code, "totp_code" in r.get_data(as_text=True)), (200, True))
        r = stepup_get("admin1@xmcda.store", original=None, extra={"return_url": "https://xmcda.store/dev"})
        ok("게이트가 보낸 ?return_url= 로 와도 같은 권한 확인", r.status_code == 403, r.status_code)

        # POST 직접 호출 우회: 소속이 맞지 않으면 TOTP 검증도, Lambda 기록도 하지 않는다
        risk_calls.clear()
        c.set_cookie(aa.SSO_COOKIE_NAME, login_cookie("admin1@xmcda.store"), domain="localhost")
        good_code = pyotp.TOTP(ACCOUNTS["admin1@xmcda.store"].totp_secret).now()
        r = c.post("/stepup", data={"return_url": "https://xmcda.store/dev", "totp_code": good_code})
        ok("올바른 TOTP를 직접 POST해도 소속이 다르면 403, MFA 기록 없음",
              r.status_code == 403 and "접근 권한이 없습니다" in r.get_data(as_text=True) and not risk_calls, (r.status_code, risk_calls))
        c.set_cookie(aa.SSO_COOKIE_NAME, login_cookie("dev1@xmcda.store"), domain="localhost")
        good_code = pyotp.TOTP(ACCOUNTS["dev1@xmcda.store"].totp_secret).now()
        r = c.post("/stepup", data={"return_url": "https://xmcda.store/dev", "totp_code": good_code})
        ok("소속이 맞는 사용자의 올바른 TOTP -> 인증 완료 + MFA 기록 + 원래 페이지(/dev)로 이동",
              r.status_code == 200 and "인증되었습니다" in r.get_data(as_text=True) and 'https://xmcda.store/dev' in r.get_data(as_text=True)
              and risk_calls and risk_calls[0][1] == {"mfa_reauth": True}, (r.status_code, risk_calls))

        # 로그인 안 한 상태
        c.delete_cookie(aa.SSO_COOKIE_NAME, domain="localhost")
        r = c.get("/stepup", query_string={"original_url": "xmcda.store/dev"})
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

print(f"\n{'ALL PASS' if not fails else str(fails)+' FAILED'}")
sys.exit(1 if fails else 0)
