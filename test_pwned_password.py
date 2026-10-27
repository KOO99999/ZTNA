"""pwned_password: HIBP 조회(k-anonymity) + 로그인 흐름(TOTP 후 비밀번호 변경 강제) 테스트.
실제 네트워크/DB를 쓰지 않고 requests.get·Account·db를 가짜로 바꿔 검증한다.
필요 패키지: flask, flask-sqlalchemy, pymysql, pyotp, pyjwt, cryptography"""
import hashlib, os, re, sys
from types import SimpleNamespace
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.update(DB_HOST="h", DB_NAME="n", DB_USER="u", DB_PASSWORD="p", OIDC_CLIENT_ID="cid",
                  OIDC_CLIENT_SECRET="sec", PDP_EVALUATE_URL="https://pdp.test/evaluate",
                  EVALUATE_SHARED_SECRET="test-secret-local-only", AUTO_MIGRATE_SCHEMA="0")
import flask_sqlalchemy, pyotp
flask_sqlalchemy.SQLAlchemy.create_all = lambda self, *a, **k: None
sys.path.insert(0, HERE)
import auth_app as aa
from werkzeug.security import generate_password_hash

fails = 0
def ok(name, cond, detail=""):
    global fails
    print(("[PASS] " if cond else "[FAIL] ") + name + ("" if cond else f"  detail={detail!r}"))
    fails += (not cond)

def sha(p): return hashlib.sha1(p.encode()).hexdigest().upper()

# ---- 1부: pwned_count ----
class Resp:
    def __init__(self, text, status=200): self.text, self.status = text, status
    def raise_for_status(self):
        if self.status >= 400: raise RuntimeError("http")

calls = []
def fake_get(body=None, exc=None, status=200):
    def g(url, headers=None, timeout=None):
        calls.append((url, headers, timeout))
        if exc: raise exc
        return Resp(body, status)
    return g

# 공개 테스트 벡터: "password" -> 5BAA6 / 1E4C9B93F3F0682250B6CF8331B7EE68FD8
ok("SHA-1 테스트 벡터", sha("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
body = "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2"
with patch.object(aa.requests, "get", fake_get(body)):
    ok("유출된 비밀번호 -> 횟수", aa.pwned_count("password") == 9545824)
url, hdr, to = calls[-1]
ok("앞 5자리만 전송", url.endswith("/range/5BAA6") and "1E4C9B" not in url, url)
ok("Add-Padding 헤더 + 타임아웃", hdr.get("Add-Padding") == "true" and to and to <= 3, (hdr, to))
with patch.object(aa.requests, "get", fake_get("0018A45C4D1DEF81644B54AB7F969B88D65:0\r\nAAAAA:3")):
    ok("목록에 없음 -> 0", aa.pwned_count("password") == 0)
pad_body = f"{sha('password')[5:]}:0"
with patch.object(aa.requests, "get", fake_get(pad_body)):
    ok("패딩(count 0) 항목은 유출로 보지 않음", aa.pwned_count("password") == 0)
for label, kw in [("타임아웃", dict(exc=TimeoutError())), ("연결 실패", dict(exc=ConnectionError())),
                  ("HTTP 500", dict(body="", status=500))]:
    with patch.object(aa.requests, "get", fake_get(**kw)):
        ok(f"{label} -> None(fail-open)", aa.pwned_count("password") is None)

# ---- 2부: 로그인 흐름 ----
ACC = {}
def mk(email, pw, totp=True):
    a = SimpleNamespace(email=email, password_hash=generate_password_hash(pw), totp_secret=pyotp.random_base32(),
                        totp_enabled=totp, id=len(ACC) + 1, role="employee", department="dev")
    ACC[email] = a; return a
class FQ:
    def filter_by(self, **kw):
        return SimpleNamespace(first=lambda: ACC.get(kw.get("email")), all=lambda: [])
commits = []
risk_calls = []
def fake_risk(email, signals):
    risk_calls.append((email, signals)); return {"allow": True, "action": "allow"}

OLD = "OldPassw0rd-leaked"
NEW = "correct horse battery 42"
mk("u@xmcda.store", OLD)
FORM = dict(client_id="cid", redirect_uri="https://app.test/cb", state="s", response_type="code", scope="openid")

def login(pw, pwned, email="u@xmcda.store"):
    c = aa.app.test_client()
    with patch.object(aa, "pwned_count", lambda p: pwned.get(p, 0)):
        r = c.post("/authorize", data={**FORM, "email": email, "password": pw})
    return c, r.get_data(as_text=True)

FAKE_SESSION = SimpleNamespace(add=lambda x: None, commit=lambda: commits.append(1))
with patch.object(aa, "Account", SimpleNamespace(query=FQ())), \
     patch.object(aa, "db", SimpleNamespace(session=FAKE_SESSION)), \
     patch.object(aa, "evaluate_login_risk", fake_risk), \
     patch.object(aa, "BackupCode", SimpleNamespace(query=SimpleNamespace(filter_by=lambda **k: SimpleNamespace(all=lambda: [])))), \
     patch.object(aa, "check_brute_force", lambda e: False):
    acct = ACC["u@xmcda.store"]

    # 유출 비번 -> TOTP 화면(변경 화면 아님), 위험도 평가는 아직 안 함
    aa.PENDING_LOGINS.clear(); risk_calls.clear()
    c, html = login(OLD, {OLD: 100})
    cid = next(iter(aa.PENDING_LOGINS))
    ok("유출 비번: 먼저 TOTP 화면", "verify-totp" in html and "change-password" not in html)
    ok("PENDING에 평문 비번 없음", OLD not in repr(aa.PENDING_LOGINS) and aa.PENDING_LOGINS[cid]["must_change"])
    # 비번만 아는 공격자: 변경 엔드포인트 직접 호출 불가
    r = c.post("/authorize/change-password", data={"challenge_id": cid, "new_password": NEW, "confirm_password": NEW})
    ok("TOTP 전에는 변경 불가", acct.password_hash and aa.check_password_hash(acct.password_hash, OLD)
       and "만료" in r.get_data(as_text=True))
    # 위 호출이 challenge를 지웠으므로 다시 로그인
    aa.PENDING_LOGINS.clear()
    c, html = login(OLD, {OLD: 100}); cid = next(iter(aa.PENDING_LOGINS))
    r = c.post("/authorize/verify-totp", data={"challenge_id": cid, "totp_code": "000000"})
    ok("TOTP 틀리면 변경 화면 안 나옴", "change-password" not in r.get_data(as_text=True))
    ok("TOTP 틀린 것도 로그인 실패로 기록(무차별 대입 잠금 대상)", len(commits) == 1, commits)
    commits.clear()   # 아래 "거부 중에는 해시 불변"은 비밀번호 변경 저장만 본다
    r = c.post("/authorize/verify-totp", data={"challenge_id": cid, "totp_code": pyotp.TOTP(acct.totp_secret).now()})
    h = r.get_data(as_text=True)
    ok("TOTP 통과 -> 변경 화면", "change-password" in h and r.status_code == 200 and not risk_calls)
    ok("변경 버튼 문구는 '변경'", '<button type="submit">변경</button>' in h and "변경 후 로그인" not in h)

    def change(newpw, conf=None, pwned=None):
        with patch.object(aa, "pwned_count", lambda p: (pwned or {}).get(p, 0)):
            return c.post("/authorize/change-password",
                          data={"challenge_id": cid, "new_password": newpw, "confirm_password": conf if conf is not None else newpw})
    t = lambda r: r.get_data(as_text=True)
    ok("11자 거부", "12자" in t(change("a" * 11)))
    ok("확인 불일치 거부", "일치하지" in t(change(NEW, NEW + "x")))
    ok("이전 비번과 동일 거부", "이전 비밀번호" in t(change(OLD)))
    ok("유출된 새 비번 거부", "유출" in t(change("leakedleaked12", pwned={"leakedleaked12": 5})))
    ok("거부 중에는 해시 불변", aa.check_password_hash(acct.password_hash, OLD) and not commits)
    # 변경 전에 이 계정의 기존 SSO 세션이 있었다고 가정 -> 변경 후 모두 무효화돼야 함
    aa.SSO_SESSIONS.clear()
    old_tok = aa.create_sso_session("u@xmcda.store"); other_tok = aa.create_sso_session("other@xmcda.store")
    r = change(NEW)
    ok("변경 성공 -> 자동 로그인 안 함(200, 로그인 화면)", r.status_code == 200 and "code=" not in r.headers.get("Location", "")
       and "다시 로그인" in t(r), (r.status_code, t(r)[:80]))
    ok("해시 교체 + 커밋", aa.check_password_hash(acct.password_hash, NEW) and not aa.check_password_hash(acct.password_hash, OLD) and commits)
    ok("변경 직후 위험도 평가 없음(재로그인 때 평가)", len(risk_calls) == 0, risk_calls)
    ok("기존 SSO 세션 무효화", old_tok not in aa.SSO_SESSIONS and aa.get_sso_session_email(old_tok) is None)
    ok("다른 사용자 SSO 세션은 유지", other_tok in aa.SSO_SESSIONS)
    ok("challenge 소모(재사용 불가)", cid not in aa.PENDING_LOGINS)
    r = change("another passphrase 99")
    ok("재사용 시 만료 안내", "만료" in t(r))

    # 정상 비번 -> 기존 흐름(변경 화면 없음)
    aa.PENDING_LOGINS.clear(); risk_calls.clear()
    c, html = login(NEW, {}); cid = next(iter(aa.PENDING_LOGINS))
    ok("정상 비번: must_change False", aa.PENDING_LOGINS[cid]["must_change"] is False)
    r = c.post("/authorize/verify-totp", data={"challenge_id": cid, "totp_code": pyotp.TOTP(acct.totp_secret).now()})
    ok("정상 비번: 바로 로그인", r.status_code == 302 and len(risk_calls) == 1)

    # fail-open: 조회 실패(None)여도 로그인 가능
    aa.PENDING_LOGINS.clear()
    with patch.object(aa, "pwned_count", lambda p: None):
        c = aa.app.test_client()
        c.post("/authorize", data={**FORM, "email": "u@xmcda.store", "password": NEW})
    cid = next(iter(aa.PENDING_LOGINS))
    ok("HIBP 실패: fail-open(변경 강제 없음)", aa.PENDING_LOGINS[cid]["must_change"] is False)

    # 틀린 비번이면 HIBP를 부르지 않음(외부 호출 최소화)
    seen = []
    with patch.object(aa, "pwned_count", lambda p: seen.append(p) or 0), \
         patch.object(aa, "LoginFailure", lambda **kw: None):
        aa.app.test_client().post("/authorize", data={**FORM, "email": "u@xmcda.store", "password": "wrong-wrong-wrong"})
    ok("틀린 비번은 HIBP 미호출", not seen, seen)

    # TOTP 미사용 계정 + 유출 -> 바로 변경 화면
    mk("n@xmcda.store", OLD, totp=False)
    aa.PENDING_LOGINS.clear()
    c, html = login(OLD, {OLD: 1}, "n@xmcda.store")
    ok("TOTP 없는 계정: 바로 변경 화면", "change-password" in html)

# 로그아웃: 5개 앱 로그아웃 요청이 모두 끝난 뒤 이동(고정 1초 아님), 응답 없어도 5초 뒤 이동
aa.SSO_SESSIONS.clear()
tk = aa.create_sso_session("u@xmcda.store")
c = aa.app.test_client(); c.set_cookie(aa.SSO_COOKIE_NAME, tk)
html = c.get("/logout").get_data(as_text=True)
ok("로그아웃: SSO 세션 서버에서 삭제", tk not in aa.SSO_SESSIONS)
ok("로그아웃: 5개 앱 로그아웃 주소 호출", html.count("/cdn-cgi/access/logout") == 5 and "admin.xmcda.store/cdn-cgi/access/logout" in html)
ok("로그아웃: 요청 끝난 뒤 이동(onload/onerror 카운트)", html.count('onload="done()"') == 5 and html.count('onerror="done()"') == 5 and "var remaining = 5" in html)
ok("로그아웃: 고정 1초 이동 없음 + 5초 안전장치", "1000" not in html and "setTimeout(go, 5000)" in html)
ok("로그아웃: 스크립트가 이미지보다 먼저 정의", html.index("function done()") < html.index("<img"))
# [서브도메인 분리] 앱 로그아웃 주소는 호스트 바로 아래(/cdn-cgi/...)여야 동작한다(경로 앱의 /dev/cdn-cgi/...는 실측 404/302)
ok("로그아웃: 경로 형태(/dev/cdn-cgi) 주소 없음", "/dev/cdn-cgi" not in html and "/hr/cdn-cgi" not in html and "/marketing/cdn-cgi" not in html)
ok("로그아웃: 5개 앱 호스트 각각의 로그아웃 주소",
   all(f"https://{h}/cdn-cgi/access/logout" in html for h in ("xmcda.store", "dev.xmcda.store", "marketing.xmcda.store", "hr.xmcda.store", "admin.xmcda.store")))
# 앱 로그아웃이 끝나면 우리 "로그아웃되었습니다" 화면으로 이동(Cloudflare 오류 화면 대신)
ok("로그아웃: 마지막 이동지 = /logged-out", 'window.location.href = "/logged-out"' in html)
ok("로그아웃: Cloudflare 팀 도메인 주소로 보내지 않음", "cloudflareaccess.com" not in html)
r = aa.app.test_client().get("/logged-out")
lo = r.get_data(as_text=True)
ok("로그아웃 완료 화면: 안내 문구 + 다시 로그인(포털) 버튼 + 캐시 안 함",
   r.status_code == 200 and "로그아웃되었습니다" in lo and 'href="https://xmcda.store/"' in lo and r.headers.get("Cache-Control") == "no-store")
os.environ["APP_HOSTS"] = "xmcda.store,dev.xmcda.store"
h3 = aa.app.test_client().get("/logout").get_data(as_text=True)
ok("로그아웃: 앱 목록은 APP_HOSTS(Terraform)를 따름", h3.count("/cdn-cgi/access/logout") == 2 and "var remaining = 2" in h3)
os.environ.pop("APP_HOSTS", None)

# 로그인 평가: 출처 login, 자원 = 로그인 서버 주소, 시각(UTC) 포함 (예전엔 자원 unknown/출처 A/밤에도 0점)
sent = []
class _R:
    def json(self): return {"allow": True}
with patch.object(aa.requests, "post", lambda url, **kw: sent.append(kw) or _R()):
    aa.evaluate_login_risk("u@xmcda.store", {"security_mfa_passed": True})
body = sent[0]["json"]
ok("로그인 평가 본문: source=login", body.get("source") == "login", body)
ok("로그인 평가 본문: resource_path=auth.xmcda.store/authorize", body.get("resource_path") == "auth.xmcda.store/authorize", body)
ok("로그인 평가 본문: request_timestamp(UTC, Z)", re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", body.get("request_timestamp", "")), body)
ok("로그인 평가 본문: 기존 신호 유지", body.get("security_mfa_passed") is True and body.get("identity") == "u@xmcda.store")

# SSO 30분 무활동 만료
import time as _t
aa.SSO_SESSIONS.clear()
tk = aa.create_sso_session("u@xmcda.store")
ok("방금 만든 세션 유효", aa.get_sso_session_email(tk) == "u@xmcda.store")
aa.SSO_SESSIONS[tk]["last_seen"] = _t.time() - (aa.SSO_IDLE_SECONDS - 60)
ok("29분 무활동: 유효 + last_seen 갱신", aa.get_sso_session_email(tk) == "u@xmcda.store" and _t.time() - aa.SSO_SESSIONS[tk]["last_seen"] < 5)
aa.SSO_SESSIONS[tk]["last_seen"] = _t.time() - (aa.SSO_IDLE_SECONDS + 60)
ok("31분 무활동: 만료", aa.get_sso_session_email(tk) is None and tk not in aa.SSO_SESSIONS)
tk = aa.create_sso_session("u@xmcda.store")
aa.SSO_SESSIONS[tk]["expires_at"] = _t.time() - 1
ok("절대 만료(8h) 지나면 무효", aa.get_sso_session_email(tk) is None)

# 로그에 비번이 안 남는지(소스 수준)
src = open(os.path.join(HERE, "auth_app.py"), encoding="utf-8").read()
ok("로그 출력에 password 변수 없음", not re.search(r"print\(f?[\"'][^\n]*\{(password|new_pw|h)\b", src))

print(f"\n실패 {fails}건"); sys.exit(1 if fails else 0)
