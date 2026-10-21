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
    r = c.post("/authorize/verify-totp", data={"challenge_id": cid, "totp_code": pyotp.TOTP(acct.totp_secret).now()})
    h = r.get_data(as_text=True)
    ok("TOTP 통과 -> 변경 화면", "change-password" in h and r.status_code == 200 and not risk_calls)

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
    r = change(NEW)
    ok("변경 성공 -> 로그인 완료(redirect)", r.status_code == 302 and "code=" in r.headers["Location"], (r.status_code, t(r)[:80]))
    ok("해시 교체 + 커밋", aa.check_password_hash(acct.password_hash, NEW) and not aa.check_password_hash(acct.password_hash, OLD) and commits)
    ok("그때 위험도 평가 1회(totp_ok)", len(risk_calls) == 1 and risk_calls[0][1].get("security_mfa_passed") is True
       and "pwned_password" not in risk_calls[0][1], risk_calls)
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

# 로그에 비번이 안 남는지(소스 수준)
src = open(os.path.join(HERE, "auth_app.py"), encoding="utf-8").read()
ok("로그 출력에 password 변수 없음", not re.search(r"print\(f?[\"'][^\n]*\{(password|new_pw|h)\b", src))

print(f"\n실패 {fails}건"); sys.exit(1 if fails else 0)
