"""auth_app.py의 자동 계정 시딩(seed_accounts_from_ssm)을 실제 AWS/DB 없이 검증.
함수 소스만 추출해 가짜 DB/가짜 SSM으로 실행하므로 추가 패키지가 필요 없다."""
import ast, json, os, re, sys
from types import SimpleNamespace
from unittest.mock import MagicMock

HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "auth_app.py"), encoding="utf-8").read()
tree = ast.parse(src)
funcs = {n.name: ast.get_source_segment(src, n) for n in tree.body if isinstance(n, ast.FunctionDef)}
assigns = {t.id: ast.get_source_segment(src, n) for n in tree.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
need_funcs = ["_parse_account_departments", "seed_accounts_from_ssm"]
need_assigns = ["_PASSWORD_HASH_RE", "_TOTP_SECRET_RE"]
assert all(f in funcs for f in need_funcs) and all(a in assigns for a in need_assigns), "시딩 함수/상수를 찾지 못함"

fails = 0
def check(name, cond, detail=""):
    global fails
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + ("" if cond else f"\n    -> {detail!r}"))
    if not cond:
        fails += 1

# ---- 가짜 DB / 가짜 Account / 가짜 SSM ----
STORE = {}          # email -> Account
class FakeAccount:
    def __init__(self, **kw):
        self.__dict__.update(kw)
class FakeQuery:
    def filter_by(self, **kw):
        return SimpleNamespace(first=lambda: STORE.get(kw["email"]))
FakeAccount.query = FakeQuery()
class FakeSession:
    def __init__(self): self.pending = []; self.fail = False; self.rollbacks = 0
    def add(self, a): self.pending.append(a)
    def commit(self):
        if self.fail:
            raise RuntimeError("db down")
        for a in self.pending: STORE[a.email] = a
        self.pending = []
    def rollback(self): self.pending = []; self.rollbacks += 1
session = FakeSession()
db = SimpleNamespace(session=session)

ssm_value = {"v": None}
ssm_error = {"e": None}
ssm_calls = []
class FakeSsm:
    def get_parameter(self, Name, WithDecryption):
        ssm_calls.append((Name, WithDecryption))
        if ssm_error["e"]:
            raise ssm_error["e"]
        return {"Parameter": {"Value": ssm_value["v"]}}
fake_boto3 = SimpleNamespace(client=lambda svc, region_name=None: FakeSsm())
sys.modules["boto3"] = fake_boto3

ns = {"os": os, "re": re, "json": json, "Account": FakeAccount, "db": db}
exec("\n".join(assigns[a] for a in need_assigns) + "\n\n" + "\n\n".join(funcs[f] for f in need_funcs), ns)
seed = ns["seed_accounts_from_ssm"]

GOOD_HASH = "scrypt:32768:8:1$abcdefghijkl$" + "a" * 64
GOOD_TOTP = "JBSWY3DPEHPK3PXP"
DEPTS = "bdcozeee@gmail.com=admin;breakglass@xmcda.store=admin;employee01@xmcda.store=dev"

def run(creds, env=None, raw=None):
    STORE.clear(); ssm_calls.clear(); session.pending = []; session.fail = False; session.rollbacks = 0
    ssm_error["e"] = None
    ssm_value["v"] = raw if raw is not None else json.dumps(creds)
    for k in ("SEED_PARAM_NAME", "AUTO_SEED_ACCOUNTS", "ACCOUNT_DEPARTMENTS"):
        os.environ.pop(k, None)
    os.environ.update({"SEED_PARAM_NAME": "/zt/auth/seed_credentials", "ACCOUNT_DEPARTMENTS": DEPTS})
    os.environ.update(env or {})
    seed()

# 1. 정상 생성
run({"breakglass@xmcda.store": {"password_hash": GOOD_HASH, "totp_secret": GOOD_TOTP}})
a = STORE.get("breakglass@xmcda.store")
check("정상: 계정 생성(소속 admin -> role admin, TOTP 활성)", a and a.role == "admin" and a.department == "admin" and a.totp_enabled is True
      and a.password_hash == GOOD_HASH and a.totp_secret == GOOD_TOTP, a and a.__dict__)
check("SSM을 복호화 요청(WithDecryption)으로 읽음", ssm_calls == [("/zt/auth/seed_credentials", True)], ssm_calls)

run({"employee01@xmcda.store": {"password_hash": GOOD_HASH, "totp_secret": GOOD_TOTP}})
check("소속 dev -> role employee", STORE["employee01@xmcda.store"].role == "employee" and STORE["employee01@xmcda.store"].department == "dev")

# 2. 이미 있는 계정은 덮어쓰지 않음
STORE.clear()
STORE["breakglass@xmcda.store"] = FakeAccount(email="breakglass@xmcda.store", password_hash="old", totp_secret="OLD")
ssm_value["v"] = json.dumps({"breakglass@xmcda.store": {"password_hash": GOOD_HASH, "totp_secret": GOOD_TOTP}})
seed()
check("이미 있는 계정은 비밀번호/TOTP를 덮어쓰지 않음", STORE["breakglass@xmcda.store"].password_hash == "old" and STORE["breakglass@xmcda.store"].totp_secret == "OLD")

# 3. 이메일 대소문자/공백
run({" BreakGlass@xmcda.store ": {"password_hash": GOOD_HASH, "totp_secret": GOOD_TOTP}})
check("이메일은 소문자/공백 제거로 맞춤", "breakglass@xmcda.store" in STORE, list(STORE))

# 4. 거부 조건
run({"stranger@evil.com": {"password_hash": GOOD_HASH, "totp_secret": GOOD_TOTP}})
check("ACCOUNT_DEPARTMENTS에 없는 이메일은 만들지 않음", not STORE, list(STORE))
run({"breakglass@xmcda.store": {"password_hash": "MyPlainPassword123!", "totp_secret": GOOD_TOTP}})
check("평문 비밀번호(해시 형식 아님)는 거부", not STORE, list(STORE))
run({"breakglass@xmcda.store": {"password": "plain", "totp_secret": GOOD_TOTP}})
check("password_hash 없이 password만 있으면 거부", not STORE, list(STORE))
run({"breakglass@xmcda.store": {"password_hash": GOOD_HASH}})
check("TOTP 시크릿이 없으면 거부(서버가 임의로 만들지 않음)", not STORE, list(STORE))
run({"breakglass@xmcda.store": {"password_hash": GOOD_HASH, "totp_secret": "not base32!"}})
check("TOTP 시크릿 형식이 이상하면 거부", not STORE, list(STORE))
run({"breakglass@xmcda.store": "문자열"})
check("항목이 객체가 아니면 건너뜀", not STORE, list(STORE))
run({"breakglass@xmcda.store": {"password_hash": GOOD_HASH, "totp_secret": GOOD_TOTP},
     "employee01@xmcda.store": {"password_hash": "bad", "totp_secret": GOOD_TOTP}})
check("한 계정이 잘못돼도 나머지는 생성", list(STORE) == ["breakglass@xmcda.store"], list(STORE))

# 5. 실패해도 서버는 계속 켜진다(예외를 밖으로 내지 않음) + 비밀이 로그에 안 남음
import io, contextlib
def run_logged(**kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        run(**kw)
    return buf.getvalue()

STORE.clear()
log = run_logged(creds={"breakglass@xmcda.store": {"password_hash": GOOD_HASH, "totp_secret": GOOD_TOTP}})
check("성공 로그에 해시/TOTP 값이 없음", GOOD_HASH not in log and GOOD_TOTP not in log and "[SEED] breakglass@xmcda.store 생성" in log, log)

for label, err in [("권한 없음", PermissionError("AccessDenied secret-detail")), ("파라미터 없음", KeyError("ParameterNotFound"))]:
    STORE.clear(); ssm_calls.clear()
    ssm_value["v"] = "{}"; ssm_error["e"] = err
    for k in ("SEED_PARAM_NAME", "AUTO_SEED_ACCOUNTS"): os.environ.pop(k, None)
    os.environ["SEED_PARAM_NAME"] = "/zt/auth/seed_credentials"
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        seed()
    out = buf.getvalue()
    check(f"SSM 읽기 실패({label}): 예외 없이 건너뛰고 예외 종류만 기록, 내용은 미노출", "[SEED_SKIPPED]" in out and "secret-detail" not in out and not STORE, out)
ssm_error["e"] = None

log = run_logged(creds=None, raw="not json")
check("JSON이 아니면 건너뜀", "[SEED_SKIPPED]" in log and not STORE, log)
log = run_logged(creds=None, raw='["list"]')
check("JSON 객체가 아니면 건너뜀", "[SEED_SKIPPED]" in log and not STORE, log)

STORE.clear(); ssm_value["v"] = json.dumps({"breakglass@xmcda.store": {"password_hash": GOOD_HASH, "totp_secret": GOOD_TOTP}})
session.fail = True
os.environ.update({"SEED_PARAM_NAME": "/zt/auth/seed_credentials", "ACCOUNT_DEPARTMENTS": DEPTS})
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    seed()
check("DB 저장 실패: 롤백하고 계속(예외 없음), 값 미노출", session.rollbacks == 1 and "[SEED_FAILED]" in buf.getvalue() and GOOD_HASH not in buf.getvalue(), buf.getvalue())
session.fail = False

# 6. 끄는 방법 / 설정 없음
run({"breakglass@xmcda.store": {"password_hash": GOOD_HASH, "totp_secret": GOOD_TOTP}}, env={"AUTO_SEED_ACCOUNTS": "0"})
check("AUTO_SEED_ACCOUNTS=0이면 SSM을 읽지도 않음", not STORE and not ssm_calls, ssm_calls)
STORE.clear(); ssm_calls.clear()
for k in ("SEED_PARAM_NAME", "AUTO_SEED_ACCOUNTS"): os.environ.pop(k, None)
seed()
check("SEED_PARAM_NAME이 없으면 아무것도 하지 않음", not STORE and not ssm_calls)

print("\n실패 수:", fails)
sys.exit(1 if fails else 0)
