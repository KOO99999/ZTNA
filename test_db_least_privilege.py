"""WAS->DB 구간: TLS 강제, 앱 전용 최소권한 DB 계정, 부팅 단계 분리, 앱 프로세스의 메타데이터 접근 차단 검증.
실제 DB/AWS 없이 SQL 문장과 설정 파일 내용을 검사한다. (실제 동작은 배포 후 SSM 터미널에서 확인)
필요 패키지: flask, flask-sqlalchemy, pymysql, pyotp, pyjwt, cryptography"""
import os, re, sys, subprocess
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
fails = 0
def ok(name, cond, detail=""):
    global fails
    fails += (not cond)
    print(("[PASS] " if cond else "[FAIL] ") + name + ("" if cond else f"\n    -> {detail}"))

os.environ.update(DB_HOST="zt-login-db.abc.ap-northeast-2.rds.amazonaws.com", DB_NAME="login_server",
                  DB_USER="zt_auth_app", DB_PASSWORD="p", DB_SSL_CA="/etc/ztauth/rds-ca.pem",
                  OIDC_CLIENT_ID="cid", OIDC_CLIENT_SECRET="sec", PDP_EVALUATE_URL="https://pdp.test/evaluate",
                  EVALUATE_SHARED_SECRET="s", AUTO_MIGRATE_SCHEMA="0")
import flask_sqlalchemy
created = []
flask_sqlalchemy.SQLAlchemy.create_all = lambda self, *a, **k: created.append(1)
sys.path.insert(0, HERE)
import auth_app as aa

# ---------- 1. 앱의 DB 접속: TLS + 서버 인증서/이름 검증 ----------
opts = aa.app.config.get("SQLALCHEMY_ENGINE_OPTIONS", {})
ssl = opts.get("connect_args", {}).get("ssl", {})
ok("DB_SSL_CA가 있으면 TLS 접속 설정(ca=RDS 인증서 묶음)", ssl.get("ca") == "/etc/ztauth/rds-ca.pem", opts)
ok("서버 인증서 이름(호스트) 검증 켬", ssl.get("check_hostname") is True, ssl)
ok("앱은 import만으로 테이블 생성/시딩을 하지 않음(부팅 단계에서만)", not created, created)

# ---------- 2. 앱 전용 계정 만들기(SQL) ----------
class FakeSession:
    def __init__(self): self.sql = []; self.commits = 0
    def execute(self, stmt, params=None): self.sql.append((str(stmt), params))
    def commit(self): self.commits += 1
    def rollback(self): pass

def run_user(env):
    fs = FakeSession()
    with patch.dict(os.environ, env, clear=False), patch.object(aa.db, "session", fs):
        aa.ensure_app_db_user()
    return fs

PW = "A" * 32
fs = run_user({"APP_DB_USER": "zt_auth_app", "APP_DB_PASSWORD": PW, "APP_DB_HOST": "10.0.2.0/255.255.255.0"})
sqls = [s for s, _ in fs.sql]
ok("CREATE USER IF NOT EXISTS ... REQUIRE SSL (앱 서브넷에서만)",
   any(s.startswith("CREATE USER IF NOT EXISTS `zt_auth_app`@'10.0.2.0/255.255.255.0'") and s.endswith("REQUIRE SSL") for s in sqls), sqls)
ok("ALTER USER로 비밀번호/REQUIRE SSL 재적용(재실행해도 같은 상태)", any(s.startswith("ALTER USER `zt_auth_app`") and "REQUIRE SSL" in s for s in sqls), sqls)
grant = [s for s in sqls if s.startswith("GRANT")]
ok("권한은 이 DB의 SELECT/INSERT/UPDATE/DELETE만",
   grant == ["GRANT SELECT, INSERT, UPDATE, DELETE ON `login_server`.* TO `zt_auth_app`@'10.0.2.0/255.255.255.0'"], grant)
ok("DDL/관리 권한(CREATE, DROP, ALTER, GRANT OPTION, ALL) 없음",
   not any(re.search(r"\b(ALL|DROP|CREATE|ALTER|INDEX|GRANT OPTION)\b", g.split(" ON ")[0].replace("GRANT ", "", 1)) for g in grant), grant)
ok("비밀번호는 SQL 문장에 직접 넣지 않고 바인딩", all(PW not in s for s in sqls) and any(p and p.get("pw") == PW for _, p in fs.sql))
ok("커밋함", fs.commits == 1)

for name, env in [("사용자 이름에 따옴표/백틱", {"APP_DB_USER": "a`; DROP TABLE accounts;--", "APP_DB_PASSWORD": PW, "APP_DB_HOST": "%"}),
                  ("호스트에 따옴표", {"APP_DB_USER": "zt_auth_app", "APP_DB_PASSWORD": PW, "APP_DB_HOST": "%' OR '1"}),
                  ("짧거나 특수문자 비밀번호", {"APP_DB_USER": "zt_auth_app", "APP_DB_PASSWORD": "short'pw", "APP_DB_HOST": "%"}),
                  ("사용자 이름 없음", {"APP_DB_USER": "", "APP_DB_PASSWORD": PW, "APP_DB_HOST": "%"})]:
    try:
        f2 = run_user(env)
        ok(f"형식 오류({name}) -> 거부, SQL 실행 없음", False, f2.sql)
    except ValueError:
        ok(f"형식 오류({name}) -> 거부, SQL 실행 없음", True)

# ---------- 3. 부팅 단계 순서 ----------
order = []
with patch.object(aa.db, "create_all", lambda *a, **k: order.append("create_all")), \
     patch.object(aa, "ensure_department_schema", lambda: order.append("schema")), \
     patch.object(aa, "ensure_app_db_user", lambda: order.append("app_user")), \
     patch.object(aa, "seed_accounts_from_ssm", lambda: order.append("seed")):
    aa.bootstrap_database()
ok("부팅 단계 순서: 테이블 생성 -> 컬럼/소속 -> 앱 계정 -> 계정 시딩", order == ["create_all", "schema", "app_user", "seed"], order)
src = open(os.path.join(HERE, "auth_app.py"), encoding="utf-8").read()
ok("--bootstrap 인자일 때만 부팅 단계 실행 후 종료", "if '--bootstrap' in sys.argv:" in src and "bootstrap_database()" in src.split("if '--bootstrap' in sys.argv:")[1][:200])

# ---------- 4. 배포 설정(user_data / Terraform) ----------
tpl = open(os.path.join(HERE, "templates", "user_data_auth.sh.tpl"), encoding="utf-8").read()
app_env = tpl.split("cat << 'ZTENV' > /etc/ztauth/env")[1].split("ZTENV")[0]
boot_env = tpl.split("cat << 'ZTBOOT' > /etc/ztauth/bootstrap.env")[1].split("ZTBOOT")[0]
ok("앱 환경변수: DB 계정은 앱 전용 계정", "DB_USER=${app_db_user}" in app_env and "DB_PASSWORD=${app_db_password}" in app_env)
ok("앱 환경변수에 마스터 계정/시딩/AWS 값 없음", "master_db" not in app_env and "SEED_PARAM_NAME" not in app_env and "AWS_REGION" not in app_env)
ok("앱 환경변수: TLS 인증서 묶음 경로", "DB_SSL_CA=/etc/ztauth/rds-ca.pem" in app_env)
ok("부팅 전용 파일에만 마스터 계정", "DB_USER=${master_db_user}" in boot_env and "DB_PASSWORD=${master_db_password}" in boot_env)
ok("부팅 전용 파일은 root만 읽기 + 끝나면 삭제", "chmod 600 /etc/ztauth/bootstrap.env" in tpl and "shred -u /etc/ztauth/bootstrap.env" in tpl)
ok("부팅 단계가 서비스 시작보다 먼저", tpl.index("--bootstrap") < tpl.index("systemctl enable --now auth-app"))
ok("AWS 공식 RDS 인증서 묶음 다운로드", "https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem" in tpl)
svc = tpl.split("[Service]")[1].split("[Install]")[0]
ok("앱 서비스: 인스턴스 메타데이터 접근 차단(IPAddressDeny)", "IPAddressDeny=169.254.169.254" in svc)
ok("앱 서비스: 전용 계정(ztauth)으로 실행", "User=ztauth" in svc)

def read_tf(name):
    return open(os.path.join(HERE, name), encoding="utf-8").read().replace("\r\n", "\n")
dbtf = read_tf("database.tf")
ok("RDS 파라미터 그룹: require_secure_transport = ON", re.search(r'name\s*=\s*"require_secure_transport"\s*\n\s*value\s*=\s*"ON"', dbtf) is not None)
ok("RDS 인스턴스에 파라미터 그룹 연결", "parameter_group_name   = aws_db_parameter_group.login_db_params.name" in dbtf)
ec2 = read_tf("ec2_auth.tf")
ok("앱 계정 접속 위치 = 앱 서브넷(IP/넷마스크)", "cidrnetmask(aws_subnet.app_subnet.cidr_block)" in ec2)

print(f"\n실패 {fails}건"); sys.exit(1 if fails else 0)
