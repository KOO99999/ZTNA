from flask import Flask, request, jsonify, redirect, make_response, has_request_context
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
import sys
import time
import uuid
import secrets
import pyotp
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import requests
import re
import hashlib
import hmac
from html import escape
from urllib.parse import urlparse

from zt_mtls import build_server_context, client_allowed, client_cert_cn, mtls_settings
from zt_ui import alert, auth_page, esc, icon, link_button


def log_event(event, **fields):
    """관제(ELK)용 구조화 로그 한 줄 "ZT_EVENT {json}" (엔진/웹 서버와 같은 형식). journald -> Filebeat -> Logstash.
    접속 IP는 요청 중일 때만 Cloudflare가 넣어 준 실제 접속 IP(CF-Connecting-IP)를 붙인다."""
    record = {"event": event, "service": "auth", "ts": int(time.time())}
    if has_request_context() and "client_ip" not in fields:
        record["client_ip"] = request.headers.get('CF-Connecting-IP')
    record.update({k: v for k, v in fields.items() if v is not None})
    print("ZT_EVENT " + json.dumps(record, ensure_ascii=False, default=str), flush=True)

app = Flask(__name__)

# [Web->WAS mTLS] 웹 서버(nginx)의 클라이언트 인증서로 들어온 요청만 받는다(zt_mtls.py). 연결 단계에서 내부 CA
# 서명이 없는 인증서는 이미 거부되고, 여기서는 그 인증서의 이름이 웹 서버(MTLS_ALLOWED_CLIENT)인지 한 번 더 본다.
MTLS = mtls_settings()


@app.before_request
def mtls_client_gate():
    if MTLS and not client_allowed(request.environ, MTLS[3]):
        print(f"[MTLS_CLIENT_REJECTED] cn={client_cert_cn(request.environ)!r} remote={request.remote_addr}", flush=True)
        log_event("mtls_client_rejected", cn=client_cert_cn(request.environ), remote=request.remote_addr, client_ip=None)
        return "forbidden", 403
    return None


DB_HOST = os.environ.get('DB_HOST')
DB_NAME = os.environ.get('DB_NAME')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')

app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# [WAS->DB TLS] DB_SSL_CA(AWS RDS 인증서 묶음 파일 경로)가 있으면 TLS로만 접속하고, 서버 인증서가 그 묶음으로
# 서명됐는지와 인증서의 이름이 접속한 주소(DB_HOST)와 같은지까지 확인한다(가짜 DB 서버로의 중간자 공격 차단).
# RDS 쪽도 require_secure_transport=ON(database.tf)이라 암호화 안 된 접속은 서버가 거부한다.
DB_SSL_CA = os.environ.get('DB_SSL_CA')
if DB_SSL_CA:
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        "connect_args": {"ssl": {"ca": DB_SSL_CA, "check_hostname": True}},
        "pool_pre_ping": True,
    }

db = SQLAlchemy(app)


class Account(db.Model):
    __tablename__ = 'accounts'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    role = db.Column(db.String(32), default='employee', nullable=False)
    # 소속 부서(dev / marketing / hr / admin). 토큰의 department 클레임과 "접근 권한 없음" 안내 화면에 쓴다.
    # 기존 DB에는 이 컬럼이 없다(db.create_all()은 이미 있는 테이블에 컬럼을 추가해 주지 않음).
    # 아래 ensure_department_schema()가 부팅 단계(bootstrap_database, 마스터 계정)에서 자동으로 추가한다.
    department = db.Column(db.String(32), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class BackupCode(db.Model):
    __tablename__ = 'backup_codes'

    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)
    code_hash = db.Column(db.String(255), nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class LoginFailure(db.Model):
    __tablename__ = 'login_failures'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    attempted_at = db.Column(db.DateTime, server_default=db.func.now())
    ip_address = db.Column(db.String(45), nullable=True)




# ==========================================================================
# [자동 마이그레이션] 부팅 단계(bootstrap_database)에서 accounts.department 컬럼을 보장하고 소속을 채운다.
#
# 왜: db.create_all()은 "없는 테이블"만 만들고 이미 있는 테이블에 컬럼을 추가해 주지 않는다.
#     옛 DB에 새 코드가 붙으면 없는 컬럼을 SELECT해서 로그인 서버 전체가 오류가 난다.
# 무엇을:
#   1) department 컬럼이 없으면 ALTER TABLE로 추가한다(NULL 허용, 있으면 아무것도 안 함).
#   2) ACCOUNT_DEPARTMENTS 환경변수("이메일=소속;이메일=소속", Terraform main.tf의 이메일 목록에서 생성)에
#      적힌 계정만 소속을 맞춘다. 목록에 없는 계정은 건드리지 않는다.
# 따로 빼는 법: AUTO_MIGRATE_SCHEMA=0 으로 끄거나(환경변수), 이 블록(ensure_department_schema와
#      아래 호출 두 줄)을 지우고 account/migrate_department.py를 손으로 돌리면 된다.
# ==========================================================================
def _parse_account_departments(raw):
    """'a@x=dev;b@x=hr' -> {'a@x': 'dev', 'b@x': 'hr'}. 형식이 이상한 항목은 건너뛴다."""
    result = {}
    for item in (raw or '').split(';'):
        email, sep, dept = item.strip().partition('=')
        email, dept = email.strip().lower(), dept.strip()
        if sep and email and dept:
            result[email] = dept[:32]
    return result


def ensure_department_schema():
    if os.environ.get('AUTO_MIGRATE_SCHEMA', '1') != '1':
        return
    from sqlalchemy import inspect, text

    if 'department' not in [c['name'] for c in inspect(db.engine).get_columns('accounts')]:
        try:
            db.session.execute(text('ALTER TABLE accounts ADD COLUMN department VARCHAR(32) NULL'))
            db.session.commit()
            print('[MIGRATE] accounts.department 컬럼 추가', flush=True)
        except Exception as e:
            db.session.rollback()
            # 워커가 여러 개면 다른 쪽이 먼저 추가했을 수 있다. 그래도 없으면 진짜 오류이므로 그대로 올린다.
            if 'department' not in [c['name'] for c in inspect(db.engine).get_columns('accounts')]:
                raise
            print(f'[MIGRATE] 컬럼은 다른 프로세스가 이미 추가함: {e}', flush=True)

    try:
        changed = 0
        for email, dept in _parse_account_departments(os.environ.get('ACCOUNT_DEPARTMENTS')).items():
            account = Account.query.filter_by(email=email).first()
            if account and account.department != dept:
                print(f'[MIGRATE] {email}: {account.department!r} -> {dept!r}', flush=True)
                account.department = dept
                changed += 1
        db.session.commit()
        print(f'[MIGRATE] 소속 갱신 {changed}건', flush=True)
    except Exception as e:
        db.session.rollback()
        print(f'[MIGRATE_SYNC_FAILED] {e}', flush=True)


# ==========================================================================
# [자동 계정 시딩] 부팅 단계(bootstrap_database, root)에서 AWS SSM Parameter Store(SecureString)에 저장된 계정 정보로, DB에 없는 계정만 만든다.
# (앱 서비스는 AWS 권한을 쓰지 않는다 - 인스턴스 메타데이터 접근을 systemd가 막음)
#
# 왜: RDS를 새로 만들면 accounts가 비어 있어서 계정을 손으로 다시 만들어야 했다(seed_accounts.py).
#     비밀번호/TOTP는 Terraform 변수나 user_data에 넣으면 콘솔과 state에 남으므로, 값은 내 PC에서 AWS에 직접 올리고
#     (account/put_seed_credentials.py) 이 서버는 자기 IAM 역할로 그 값만 읽는다.
# 저장 형식(JSON): {"이메일": {"password_hash": "scrypt:...", "totp_secret": "BASE32"}, ...}
#   - 비밀번호는 평문이 아니라 해시(werkzeug)만 저장한다. 평문이 들어 있으면(형식이 해시가 아니면) 만들지 않는다.
#   - ACCOUNT_DEPARTMENTS(Terraform 이메일 목록)에 없는 이메일은 만들지 않는다. 소속과 role은 그 목록에서 정한다.
#   - 이미 있는 계정은 건드리지 않는다(비밀번호/TOTP 덮어쓰기 없음). 값을 못 읽어도 로그인 서버는 그대로 켜진다.
# 끄는 법: AUTO_SEED_ACCOUNTS=0 (또는 SEED_PARAM_NAME을 비움)
# ==========================================================================
_PASSWORD_HASH_RE = re.compile(r'^(scrypt|pbkdf2):[^\s]{20,}$')
_TOTP_SECRET_RE = re.compile(r'^[A-Z2-7]{16,64}$')


def seed_accounts_from_ssm():
    param_name = os.environ.get('SEED_PARAM_NAME')
    if os.environ.get('AUTO_SEED_ACCOUNTS', '1') != '1' or not param_name:
        return
    try:
        import boto3
        ssm = boto3.client('ssm', region_name=os.environ.get('AWS_REGION', 'ap-northeast-2'))
        raw = ssm.get_parameter(Name=param_name, WithDecryption=True)['Parameter']['Value']
        creds = json.loads(raw)
        if not isinstance(creds, dict):
            raise ValueError('JSON 객체가 아님')
    except Exception as e:
        # 값(비밀)이 로그에 남지 않게 예외 종류만 적는다
        print(f'[SEED_SKIPPED] 계정 시딩 값을 읽지 못함: {type(e).__name__}', flush=True)
        return

    departments = _parse_account_departments(os.environ.get('ACCOUNT_DEPARTMENTS'))
    created = 0
    for raw_email, entry in creds.items():
        email = str(raw_email).strip().lower()
        dept = departments.get(email)
        if dept is None:
            print(f'[SEED] {email}: ACCOUNT_DEPARTMENTS에 없어 건너뜀', flush=True)
            continue
        if not isinstance(entry, dict):
            continue
        password_hash, totp_secret = entry.get('password_hash'), entry.get('totp_secret')
        if not (isinstance(password_hash, str) and _PASSWORD_HASH_RE.match(password_hash)
                and isinstance(totp_secret, str) and _TOTP_SECRET_RE.match(totp_secret)):
            print(f'[SEED] {email}: password_hash/totp_secret 형식이 올바르지 않아 건너뜀', flush=True)
            continue
        try:
            if Account.query.filter_by(email=email).first():
                continue
            db.session.add(Account(email=email, password_hash=password_hash, totp_secret=totp_secret,
                                   totp_enabled=True, role='admin' if dept == 'admin' else 'employee', department=dept))
            db.session.commit()
            created += 1
            print(f'[SEED] {email} 생성 (소속 {dept})', flush=True)
        except Exception as e:
            db.session.rollback()
            print(f'[SEED_FAILED] {email}: {type(e).__name__}', flush=True)
    print(f'[SEED] 새 계정 {created}건', flush=True)


# ==========================================================================
# [DB 최소권한] 앱(로그인 서버)이 쓸 전용 DB 계정을 만든다. 부팅 스크립트(root)가 마스터 계정으로 한 번 실행한다.
#
# 왜: 예전엔 앱이 RDS 마스터 계정으로 접속해서, 앱이 뚫리면(예: SQL 삽입) 테이블 삭제·계정 생성까지 가능했다.
# 무엇을: 앱 계정에는 이 DB의 행 읽기/추가/수정/삭제(SELECT/INSERT/UPDATE/DELETE)만 준다(테이블 생성·변경·삭제 불가).
#        계정 자체에 REQUIRE SSL을 걸어 암호화 안 된 접속을 한 번 더 막고, 접속 가능 위치도 앱 서브넷으로 제한한다.
# 테이블 생성/컬럼 추가/계정 시딩처럼 권한이 더 필요한 일은 전부 이 부팅 단계(bootstrap_database)에서 끝낸다.
# ==========================================================================
_DB_IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,31}$')
_DB_HOST_PATTERN_RE = re.compile(r'^[0-9.%/]{1,64}$')
_DB_PASSWORD_RE = re.compile(r'^[A-Za-z0-9]{16,128}$')


def ensure_app_db_user():
    from sqlalchemy import text
    user = os.environ.get('APP_DB_USER', '')
    password = os.environ.get('APP_DB_PASSWORD', '')
    host = os.environ.get('APP_DB_HOST', '%')
    # 이름/위치/DB 이름은 SQL 문장에 그대로 들어가므로(바인딩 불가) 허용 문자만 통과시킨다. 비밀번호는 바인딩한다.
    if not (_DB_IDENT_RE.match(user) and _DB_PASSWORD_RE.match(password)
            and _DB_HOST_PATTERN_RE.match(host) and _DB_IDENT_RE.match(DB_NAME or '')):
        raise ValueError('APP_DB_USER/APP_DB_PASSWORD/APP_DB_HOST/DB_NAME 형식이 올바르지 않음')
    account = f"`{user}`@'{host}'"
    db.session.execute(text(f"CREATE USER IF NOT EXISTS {account} IDENTIFIED BY :pw REQUIRE SSL"), {"pw": password})
    db.session.execute(text(f"ALTER USER {account} IDENTIFIED BY :pw REQUIRE SSL"), {"pw": password})
    db.session.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON `{DB_NAME}`.* TO {account}"))
    db.session.commit()
    print(f'[BOOTSTRAP] 앱 DB 계정 {user}@{host}: SELECT/INSERT/UPDATE/DELETE, REQUIRE SSL', flush=True)


def bootstrap_database():
    """부팅 스크립트가 마스터 계정으로 한 번 실행: 테이블 생성 -> 컬럼/소속 맞추기 -> 앱 계정 -> 계정 시딩.
    앱 서비스(ztauth)는 이 함수를 부르지 않고, 앱 계정(행 읽기/쓰기만)으로만 접속한다."""
    db.create_all()
    ensure_department_schema()
    ensure_app_db_user()
    seed_accounts_from_ssm()


PDP_EVALUATE_URL = os.environ.get('PDP_EVALUATE_URL')
EVALUATE_SHARED_SECRET = os.environ.get('EVALUATE_SHARED_SECRET')


# [로그인 평가 구분] 예전엔 자원/출처/시각 없이 보내서 관리자 로그에 "자원 unknown, 출처 A(Access와 혼동),
# 밤인데도 0점"으로 찍혔다. 이제 출처는 login, 자원은 이 로그인 서버의 주소, 시각은 지금(UTC)을 함께 보낸다.
# 자원(auth.xmcda.store/authorize)은 엔진 등급표에 없으므로 임계값은 예전과 같은 기본값(40)이 적용된다.
def evaluate_login_risk(identity, signals):
    login_host = os.environ.get('DOMAIN_NAME', 'auth.xmcda.store')
    try:
        resp = requests.post(
            PDP_EVALUATE_URL,
            headers={
                "Content-Type": "application/json",
                "X-Evaluate-Secret": EVALUATE_SHARED_SECRET,
            },
            json={
                "identity": identity,
                "session_id": str(uuid.uuid4()),
                "source": "login",
                "resource_path": f"{login_host}/authorize",
                "request_timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                # 접속 IP(Cloudflare가 넣는 CF-Connecting-IP): 엔진이 IP 평판(AbuseIPDB)을 본다
                "client_ip": request.headers.get('CF-Connecting-IP') if has_request_context() else None,
                **signals,
            },
            timeout=3,
        )
        return resp.json()
    except Exception as e:
        print("Lambda 위험점수 평가 실패, fail-closed 처리:", str(e))
        return {"allow": False, "action": "lambda_call_failed"}


# [WAF] 예전에는 로그인 폼 입력값을 정규식으로 검사해 waf_sqli를 기록했다. 이제 로그인 서버 앞 nginx의
# ModSecurity + OWASP CRS가 이 요청을 검사하고 막는다(user_data_web.sh.tpl). 정규식을 뺀 이유:
#   1) ';', '--', 작은따옴표가 들어간 정상 비밀번호까지 막았다(예: "abc;123").
#   2) 로그인 전이라 입력한 이메일이 본인 것인지 모르는데, 그 이메일 이름으로 공격 기록을 남겼다(남의 이메일을 적으면 그 사람 기록이 됨).
#   3) CRS는 libinjection 기반 탐지 등 검증된 규칙 묶음이라 정규식 한 줄보다 탐지 범위가 넓다.
# 로그인 전 공격은 신원이 없으므로 WAF가 막기만 하고, 사람에게 위험을 거는 연결은 로그인한 요청(앱)에서만 한다(zt_waf.py).


_rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWT_PRIVATE_KEY = _rsa_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
JWT_PUBLIC_NUMBERS = _rsa_key.public_key().public_numbers()
JWT_KID = "zt-login-server-key-1"

OIDC_ISSUER = f"https://{os.environ.get('DOMAIN_NAME', 'auth.xmcda.store')}"

OIDC_CLIENT_ID = os.environ.get('OIDC_CLIENT_ID')
OIDC_CLIENT_SECRET = os.environ.get('OIDC_CLIENT_SECRET')


def _get_client_credentials():
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Basic '):
        try:
            import base64
            decoded = base64.b64decode(auth_header[len('Basic '):]).decode('utf-8')
            client_id, _, client_secret = decoded.partition(':')
            return client_id, client_secret
        except Exception:
            return None, None
    return request.form.get('client_id'), request.form.get('client_secret')


AUTH_CODES = {}
ACCESS_TOKENS = {}
PENDING_LOGINS = {}

SSO_SESSIONS = {}
SSO_COOKIE_NAME = 'sso_session'
SSO_SESSION_SECONDS = 8 * 3600


# [SSO 세션] 절대 만료 8시간(NIST SP 800-63B AAL2 상한 12시간 이내) + 무활동 30분(AAL2 기준 30분).
# 무활동은 "이 서버가 SSO 쿠키를 마지막으로 확인한 시각"으로 잰다. Access 세션이 15분마다 갱신되며 이 서버로
# 오기 때문에, 계속 쓰는 사용자는 15분마다 시각이 갱신되고 30분 넘게 안 쓴 사용자는 만료된다(정밀한 요청 단위는 아님).
SSO_IDLE_SECONDS = 30 * 60


def create_sso_session(email):
    token = secrets.token_urlsafe(32)
    now = time.time()
    SSO_SESSIONS[token] = {"email": email, "expires_at": now + SSO_SESSION_SECONDS, "last_seen": now}
    return token


def get_sso_session_email(token):
    entry = SSO_SESSIONS.get(token)
    now = time.time()
    if not entry or entry["expires_at"] < now or now - entry.get("last_seen", now) > SSO_IDLE_SECONDS:
        SSO_SESSIONS.pop(token, None)
        return None
    entry["last_seen"] = now
    return entry["email"]


def clear_sso_sessions_for(email):
    """비밀번호 변경 뒤 그 사용자의 기존 SSO 세션을 모두 끊는다(OWASP: 비밀번호 변경 후 세션 무효화)."""
    for t in [t for t, e in SSO_SESSIONS.items() if e["email"] == email]:
        SSO_SESSIONS.pop(t, None)


def clear_sso_session(token):
    SSO_SESSIONS.pop(token, None)


# [잠금 정책] 5분 안에 5번 실패하면 잠금. 15분에서 5분으로 단축(팀 판단, 표준값 아님).
# 창(윈도우) 자체를 5분으로 줄였기 때문에, 계속 틀리지만 않으면 마지막 실패로부터
# 5분이 지나는 순간 자동으로 풀림(별도 "잠금 해제 시각"을 안 둬도 됨).
BRUTE_FORCE_WINDOW_MINUTES = 5
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_LOCKOUT_MINUTES = BRUTE_FORCE_WINDOW_MINUTES  # 안내 문구용


def check_brute_force(email):
    from datetime import datetime, timedelta
    window_start = datetime.utcnow() - timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
    recent_failures = LoginFailure.query.filter(
        LoginFailure.email == email,
        LoginFailure.attempted_at >= window_start,
    ).count()
    return recent_failures >= BRUTE_FORCE_THRESHOLD


# [pwned_password] 유출 비밀번호 검사 (NIST SP 800-63B 5.1.1.2: 설정/변경 시 유출 목록 대조).
# HIBP k-anonymity: SHA-1 앞 5자리만 전송, 나머지는 응답 목록에서 로컬 비교(비번/전체 해시는 외부로 안 나감).
# Add-Padding 응답의 가짜 항목(count 0)은 무시. 조회 실패는 fail-open(로그인 가용성 우선) + 로그.
PWNED_MIN_LEN = 12


def pwned_count(pw):
    try:
        h = hashlib.sha1(pw.encode('utf-8')).hexdigest().upper()
        r = requests.get("https://api.pwnedpasswords.com/range/" + h[:5],
                         headers={"Add-Padding": "true"}, timeout=2)
        r.raise_for_status()
        for line in r.text.splitlines():
            suf, _, cnt = line.partition(':')
            if hmac.compare_digest(suf.strip(), h[5:]):
                return int(cnt.strip() or 0)
        return 0
    except Exception as e:
        print(f"[PWNED_CHECK_FAILED] {type(e).__name__}", flush=True)
        return None


def finalize_login(email, client_id, redirect_uri, state, response_type, scope, totp_ok):
    brute_force_flag = check_brute_force(email)
    # [정리] 예전에는 여기서 night_access를 직접 계산(UTC 0~4시 = 한국 낮 9~14시라 반대로
    # 동작하는 오류가 있었음)했으나, 야간 판정은 Lambda가 요청 시각(KST 22~06시)으로
    # 전담하는 구조(PDP 일원화)이므로 로그인 서버는 자기만 아는 신호(brute_force)만 보낸다.
    signals = {
        "brute_force": brute_force_flag,
    }
    risk_result = evaluate_login_risk(email, {**signals, "security_mfa_passed": totp_ok})

    if not risk_result.get("allow", False):
        print(f"[LOGIN_BLOCKED] identity={email} action={risk_result.get('action')}", flush=True)
        log_event("login_blocked", identity=email, action=risk_result.get('action'), score=risk_result.get('score'),
                  reasons=risk_result.get('reasons'))
        return render_credentials_form(
            client_id, redirect_uri, state, response_type, scope,
            # 내부 판단 이름(block_until_mfa 등)은 화면에 쓰지 않는다(공격자에게 판단 기준을 알려 주지 않음, 사용자에게는 의미 없음)
            error="보안 정책에 따라 지금은 로그인할 수 없습니다. 계속되면 보안 관리자에게 문의하세요."
        )

    print(f"[LOGIN_ALLOWED] identity={email} totp_ok={totp_ok} (SSO 재사용이면 totp 재입력 없이도 위험판단은 여기서 매번 실행됨)", flush=True)
    log_event("login_allowed", identity=email, totp_ok=totp_ok, score=risk_result.get('score'))

    auth_code = secrets.token_urlsafe(32)
    AUTH_CODES[auth_code] = {"email": email, "expires_at": time.time() + 60}

    response = make_response(redirect(f"{redirect_uri}?code={auth_code}&state={state}"))
    sso_token = create_sso_session(email)
    response.set_cookie(
        SSO_COOKIE_NAME, sso_token,
        max_age=SSO_SESSION_SECONDS,
        httponly=True,
        secure=True,
        samesite='Lax',
    )
    return response


def render_credentials_form(client_id, redirect_uri, state, response_type, scope, error=None, notice=None):
    """1단계: 이메일 + 비밀번호. 요청에서 온 값(client_id 등)은 모두 이스케이프한다(예전엔 그대로 넣어 반사형 XSS 가능)."""
    msg = (alert("error", error) if error else "") + (alert("ok", notice) if notice else "")
    hidden = "".join(f'<input type="hidden" name="{n}" value="{esc(v)}">' for n, v in (
        ("client_id", client_id), ("redirect_uri", redirect_uri), ("state", state),
        ("response_type", response_type), ("scope", scope)))
    body = f"""{msg}
    <form method="POST" action="/authorize" autocomplete="on">{hidden}
      <label class="field-label" for="email">회사 이메일</label>
      <input class="uline" id="email" type="email" name="email" placeholder="name@xmcda.store" autocomplete="username" required autofocus>
      <label class="field-label" for="pw">비밀번호</label>
      <input class="uline" id="pw" type="password" name="password" autocomplete="current-password" required>
      <div class="auth-actions"><span class="small muted">비밀번호 분실 시 보안 관리자에게 문의</span>
        <button class="btn btn-primary" type="submit">다음</button></div>
    </form>"""
    return auth_page("로그인", "로그인", body, subtitle="회사 계정을 입력하세요")


def render_change_form(challenge_id, error=None):
    """유출 목록에 있는 비밀번호: 2단계 인증 뒤 새 비밀번호 설정(NIST SP 800-63B: 길이 기준, 구성 규칙 강요 없음)."""
    msg = alert("error", error) if error else ""
    body = f"""{alert("warn", "지금 비밀번호가 외부 유출 목록에서 발견되었습니다. 계속하려면 새 비밀번호를 설정해야 합니다.")}{msg}
    <form method="POST" action="/authorize/change-password">
      <input type="hidden" name="challenge_id" value="{esc(challenge_id)}">
      <label class="field-label" for="npw">새 비밀번호</label>
      <input class="uline" id="npw" type="password" name="new_password" autocomplete="new-password" minlength="{PWNED_MIN_LEN}" required autofocus>
      <p class="hint">{PWNED_MIN_LEN}자 이상. 문장처럼 길게 만들면 기억하기 쉽고 안전합니다(특수문자 조합 규칙 없음).</p>
      <label class="field-label" for="cpw">새 비밀번호 확인</label>
      <input class="uline" id="cpw" type="password" name="confirm_password" autocomplete="new-password" required>
      <div class="auth-actions"><span></span><button class="btn btn-primary" type="submit">변경</button></div>
    </form>"""
    return auth_page("비밀번호 변경", "비밀번호를 변경해 주세요", body)


def render_totp_form(challenge_id, error=None):
    """2단계: 인증 앱 6자리 코드(또는 백업 코드)."""
    msg = alert("error", error) if error else ""
    portal_domain = os.environ.get('DOMAIN_NAME', 'auth.xmcda.store').replace('auth.', '')
    body = f"""{msg}
    <form method="POST" action="/authorize/verify-totp">
      <input type="hidden" name="challenge_id" value="{esc(challenge_id)}">
      <label class="field-label" for="code">인증 코드</label>
      <input class="uline code" id="code" type="text" name="totp_code" inputmode="numeric" autocomplete="one-time-code"
             maxlength="32" placeholder="000000" required autofocus>
      <p class="hint">휴대폰을 쓸 수 없으면 백업 코드를 입력하세요.</p>
      <div class="auth-actions"><a href="https://{esc(portal_domain)}/">처음부터 다시</a>
        <button class="btn btn-primary" type="submit">로그인</button></div>
    </form>"""
    return auth_page("2단계 인증", "2단계 인증", body, subtitle="인증 앱에 표시된 6자리 코드를 입력하세요")


@app.after_request
def security_headers(resp):
    """로그인 화면 공통 보안 헤더: 다른 사이트가 이 화면을 틀(iframe) 안에 넣어 속이는 것(클릭재킹) 방지,
    파일 형식 추측 방지, 로그인 화면을 브라우저/중간 서버가 저장하지 않게 함."""
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    if resp.mimetype == "text/html":
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.route('/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'GET':
        client_id = request.args.get('client_id', '')
        redirect_uri = request.args.get('redirect_uri', '')
        state = request.args.get('state', '')
        response_type = request.args.get('response_type', 'code')
        scope = request.args.get('scope', 'openid')

        sso_token = request.cookies.get(SSO_COOKIE_NAME)
        sso_email = get_sso_session_email(sso_token) if sso_token else None
        if sso_email:
            # [보안수정] 기존에는 SSO 세션이 살아있으면 무조건 totp_ok=True로 처리해서,
            # brute_force(무차별 대입 의심)가 걸린 계정도 TOTP를 실제로 다시 입력하지 않고
            # 페이지 접속만으로 위험도가 리셋되는 구멍이 있었음. brute_force는 "진짜 주인이
            # TOTP로 증명해야만 풀리는" 신호이므로, 이 경우엔 SSO 재사용을 막고
            # 비밀번호+TOTP를 처음부터 다시 입력하게 한다.
            if check_brute_force(sso_email):
                clear_sso_session(sso_token)
                response = make_response(render_credentials_form(
                    client_id, redirect_uri, state, response_type, scope,
                    error="보안상 재인증이 필요합니다. 비밀번호와 2단계 인증을 다시 입력해주세요."
                ))
                response.delete_cookie(SSO_COOKIE_NAME)
                return response
            # brute_force가 없으면 SSO 재사용은 그대로 허용하되, 이번 접속에서 TOTP를
            # 실제로 입력한 게 아니므로 totp_ok는 False로 정직하게 전달한다.
            return finalize_login(sso_email, client_id, redirect_uri, state, response_type, scope, totp_ok=False)

        return render_credentials_form(client_id, redirect_uri, state, response_type, scope)

    client_id = request.form.get('client_id', '')
    redirect_uri = request.form.get('redirect_uri', '')
    state = request.form.get('state', '')
    response_type = request.form.get('response_type', 'code')
    scope = request.form.get('scope', 'openid')

    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    client_ip = request.headers.get('CF-Connecting-IP', request.remote_addr)

    # [잠금 먼저 확인] 잠긴 계정은 비밀번호를 확인하지 않고 같은 잠금 화면을 보여 준다.
    # 예전에는 비밀번호를 먼저 확인하고 "맞았을 때만" 잠금 화면을 보여 줘서, 공격자가 "잠금 화면이 뜨면 비밀번호가 맞은 것"으로
    # 정답을 알아낼 수 있었다(비밀번호 확인 신호 노출). 틀린 비밀번호만 넣는 사람에게는 잠금 안내도 뜨지 않았다(실측).
    # 잠긴 동안의 시도는 실패로 더 세지 않는다(잠금이 끝없이 늘어나지 않게, 5분 창이 지나면 풀림).
    # 존재하지 않는 이메일도 똑같이 처리한다(계정이 있는지 알려 주지 않음).
    if check_brute_force(email):
        log_event("login_locked", identity=email, stage="login", window_min=BRUTE_FORCE_WINDOW_MINUTES, threshold=BRUTE_FORCE_THRESHOLD)
        return render_credentials_form(
            client_id, redirect_uri, state, response_type, scope,
            error=f"로그인 시도가 너무 많습니다. {BRUTE_FORCE_LOCKOUT_MINUTES}분 후 다시 시도해주세요."
        )

    account = Account.query.filter_by(email=email).first()
    credentials_ok = bool(account) and check_password_hash(account.password_hash, password)

    if not credentials_ok:
        db.session.add(LoginFailure(email=email, ip_address=client_ip))
        db.session.commit()
        # 계정이 있는지 여부는 남기지 않는다(로그를 보는 사람에게도 계정 존재 여부를 알려 주지 않음)
        log_event("login_failed", identity=email, stage="password")
        return render_credentials_form(
            client_id, redirect_uri, state, response_type, scope,
            error="이메일 또는 비밀번호가 올바르지 않습니다."
        )

    # (잠금 확인은 위로 옮겼다: 비밀번호가 맞든 틀리든 잠긴 계정이면 TOTP 화면까지 가지 않는다 - Microsoft Entra ID 등 lockout 방식)

    # [pwned_password] 유출 목록에 있으면 즉시 차단하지 않고, TOTP 통과 후 새 비밀번호를 강제한다
    # (비번만 아는 공격자는 변경 화면에 도달 못함). 평문은 저장하지 않고 플래그만 둔다.
    # user_risk에는 기록하지 않음(비번을 바꾸면 해소되는 상태라 sticky 신호가 아님).
    pwned = (pwned_count(password) or 0) > 0
    if pwned:
        print(f"[PWNED_DETECTED] identity={email}", flush=True)
        log_event("pwned_password_detected", identity=email)

    if not account.totp_enabled and not pwned:
        return finalize_login(email, client_id, redirect_uri, state, response_type, scope, totp_ok=True)

    challenge_id = secrets.token_urlsafe(24)
    PENDING_LOGINS[challenge_id] = {
        "must_change": pwned,
        "totp_verified": False,
        "email": email,
        "expires_at": time.time() + 300,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "response_type": response_type,
        "scope": scope,
    }
    if not account.totp_enabled:  # TOTP 없는 계정: 비번 자체가 유일한 증명이므로 바로 변경 화면
        PENDING_LOGINS[challenge_id]["totp_verified"] = True
        return render_change_form(challenge_id)
    return render_totp_form(challenge_id)



@app.route('/authorize/verify-totp', methods=['POST'])
def authorize_verify_totp():
    challenge_id = request.form.get('challenge_id', '')
    totp_input = request.form.get('totp_code', '').strip()

    entry = PENDING_LOGINS.get(challenge_id)
    if not entry or entry["expires_at"] < time.time():
        PENDING_LOGINS.pop(challenge_id, None)
        return render_credentials_form(
            '', '', '', 'code', 'openid',
            error="로그인 세션이 만료되었습니다. 처음부터 다시 시도해주세요."
        )

    email = entry["email"]
    # [잠금] 로그인 2단계(TOTP)도 같은 잠금을 따른다. 예전에는 이 단계의 실패를 세지 않아, 비밀번호를 아는 공격자가
    # 5분 동안 TOTP를 제한 없이 넣어 볼 수 있었다(재인증 /stepup은 이미 세고 있었음).
    if check_brute_force(email):
        PENDING_LOGINS.pop(challenge_id, None)
        log_event("login_locked", identity=email, stage="totp", window_min=BRUTE_FORCE_WINDOW_MINUTES, threshold=BRUTE_FORCE_THRESHOLD)
        return render_credentials_form(
            entry["client_id"], entry["redirect_uri"], entry["state"], entry["response_type"], entry["scope"],
            error=f"로그인 시도가 너무 많습니다. {BRUTE_FORCE_LOCKOUT_MINUTES}분 후 다시 시도해주세요."
        )
    account = Account.query.filter_by(email=email).first()

    totp_ok = False
    if account and account.totp_secret and pyotp.TOTP(account.totp_secret).verify(totp_input, valid_window=1):
        totp_ok = True
    elif account:
        for bc in BackupCode.query.filter_by(account_id=account.id, used=False).all():
            if check_password_hash(bc.code_hash, totp_input):
                bc.used = True
                db.session.commit()
                totp_ok = True
                break

    if not totp_ok:
        db.session.add(LoginFailure(email=email, ip_address=request.headers.get('CF-Connecting-IP', request.remote_addr)))
        db.session.commit()
        log_event("login_failed", identity=email, stage="totp")
        return render_totp_form(challenge_id, error="TOTP 코드(또는 백업코드)가 올바르지 않습니다.")

    if entry.get("must_change"):
        entry["totp_verified"] = True
        entry["expires_at"] = time.time() + 300
        return render_change_form(challenge_id)

    PENDING_LOGINS.pop(challenge_id, None)
    return finalize_login(
        email, entry["client_id"], entry["redirect_uri"], entry["state"],
        entry["response_type"], entry["scope"], totp_ok=True,
    )


@app.route('/authorize/change-password', methods=['POST'])
def authorize_change_password():
    challenge_id = request.form.get('challenge_id', '')
    new_pw = request.form.get('new_password', '')
    entry = PENDING_LOGINS.get(challenge_id)
    if (not entry or entry["expires_at"] < time.time()
            or not entry.get("must_change") or not entry.get("totp_verified")):
        PENDING_LOGINS.pop(challenge_id, None)
        return render_credentials_form(
            '', '', '', 'code', 'openid',
            error="로그인 세션이 만료되었습니다. 처음부터 다시 시도해주세요."
        )
    account = Account.query.filter_by(email=entry["email"]).first()
    err = None
    if not account:
        err = "계정을 찾을 수 없습니다."
    elif len(new_pw) < PWNED_MIN_LEN:
        err = f"비밀번호는 {PWNED_MIN_LEN}자 이상이어야 합니다."
    elif new_pw != request.form.get('confirm_password', ''):
        err = "새 비밀번호 확인이 일치하지 않습니다."
    elif check_password_hash(account.password_hash, new_pw):
        err = "이전 비밀번호와 같은 값은 사용할 수 없습니다."
    elif (pwned_count(new_pw) or 0) > 0:
        err = "이 비밀번호도 유출 목록에서 발견되었습니다. 다른 비밀번호를 사용해주세요."
    if err:
        return render_change_form(challenge_id, error=err)

    account.password_hash = generate_password_hash(new_pw)
    db.session.commit()
    PENDING_LOGINS.pop(challenge_id, None)
    clear_sso_sessions_for(entry["email"])
    print(f"[PASSWORD_CHANGED] identity={entry['email']} reason=pwned", flush=True)
    log_event("password_changed", identity=entry['email'], reason="pwned")
    # [재로그인] 변경 직후 자동 로그인하지 않고 새 비밀번호로 다시 로그인하게 한다(OWASP Forgot Password
    # Cheat Sheet: 새 비밀번호 설정 뒤 일반 로그인 절차를 거치게 함). 기존 SSO 세션도 위에서 모두 끊었다.
    return render_credentials_form(
        entry["client_id"], entry["redirect_uri"], entry["state"], entry["response_type"], entry["scope"],
        notice="비밀번호가 변경되었습니다. 새 비밀번호로 다시 로그인해주세요.",
    )


# [step-up 재인증] Access가 경계구간(위험점수는 애매한데 완전 차단은 아닌 구간)에서
# 막았을 때 안내되는 재인증 전용 페이지. 비밀번호는 다시 안 묻고(이미 로그인된 사람이
# 맞다는 전제) TOTP만 다시 확인한다. 통과하면 Lambda에 "방금 MFA했다"를 기록해서,
# 이후 몇 분간(MFA_FRESHNESS_SECONDS, risk_score_engine.py에서 관리) 경계구간을
# 다시 걸리지 않고 통과하게 한다.
#
# [미확인] Cloudflare Access의 거부 화면이 실제로 이 페이지로 안내(리다이렉트)하는지는
# main.tf의 커스텀 거부 URL 설정에 달려있고, External Evaluation 거부에도 그 설정이
# 적용되는지 문서로 확인되지 않아 직접 테스트가 필요함. 안 되더라도 이 주소를 알고
# 있으면 수동으로 접속해 재인증할 수 있음.
def render_stepup_form(return_url, error=None, locked=False):
    """위험도가 경계 구간일 때 비밀번호 없이 2단계 인증만 다시 확인한다. 왜 요청하는지(판단 기준)는 화면에 쓰지 않는다."""
    msg = alert("error", error) if error else ""
    disabled = "disabled" if locked else ""
    host = urlparse(return_url).hostname or ""
    target = (f'<div class="auth-meta">{icon("globe", 16)}<span>접속하려는 서비스 <b>{esc(host)}</b></span></div>'
              if host else "")
    body = f"""{target}{msg}
    <form method="POST" action="/stepup">
      <input type="hidden" name="return_url" value="{esc(return_url)}">
      <label class="field-label" for="code">인증 코드</label>
      <input class="uline code" id="code" type="text" name="totp_code" inputmode="numeric" autocomplete="one-time-code"
             maxlength="32" placeholder="000000" required autofocus {disabled}>
      <div class="auth-actions"><a href="/logout">다른 계정으로 로그인</a>
        <button class="btn btn-primary" type="submit" {disabled}>확인</button></div>
    </form>"""
    return auth_page("추가 인증", "본인 확인", body, subtitle="보안을 위해 인증 앱의 코드를 한 번 더 입력해 주세요")


def render_stepup_success(return_url):
    """재인증 성공 -> 잠시 후 원래 서비스로 이동(복귀 주소는 _safe_return_url로 검증된 값만 들어온다)."""
    body = f"""<div class="spinner"></div>
      {link_button(return_url, "지금 이동", "secondary", "arrow-right", block=True)}
    <script>setTimeout(function(){{window.location.href={json.dumps(return_url)};}},1200);</script>"""
    return auth_page("인증 완료", "인증되었습니다", body, subtitle="잠시 후 원래 접속하려던 서비스로 이동합니다", badge="check", tone="ok")


# [기능추가] Access의 커스텀 거부 URL 리다이렉트에는 ?original_url=(원래 가려던 주소)가
# 실려오는 것이 실제로 관찰됐지만 Cloudflare 문서에는 정의돼 있지 않다. 그래서 이 값은 규격이
# 아니라 "관찰된 동작"으로만 쓰고(_original_url_candidate), 없으면 브라우저가 이
# 페이지로 넘어오기 직전 있었던 곳(Referer 헤더)을 근거로 추정한다. 확실한 값은 아니라서
# 우리가 아는 앱 호스트(_app_hosts)에 해당할 때만 그리로 보내고, 그 외에는 항상
# 안전한 기본값(포털 홈)으로 보낸다.
def _app_hosts():
    """보호 대상 앱 호스트 목록(Terraform locals.app_hosts -> 환경변수 APP_HOSTS, 쉼표 구분).
    복귀 주소 허용 목록과 로그아웃할 앱 목록으로 쓴다. 값이 없으면 기본 구성(포털+dev/marketing/hr/admin)을 쓴다."""
    portal_domain = os.environ.get('DOMAIN_NAME', 'auth.xmcda.store').replace('auth.', '')
    raw = os.environ.get('APP_HOSTS', '')
    # 호스트 이름에 쓸 수 있는 문자만 허용(이 값은 HTML 속성/로그아웃 주소에 그대로 들어간다)
    hosts = [h.strip().lower() for h in raw.split(',') if re.fullmatch(r'[A-Za-z0-9.-]+', h.strip())]
    return hosts or [portal_domain] + [f'{p}.{portal_domain}' for p in ('dev', 'marketing', 'hr', 'admin')]


def _safe_return_url(candidate):
    """사용자가 넘긴 복귀 주소(쿼리스트링 return_url, 폼의 hidden 값)를 검증한다.
    이 값은 HTML 속성과 JS 문자열, window.location에 그대로 들어가므로, 검증 없이 쓰면
    (1) 아무 외부 사이트로 보내는 open redirect, (2) 따옴표를 섞은 값으로 스크립트가 끼어드는
    XSS가 가능해진다. 우리 앱 호스트(_app_hosts)의 https 주소이고 위험 문자가
    없을 때만 통과시키고, 아니면 None을 돌려 호출한 쪽이 안전한 기본값을 쓰게 한다."""
    if not candidate:
        return None
    portal_domain = os.environ.get('DOMAIN_NAME', 'auth.xmcda.store').replace('auth.', '')
    if any(ch in candidate for ch in '"\'<>\\ `\r\n\t'):
        return None
    try:
        parsed = urlparse(candidate)
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme != 'https' or port is not None or parsed.username or parsed.password:
        return None
    if (parsed.hostname or '').lower() not in _app_hosts():
        return None
    return candidate


def _original_url_candidate(raw):
    """Access가 커스텀 거부 URL로 보낼 때 붙여주는 ?original_url=dev.xmcda.store/ 를 읽는다.
    실제 리다이렉트 URL에서 관찰한 값이며 Cloudflare 문서에는 정의돼 있지 않다(그래서 규격으로
    믿지 않고, 없거나 이상하면 아래 Referer/기본값으로 그대로 넘어간다). 관찰된 값에는
    https://가 없으므로 붙여 주되, 최종 통과 여부는 반드시 _safe_return_url(우리 도메인
    allowlist, https만, 포트/계정정보/위험문자 거부)이 결정한다."""
    if not raw:
        return None
    raw = raw.strip()
    if '://' not in raw:
        raw = 'https://' + raw
    return _safe_return_url(raw)


# [접근 권한 안내] Cloudflare Access가 "소속이 달라서" 막은 경우와 "위험도 때문에 추가 인증이 필요해서"
# 막은 경우 모두 이 서버의 /stepup으로 보낸다(자원 하나에 거부 주소를 하나만 쓸 수 있음). 둘을 구분하지 않으면
# 권한이 없는 사람에게 TOTP를 묻고, 인증해도 같은 곳에서 또 막히는 헛걸음이 생긴다. 그래서 /stepup이
# "이 사람의 소속(DB)이 가려던 자원의 허용 소속(Terraform이 환경변수로 넘긴 표)에 드는지"를 먼저 본다.
#
# 이 표는 안내 화면을 고르는 용도일 뿐 접근을 허용하지 않는다. 실제 허용/차단은 Cloudflare Access 정책과
# nginx 앞단 판단 서비스가 하므로, 표가 없거나 틀려도 권한이 새지 않는다(최악의 경우 안내 화면이 달라질 뿐).
# 형식: "호스트=소속,소속;호스트=소속" (예: dev.xmcda.store=dev;hr.xmcda.store=hr). 포털은 표에 없음 = 제한 없음.
def _parse_path_permissions(raw):
    perms = {}
    for item in (raw or '').split(';'):
        key, sep, depts = item.strip().partition('=')
        if not sep or not key.strip():
            continue
        perms[key.strip()] = [d.strip() for d in depts.split(',') if d.strip()]
    return perms


PATH_PERMISSIONS = _parse_path_permissions(os.environ.get('PATH_PERMISSIONS'))


def _resource_key(url):
    """복귀 주소가 어느 자원인지 = 호스트(예: 'hr.xmcda.store'). 앱마다 서브도메인이 따로라 호스트가 곧 자원이다."""
    return (urlparse(url).hostname or '').lower()


def check_department_access(department, url):
    """True=소속이 허용 목록에 있음, False=없음, None=이 자원은 권한표에 없어서 판단 불가(기존 흐름대로 진행)."""
    allowed = PATH_PERMISSIONS.get(_resource_key(url))
    if allowed is None:
        return None
    return (department or '') in allowed


def render_no_permission(email, department, url):
    portal_domain = os.environ.get('DOMAIN_NAME', 'auth.xmcda.store').replace('auth.', '')
    needed = ', '.join(PATH_PERMISSIONS.get(_resource_key(url), [])) or '-'
    body = f"""<dl class="kv">
      <dt>로그인한 계정</dt><dd>{esc(email)}</dd>
      <dt>계정의 소속</dt><dd>{esc(department or '(지정되지 않음)')}</dd>
      <dt>필요한 소속</dt><dd>{esc(needed)}</dd>
    </dl>
    {alert("info", "업무상 필요하다면 소속 부서장을 통해 보안 관리자에게 권한을 요청하세요.")}
    <div class="btn-row">{link_button(f"https://{portal_domain}/", "포털 홈으로", "primary", "home")}
    {link_button("/logout", "다른 계정으로 로그인", "secondary", "logout")}</div>"""
    return auth_page("접근 권한 없음", "접근 권한이 없습니다", body,
                     subtitle="이 계정의 소속으로는 요청한 서비스를 열 수 없습니다. 추가 인증으로 해결되는 문제가 아닙니다.",
                     badge="lock", tone="danger", wide=True)


# [차단 화면] Access가 막으면 이유와 상관없이 /stepup으로 오기 때문에, 재인증으로 풀리지 않는 차단에도
# TOTP 화면을 보여주면 "재인증 -> 다시 차단 -> 재인증"이 반복된다. 판단은 엔진이 했으니 엔진에 마지막 판단을
# 물어(decision_lookup) 차단이면 차단 화면을 보여준다. 사용자가 직접 고칠 수 있는 기기 사유만 보여주고,
# 점수나 다른 신호(위치 등)는 보여주지 않는다(공격자에게 무엇을 피하면 되는지 알려주지 않기 위해).
# block_until_mfa: 보안 신호(관리자 해제 대상)가 걸린 상태. 앱 접근 단계에서는 재인증으로 풀리지 않으므로 차단 화면.
BLOCK_ACTIONS = ("block", "block_device", "block_until_mfa", "session_reauth_required")
DEVICE_HELP = {
    "device_unmanaged": ("회사에 등록된 기기가 아닙니다.",
                         "본인 계정으로 Cloudflare One Client(WARP)를 등록하고 연결한 기기에서 다시 접속하세요."),
    "device_owner_mismatch": ("다른 사람 계정으로 등록된 기기입니다.", "본인 계정으로 등록된 기기에서 접속하세요."),
    "device_posture_failed": ("기기 보안 검사(Windows 방화벽)를 통과하지 못했습니다.",
                              "Windows 방화벽을 켜고 몇 분 뒤 다시 시도하세요(기기 검사가 몇 분마다 돌아서 바로 반영되지 않습니다)."),
}


def lookup_access_decision(email, return_url):
    """엔진에 이 사용자+앱의 마지막 판단을 묻는다. 실패하면 found=False(기존처럼 재인증 화면)."""
    try:
        resp = requests.post(PDP_EVALUATE_URL, timeout=3,
                             headers={"Content-Type": "application/json", "X-Evaluate-Secret": EVALUATE_SHARED_SECRET},
                             json={"decision_lookup": True, "identity": email,
                                   "resource_host": (urlparse(return_url).hostname or "")})
        result = resp.json()
        return result if isinstance(result, dict) else {"found": False}
    except Exception as e:
        print("마지막 판단 조회 실패:", str(e), flush=True)
        return {"found": False}


def render_blocked(email, return_url, device_reasons, reauth=False):
    """엔진이 차단한 요청. 사용자가 직접 고칠 수 있는 기기 사유만 보여 주고, 점수/다른 신호(위치 등)는 보여 주지 않는다
    (공격자에게 무엇을 피하면 되는지 알려 주지 않기 위해)."""
    portal_domain = os.environ.get('DOMAIN_NAME', 'auth.xmcda.store').replace('auth.', '')
    account = f'<div class="auth-meta">{icon("user", 16)}<span>{esc(email)}</span></div>'
    actions = (f'<div class="btn-row">{link_button(f"https://{portal_domain}/", "포털 홈으로", "secondary", "home")}'
               f'{link_button("/logout", "다른 계정으로 로그인", "secondary", "logout")}</div>')
    if reauth:
        # 세션 바인딩 위반: 이유(위치가 바뀜)를 쓰지 않는다 - 쿠키를 훔친 사람에게 "같은 나라에서 쓰면 된다"는 힌트가 됨
        body = f'{account}{link_button("/logout", "로그아웃 후 다시 로그인", "primary", "logout", block=True)}'
        return auth_page("다시 로그인 필요", "다시 로그인해 주세요", body,
                         subtitle="보안을 위해 현재 세션이 종료되었습니다. 로그아웃한 뒤 다시 로그인해 주세요.",
                         badge="shield", tone="warn", wide=True)
    items = "".join(f'<div class="reason">{icon("device", 20)}<div><b>{esc(DEVICE_HELP[r][0])}</b><p>{esc(DEVICE_HELP[r][1])}</p></div></div>'
                    for r in device_reasons if r in DEVICE_HELP)
    if items:
        body = (f'{account}{items}<div style="height:8px"></div>'
                f'{link_button(return_url, "다시 시도", "primary", "arrow-right", block=True)}<div style="height:10px"></div>{actions}')
        return auth_page("기기 확인 필요", "기기 보안 요건을 충족하지 않습니다", body,
                         subtitle="이 기기에서는 요청한 서비스를 열 수 없습니다. 아래 내용을 확인한 뒤 다시 시도하세요.",
                         badge="device", tone="warn", wide=True)
    body = f'{account}{actions}'
    return auth_page("접근 차단", "접근이 차단되었습니다", body,
                     subtitle="보안 정책에 따라 접근이 차단되었습니다. 계속되면 보안 관리자에게 문의하세요.",
                     badge="block", tone="danger", wide=True)


def _blocked_response(email, return_url):
    """엔진의 마지막 판단이 차단이면 차단 화면(403)을, 아니면 None(재인증 화면으로 진행)."""
    decision = lookup_access_decision(email, return_url)
    if decision.get("found") and decision.get("action") == "session_reauth_required":
        # 출입증이 로그인한 나라와 다른 곳에서 쓰이는 중: TOTP가 아니라 처음부터 다시 로그인해야 풀린다
        print(f"[STEPUP_BLOCKED] identity={email} action=session_reauth_required resource={_resource_key(return_url)}", flush=True)
        log_event("stepup_blocked", identity=email, action="session_reauth_required", resource=_resource_key(return_url))
        return render_blocked(email, return_url, [], reauth=True), 403
    if decision.get("found") and decision.get("action") in BLOCK_ACTIONS:
        reasons = [r for r in (decision.get("device_reasons") or []) if r in DEVICE_HELP]
        print(f"[STEPUP_BLOCKED] identity={email} action={decision.get('action')} device={','.join(reasons) or '-'} "
              f"resource={_resource_key(return_url)}", flush=True)
        log_event("stepup_blocked", identity=email, action=decision.get('action'), device_reasons=reasons,
                  resource=_resource_key(return_url))
        return render_blocked(email, return_url, reasons), 403
    return None


def _no_permission_response(account, email, return_url):
    """소속이 이 자원의 허용 목록에 없으면 403 안내 화면을, 아니면 None을 돌려준다."""
    department = account.department if account else None
    if check_department_access(department, return_url) is False:
        print(f"[STEPUP_NO_PERMISSION] identity={email} department={department or '-'} resource={_resource_key(return_url)}", flush=True)
        log_event("stepup_no_permission", identity=email, department=department, resource=_resource_key(return_url))
        return render_no_permission(email, department, return_url), 403
    return None


def _resolve_return_url():
    portal_domain = os.environ.get('DOMAIN_NAME', 'auth.xmcda.store').replace('auth.', '')
    # [B 계층 추가] portal_app.py가 세션 중 재확인에서 step-up이 필요하다고 판단하면
    # ?return_url=<원래 주소>를 붙여 이리로 보낸다. 이 경우 브라우저의 Referer에는 원래 페이지가
    # 남지 않으므로(리다이렉트 응답은 Referer를 바꾸지 않음) Referer 추정보다 이 값을 우선한다.
    explicit = _safe_return_url(request.args.get('return_url'))
    if explicit:
        return explicit
    # [수정] Access 거부 리다이렉트의 ?original_url= 로 "원래 가려던 주소"를 복원한다.
    # (기존에는 이 값을 읽지 않아 /dev에서 거부돼도 인증 후 항상 홈으로 갔음)
    from_access = _original_url_candidate(request.args.get('original_url'))
    if from_access:
        return from_access
    # Referer는 호스트만 본다: 우리 앱 호스트 중 하나면 그 앱의 첫 화면으로, 아니면 포털 홈.
    # (부분 문자열 비교가 아니라 호스트를 정확히 비교 - 'dev.xmcda.store.evil.com' 같은 주소는 무시)
    try:
        referrer_host = (urlparse(request.referrer or '').hostname or '').lower()
    except ValueError:
        referrer_host = ''
    if referrer_host and referrer_host in _app_hosts():
        return f'https://{referrer_host}'
    return f'https://{portal_domain}'


@app.route('/stepup', methods=['GET'])
def stepup():
    sso_token = request.cookies.get(SSO_COOKIE_NAME)
    email = get_sso_session_email(sso_token) if sso_token else None
    return_url = _resolve_return_url()
    if not email:
        portal_domain = os.environ.get('DOMAIN_NAME', 'auth.xmcda.store').replace('auth.', '')
        body = link_button(f"https://{portal_domain}/", "포털에서 로그인", "primary", "arrow-right", block=True)
        return auth_page("로그인 필요", "로그인이 필요합니다", body, subtitle="로그인 세션이 없거나 만료되었습니다. 포털에서 다시 로그인해 주세요.",
                         badge="lock", tone="warn")
    # 소속이 달라서 막힌 경우에는 TOTP를 묻지 않고 "권한 없음"을 알려준다(인증해도 해결되지 않으므로)
    denied = _no_permission_response(Account.query.filter_by(email=email).first(), email, return_url)
    if denied:
        return denied
    blocked = _blocked_response(email, return_url)
    if blocked:
        return blocked
    if check_brute_force(email):
        log_event("login_locked", identity=email, stage="stepup", window_min=BRUTE_FORCE_WINDOW_MINUTES, threshold=BRUTE_FORCE_THRESHOLD)
        return render_stepup_form(return_url, error=f"시도 횟수를 초과했습니다. {BRUTE_FORCE_LOCKOUT_MINUTES}분 후 다시 시도해주세요.", locked=True)
    return render_stepup_form(return_url)


@app.route('/stepup', methods=['POST'])
def stepup_verify():
    sso_token = request.cookies.get(SSO_COOKIE_NAME)
    email = get_sso_session_email(sso_token) if sso_token else None
    return_url = _safe_return_url(request.form.get('return_url')) or _resolve_return_url()
    if not email:
        portal_domain = os.environ.get('DOMAIN_NAME', 'auth.xmcda.store').replace('auth.', '')
        body = link_button(f"https://{portal_domain}/", "포털에서 로그인", "primary", "arrow-right", block=True)
        return auth_page("로그인 필요", "로그인이 필요합니다", body, subtitle="로그인 세션이 없거나 만료되었습니다. 포털에서 다시 로그인해 주세요.",
                         badge="lock", tone="warn")

    account = Account.query.filter_by(email=email).first()
    # 폼을 직접 POST해도 소속이 맞지 않으면 TOTP 확인 자체를 하지 않는다
    denied = _no_permission_response(account, email, return_url)
    if denied:
        return denied
    blocked = _blocked_response(email, return_url)
    if blocked:
        return blocked

    if check_brute_force(email):
        log_event("login_locked", identity=email, stage="stepup", window_min=BRUTE_FORCE_WINDOW_MINUTES, threshold=BRUTE_FORCE_THRESHOLD)
        return render_stepup_form(return_url, error=f"시도 횟수를 초과했습니다. {BRUTE_FORCE_LOCKOUT_MINUTES}분 후 다시 시도해주세요.", locked=True)

    totp_input = request.form.get('totp_code', '').strip()
    client_ip = request.headers.get('CF-Connecting-IP', request.remote_addr)

    totp_ok = False
    if account and account.totp_secret and pyotp.TOTP(account.totp_secret).verify(totp_input, valid_window=1):
        totp_ok = True
    elif account:
        for bc in BackupCode.query.filter_by(account_id=account.id, used=False).all():
            if check_password_hash(bc.code_hash, totp_input):
                bc.used = True
                db.session.commit()
                totp_ok = True
                break

    if not totp_ok:
        # [보안] 로그인 실패 기록과 같은 테이블(LoginFailure)에 그대로 남겨서, 기존
        # check_brute_force(5분에 5회) 잠금을 새 코드 없이 그대로 재사용한다.
        db.session.add(LoginFailure(email=email, ip_address=client_ip))
        db.session.commit()
        log_event("login_failed", identity=email, stage="stepup_totp")
        return render_stepup_form(return_url, error="TOTP 코드(또는 백업코드)가 올바르지 않습니다.")

    record_result = evaluate_login_risk(email, {"mfa_reauth": True})
    if not record_result.get("recorded"):
        print(f"[STEPUP_RECORD_FAILED] identity={email} - mfa_verified 기록 실패, Lambda/DynamoDB 확인 필요", flush=True)
    log_event("stepup_verified", identity=email, resource=_resource_key(return_url), recorded=bool(record_result.get("recorded")))

    return render_stepup_success(return_url)


@app.route('/token', methods=['POST'])
def token():
    code = request.form.get('code')
    grant_type = request.form.get('grant_type')

    if grant_type != 'authorization_code' or not code:
        return jsonify({"error": "unsupported_grant_type"}), 400

    if not OIDC_CLIENT_ID or not OIDC_CLIENT_SECRET:
        return jsonify({"error": "server_misconfigured"}), 500

    client_id, client_secret = _get_client_credentials()
    if client_id != OIDC_CLIENT_ID or client_secret != OIDC_CLIENT_SECRET:
        return jsonify({"error": "invalid_client"}), 401

    entry = AUTH_CODES.pop(code, None)
    if not entry or entry["expires_at"] < time.time():
        return jsonify({"error": "invalid_grant"}), 400

    account = Account.query.filter_by(email=entry["email"]).first()
    if not account:
        return jsonify({"error": "invalid_grant"}), 400

    now = int(time.time())
    id_token_claims = {
        "iss": OIDC_ISSUER,
        "sub": account.email,
        "email": account.email,
        "role": account.role,
        "department": account.department or "",
        "iat": now,
        "exp": now + 3600,
    }
    id_token = jwt.encode(
        id_token_claims, JWT_PRIVATE_KEY, algorithm="RS256",
        headers={"kid": JWT_KID},
    )

    access_token = secrets.token_urlsafe(32)
    ACCESS_TOKENS[access_token] = {"email": account.email, "expires_at": time.time() + 3600}

    return jsonify({
        "access_token": access_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600,
    })


@app.route('/userinfo')
def userinfo():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "invalid_token"}), 401

    access_token = auth_header[len('Bearer '):]
    entry = ACCESS_TOKENS.get(access_token)
    if not entry or entry["expires_at"] < time.time():
        return jsonify({"error": "invalid_token"}), 401

    account = Account.query.filter_by(email=entry["email"]).first()
    if not account:
        return jsonify({"error": "invalid_token"}), 401

    return jsonify({
        "sub": account.email,
        "email": account.email,
        "role": account.role,
        "department": account.department or "",
    })


@app.route('/.well-known/jwks.json')
def jwks():
    def _b64url_uint(n):
        import base64
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

    return jsonify({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": JWT_KID,
            "n": _b64url_uint(JWT_PUBLIC_NUMBERS.n),
            "e": _b64url_uint(JWT_PUBLIC_NUMBERS.e),
        }]
    })


@app.route('/logged-out')
def logged_out():
    """로그아웃 완료 안내. 다시 로그인은 포털로 보내면 Access가 이 서버의 로그인 화면으로 데려온다."""
    portal_domain = os.environ.get('DOMAIN_NAME', 'auth.xmcda.store').replace('auth.', '')
    body = link_button(f"https://{portal_domain}/", "다시 로그인", "primary", "arrow-right", block=True)
    response = make_response(auth_page("로그아웃", "로그아웃되었습니다", body, badge="check", tone="ok",
                                       subtitle="모든 업무 서비스에서 로그아웃했습니다. 공용 PC라면 브라우저 창도 모두 닫아 주세요."))
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/logout')
def logout():
    sso_token = request.cookies.get(SSO_COOKIE_NAME)
    if sso_token:
        clear_sso_session(sso_token)

    # 로그아웃은 세 단계로 지운다(OpenID Connect Front-Channel Logout과 같은 구조: 로그인 서버가
    # 브라우저를 통해 각 앱의 로그아웃 주소를 부른다).
    #   1) 이 서버의 SSO 세션(위에서 서버 쪽 삭제 + 아래에서 쿠키 삭제)
    #   2) 앱별 Access 쿠키: 앱 호스트마다 https://<호스트>/cdn-cgi/access/logout 을 숨은 이미지로 호출.
    #      Cloudflare 로그아웃 주소는 호스트 바로 아래에서만 동작한다(예전 경로 앱의
    #      xmcda.store/dev/cdn-cgi/... 는 실측 404/302로 로그아웃이 안 됐음 -> 서브도메인으로 분리).
    #      앱 호스트들은 모두 xmcda.store 계열이라 same-site 요청으로 쿠키가 정상 전달된다.
    #   3) 끝나면 이 서버의 "로그아웃되었습니다" 화면(/logged-out)으로 이동.
    #      경로 앱 구조에서는 Access 전체 세션(팀 도메인 쿠키)이 남아 비밀번호 없이 다시 로그인되는 문제가
    #      있었는데(실측), 서브도메인 구조에서 앱 로그아웃을 모두 부른 뒤 팀 도메인 로그아웃 주소에 가 보니
    #      "쿠키 없음/로그아웃 실패"가 떴고 포털에 다시 들어가면 로그인 화면이 나왔다(실측) = 앱 로그아웃
    #      단계에서 이미 정리된다. 그래서 Cloudflare 오류 화면 대신 우리 안내 화면으로 끝낸다.
    logout_urls = [f"https://{host}/cdn-cgi/access/logout" for host in _app_hosts()]
    final_url = "/logged-out"
    logout_pixels = "\n        ".join(
        f'<img src="{url}" style="display:none" onload="done()" onerror="done()">' for url in logout_urls
    )

    body = f"""<div class="spinner"></div>
        <script>
          // [버그수정] 예전엔 고정 1초 뒤에 이동해서, 앱 로그아웃 요청이 끝나기 전에 페이지가
          // 넘어가면 일부 세션 쿠키가 안 지워져 로그아웃을 두 번 눌러야 했음.
          // 요청이 전부 끝나면(성공/실패 무관) 이동하고, 응답이 없어도 5초 뒤엔 이동한다.
          var remaining = {len(logout_urls)};
          var moved = false;
          function go() {{
            if (moved) return;
            moved = true;
            window.location.href = "{final_url}";
          }}
          function done() {{
            remaining -= 1;
            if (remaining <= 0) go();
          }}
          setTimeout(go, 5000);
        </script>
        {logout_pixels}"""
    response = make_response(auth_page("로그아웃 중", "로그아웃하는 중", body, subtitle="모든 업무 서비스에서 로그아웃하고 있습니다."))
    response.delete_cookie(SSO_COOKIE_NAME)
    return response


if __name__ == '__main__':
    if '--bootstrap' in sys.argv:
        with app.app_context():
            bootstrap_database()
        sys.exit(0)
    ssl_context = build_server_context(*MTLS[:3]) if MTLS else None
    app.run(host='0.0.0.0', port=8080, ssl_context=ssl_context)
