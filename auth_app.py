from flask import Flask, request, jsonify, redirect, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
import time
import uuid
import secrets
import pyotp
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import requests
import re
from html import escape
from urllib.parse import urlparse

app = Flask(__name__)

DB_HOST = os.environ.get('DB_HOST')
DB_NAME = os.environ.get('DB_NAME')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')

app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    # 아래 ensure_department_schema()가 서버 시작 때 자동으로 추가한다.
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


with app.app_context():
    db.create_all()


# ==========================================================================
# [자동 마이그레이션] 서버가 켜질 때 accounts.department 컬럼을 보장하고 소속을 채운다.
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
# [자동 계정 시딩] 서버가 켜질 때 AWS SSM Parameter Store(SecureString)에 저장된 계정 정보로, DB에 없는 계정만 만든다.
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


with app.app_context():
    ensure_department_schema()
    seed_accounts_from_ssm()


PDP_EVALUATE_URL = os.environ.get('PDP_EVALUATE_URL')
EVALUATE_SHARED_SECRET = os.environ.get('EVALUATE_SHARED_SECRET')


def evaluate_login_risk(identity, signals):
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
                **signals,
            },
            timeout=3,
        )
        return resp.json()
    except Exception as e:
        print("Lambda 위험점수 평가 실패, fail-closed 처리:", str(e))
        return {"allow": False, "action": "lambda_call_failed"}


# [팀원 추가, 병합] SQL 인젝션 패턴 탐지 - waf_sqli 신호를 처음으로 실제 코드에 연결.
# WAF가 아니라 로그인 폼 입력값 자체에서 패턴을 감지하는 방식으로 "WAF는 JWT를
# 파싱하지 않는다"는 기존 미해결 문제(§3-3-1)를 우회 해결함.
SQLI_PATTERN = re.compile(
    r"(--|;|/\*|\*/|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|'\s*OR\s*'|'\s*=\s*')",
    re.IGNORECASE,
)

def detect_sqli(value):
    if not value:
        return False
    return bool(SQLI_PATTERN.search(value))


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


def create_sso_session(email):
    token = secrets.token_urlsafe(32)
    SSO_SESSIONS[token] = {"email": email, "expires_at": time.time() + SSO_SESSION_SECONDS}
    return token


def get_sso_session_email(token):
    entry = SSO_SESSIONS.get(token)
    if not entry or entry["expires_at"] < time.time():
        SSO_SESSIONS.pop(token, None)
        return None
    return entry["email"]


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
        return render_credentials_form(
            client_id, redirect_uri, state, response_type, scope,
            error=f"보안 정책에 의해 로그인이 차단되었습니다 ({risk_result.get('action')})."
        )

    print(f"[LOGIN_ALLOWED] identity={email} totp_ok={totp_ok} (SSO 재사용이면 totp 재입력 없이도 위험판단은 여기서 매번 실행됨)", flush=True)

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


def render_credentials_form(client_id, redirect_uri, state, response_type, scope, error=None):
    error_html = f'<p style="color:#dc3545;"><strong>{error}</strong></p>' if error else ""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>ZT Login Server</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background-color: #f4f6f9; }}
            .card {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 400px; margin: 60px auto; }}
            input {{ width: 100%; padding: 10px; margin: 6px 0 14px 0; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }}
            button {{ width: 100%; background: #007bff; color: white; border: none; padding: 12px; border-radius: 6px; cursor: pointer; font-weight: bold; }}
            label {{ font-size: 0.9em; color: #555; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h2>ZT Login</h2>
            {error_html}
            <form method="POST" action="/authorize">
                <input type="hidden" name="client_id" value="{client_id}">
                <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                <input type="hidden" name="state" value="{state}">
                <input type="hidden" name="response_type" value="{response_type}">
                <input type="hidden" name="scope" value="{scope}">

                <label>이메일</label>
                <input type="email" name="email" required autofocus>

                <label>비밀번호</label>
                <input type="password" name="password" required>

                <button type="submit">다음</button>
            </form>
        </div>
    </body>
    </html>
    """


def render_totp_form(challenge_id, error=None):
    error_html = f'<p style="color:#dc3545;"><strong>{error}</strong></p>' if error else ""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>ZT Login Server</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background-color: #f4f6f9; }}
            .card {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 400px; margin: 60px auto; }}
            input {{ width: 100%; padding: 10px; margin: 6px 0 14px 0; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }}
            button {{ width: 100%; background: #007bff; color: white; border: none; padding: 12px; border-radius: 6px; cursor: pointer; font-weight: bold; }}
            label {{ font-size: 0.9em; color: #555; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h2>2단계 인증</h2>
            <p style="font-size:0.9em; color:#555;">인증 앱의 6자리 코드 또는 백업코드를 입력하세요.</p>
            {error_html}
            <form method="POST" action="/authorize/verify-totp">
                <input type="hidden" name="challenge_id" value="{challenge_id}">

                <label>TOTP 코드 (또는 백업코드)</label>
                <input type="text" name="totp_code" required autofocus>

                <button type="submit">로그인</button>
            </form>
        </div>
    </body>
    </html>
    """


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

    # [팀원 추가, 병합] SQL 인젝션 패턴 사전 검사 - 자격증명 확인보다 먼저 걸러냄
    if detect_sqli(email) or detect_sqli(password):
        risk_result = evaluate_login_risk(
            email or 'unknown',
            {"waf_sqli": True, "security_mfa_passed": False},
        )
        print(f"[WAF_BLOCKED] identity={email} action={risk_result.get('action')}", flush=True)
        return render_credentials_form(
            client_id, redirect_uri, state, response_type, scope,
            error="비정상적인 요청이 감지되어 접속이 차단되었습니다."
        )

    account = Account.query.filter_by(email=email).first()
    credentials_ok = bool(account) and check_password_hash(account.password_hash, password)

    if not credentials_ok:
        db.session.add(LoginFailure(email=email, ip_address=client_ip))
        db.session.commit()
        return render_credentials_form(
            client_id, redirect_uri, state, response_type, scope,
            error="이메일 또는 비밀번호가 올바르지 않습니다."
        )

    # [방식변경] 예전엔 비밀번호가 맞으면 brute_force 여부와 무관하게 TOTP 화면으로
    # 보내고, 걸린 경우 문구만 다르게 표시했음. 근데 이 시점엔 공격자가 비밀번호를
    # 이미 맞힌 상태라 TOTP 화면 자체는 공격자든 주인이든 똑같이 겪는 절차라
    # "추가 인증"으로서 실질적 의미가 없었음(업계도 MFA를 더 요구하기보다, 비밀번호가
    # 맞아도 이 시점에 바로 잠그는 lockout 방식을 표준으로 씀 - Microsoft Entra ID,
    # SecureAuth 등). 그래서 비밀번호가 맞았어도 brute_force면 TOTP 화면 자체를
    # 안 보여주고 여기서 바로 막는다.
    if check_brute_force(email):
        return render_credentials_form(
            client_id, redirect_uri, state, response_type, scope,
            error=f"로그인 시도가 너무 많습니다. {BRUTE_FORCE_LOCKOUT_MINUTES}분 후 다시 시도해주세요."
        )

    if not account.totp_enabled:
        return finalize_login(email, client_id, redirect_uri, state, response_type, scope, totp_ok=True)

    challenge_id = secrets.token_urlsafe(24)
    PENDING_LOGINS[challenge_id] = {
        "email": email,
        "expires_at": time.time() + 300,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "response_type": response_type,
        "scope": scope,
    }
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
        return render_totp_form(challenge_id, error="TOTP 코드(또는 백업코드)가 올바르지 않습니다.")

    PENDING_LOGINS.pop(challenge_id, None)
    return finalize_login(
        email, entry["client_id"], entry["redirect_uri"], entry["state"],
        entry["response_type"], entry["scope"], totp_ok=True,
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
    error_html = f'<p style="color:#dc3545;"><strong>{error}</strong></p>' if error else ""
    disabled = "disabled" if locked else ""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>추가 인증 - ZT Login Server</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background-color: #f4f6f9; }}
            .card {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 400px; margin: 60px auto; }}
            input {{ width: 100%; padding: 10px; margin: 6px 0 14px 0; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }}
            button {{ width: 100%; background: #007bff; color: white; border: none; padding: 12px; border-radius: 6px; cursor: pointer; font-weight: bold; }}
            button:disabled {{ background: #aaa; cursor: not-allowed; }}
            label {{ font-size: 0.9em; color: #555; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h2>추가 인증이 필요합니다</h2>
            <p style="font-size:0.9em; color:#555;">보안 정책에 따라 2단계 인증을 한 번 더 확인합니다.</p>
            {error_html}
            <form method="POST" action="/stepup">
                <input type="hidden" name="return_url" value="{return_url}">
                <label>TOTP 코드 (또는 백업코드)</label>
                <input type="text" name="totp_code" required autofocus {disabled}>
                <button type="submit" {disabled}>인증</button>
            </form>
        </div>
    </body>
    </html>
    """


def render_stepup_success(return_url):
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>인증 완료 - ZT Login Server</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background-color: #f4f6f9; }}
            .card {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 400px; margin: 60px auto; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h2>✅ 인증되었습니다</h2>
            <p style="font-size:0.9em; color:#555;">잠시 후 원래 접속하려던 페이지로 이동합니다.</p>
            <a href="{return_url}">지금 바로 이동</a>
        </div>
        <script>
          setTimeout(function() {{ window.location.href = "{return_url}"; }}, 1500);
        </script>
    </body>
    </html>
    """


# [기능추가] Access의 커스텀 거부 URL 리다이렉트에는 ?original_url=(원래 가려던 주소)가
# 실려오는 것이 실제로 관찰됐지만 Cloudflare 문서에는 정의돼 있지 않다. 그래서 이 값은 규격이
# 아니라 "관찰된 동작"으로만 쓰고(_original_url_candidate), 없으면 브라우저가 이
# 페이지로 넘어오기 직전 있었던 곳(Referer 헤더)을 근거로 추정한다. 확실한 값은 아니라서
# 우리가 아는 앱 도메인(admin 서브도메인)에 해당할 때만 그리로 보내고, 그 외에는 항상
# 안전한 기본값(포털 홈)으로 보낸다.
def _safe_return_url(candidate):
    """사용자가 넘긴 복귀 주소(쿼리스트링 return_url, 폼의 hidden 값)를 검증한다.
    이 값은 HTML 속성과 JS 문자열, window.location에 그대로 들어가므로, 검증 없이 쓰면
    (1) 아무 외부 사이트로 보내는 open redirect, (2) 따옴표를 섞은 값으로 스크립트가 끼어드는
    XSS가 가능해진다. 우리 도메인(portal/admin 서브도메인)의 https 주소이고 위험 문자가
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
    if parsed.hostname not in (portal_domain, f'admin.{portal_domain}'):
        return None
    return candidate


def _original_url_candidate(raw):
    """Access가 커스텀 거부 URL로 보낼 때 붙여주는 ?original_url=xmcda.store/dev 를 읽는다.
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
# 형식: "경로=소속,소속;경로=소속" (예: /dev=dev;/hr=hr;admin=admin). admin 서브도메인은 키가 admin.
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
    """복귀 주소가 어느 자원인지: admin 서브도메인이면 'admin', 아니면 첫 경로 조각('/dev', '/hr' ...), 홈은 '/'."""
    parsed = urlparse(url)
    if (parsed.hostname or '').startswith('admin.'):
        return 'admin'
    segments = [seg for seg in parsed.path.split('/') if seg]
    return '/' + segments[0] if segments else '/'


def check_department_access(department, url):
    """True=소속이 허용 목록에 있음, False=없음, None=이 자원은 권한표에 없어서 판단 불가(기존 흐름대로 진행)."""
    allowed = PATH_PERMISSIONS.get(_resource_key(url))
    if allowed is None:
        return None
    return (department or '') in allowed


def render_no_permission(email, department, url):
    portal_domain = os.environ.get('DOMAIN_NAME', 'auth.xmcda.store').replace('auth.', '')
    needed = ', '.join(PATH_PERMISSIONS.get(_resource_key(url), [])) or '-'
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>접근 권한 없음 - ZT Login Server</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background-color: #f4f6f9; }}
            .card {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 440px; margin: 60px auto; }}
            a.btn {{ display: inline-block; margin: 6px 8px 0 0; padding: 10px 16px; border-radius: 6px; background: #007bff; color: white; text-decoration: none; font-weight: bold; }}
            a.sub {{ background: #6c757d; }}
            dt {{ color: #777; font-size: 0.85em; margin-top: 10px; }}
            dd {{ margin: 2px 0 0 0; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h2>접근 권한이 없습니다</h2>
            <p style="font-size:0.9em; color:#555;">이 계정의 소속으로는 요청한 페이지를 열 수 없습니다. 추가 인증으로 해결되는 문제가 아닙니다.</p>
            <dl>
                <dt>로그인한 계정</dt><dd>{escape(email)}</dd>
                <dt>계정의 소속</dt><dd>{escape(department or '(지정되지 않음)')}</dd>
                <dt>이 페이지를 열 수 있는 소속</dt><dd>{escape(needed)}</dd>
            </dl>
            <p style="font-size:0.9em; color:#555;">권한이 필요하면 관리자에게 소속 변경을 요청하세요.</p>
            <a class="btn" href="https://{escape(portal_domain)}/">포털 홈으로</a>
            <a class="btn sub" href="/logout">다른 계정으로 로그인</a>
        </div>
    </body>
    </html>
    """


def _no_permission_response(account, email, return_url):
    """소속이 이 자원의 허용 목록에 없으면 403 안내 화면을, 아니면 None을 돌려준다."""
    department = account.department if account else None
    if check_department_access(department, return_url) is False:
        print(f"[STEPUP_NO_PERMISSION] identity={email} department={department or '-'} resource={_resource_key(return_url)}", flush=True)
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
    referrer = request.referrer or ''
    # [확대] admin 서브도메인만 알아보던 걸, custom_deny_url을 새로 붙인 5개 앱
    # (portal/dev/marketing/hr/admin_console) 전부 인식하도록 확장.
    if f'admin.{portal_domain}' in referrer:
        return f'https://admin.{portal_domain}'
    for path in ('/dev', '/marketing', '/hr'):
        if f'{portal_domain}{path}' in referrer:
            return f'https://{portal_domain}{path}'
    return f'https://{portal_domain}'


@app.route('/stepup', methods=['GET'])
def stepup():
    sso_token = request.cookies.get(SSO_COOKIE_NAME)
    email = get_sso_session_email(sso_token) if sso_token else None
    return_url = _resolve_return_url()
    if not email:
        return """
        <p>로그인이 필요합니다. <a href="https://xmcda.store">포털에서 다시 로그인해주세요</a>.</p>
        """
    # 소속이 달라서 막힌 경우에는 TOTP를 묻지 않고 "권한 없음"을 알려준다(인증해도 해결되지 않으므로)
    denied = _no_permission_response(Account.query.filter_by(email=email).first(), email, return_url)
    if denied:
        return denied
    if check_brute_force(email):
        return render_stepup_form(return_url, error=f"시도 횟수를 초과했습니다. {BRUTE_FORCE_LOCKOUT_MINUTES}분 후 다시 시도해주세요.", locked=True)
    return render_stepup_form(return_url)


@app.route('/stepup', methods=['POST'])
def stepup_verify():
    sso_token = request.cookies.get(SSO_COOKIE_NAME)
    email = get_sso_session_email(sso_token) if sso_token else None
    return_url = _safe_return_url(request.form.get('return_url')) or _resolve_return_url()
    if not email:
        return """
        <p>로그인이 필요합니다. <a href="https://xmcda.store">포털에서 다시 로그인해주세요</a>.</p>
        """

    account = Account.query.filter_by(email=email).first()
    # 폼을 직접 POST해도 소속이 맞지 않으면 TOTP 확인 자체를 하지 않는다
    denied = _no_permission_response(account, email, return_url)
    if denied:
        return denied

    if check_brute_force(email):
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
        return render_stepup_form(return_url, error="TOTP 코드(또는 백업코드)가 올바르지 않습니다.")

    record_result = evaluate_login_risk(email, {"mfa_reauth": True})
    if not record_result.get("recorded"):
        print(f"[STEPUP_RECORD_FAILED] identity={email} - mfa_verified 기록 실패, Lambda/DynamoDB 확인 필요", flush=True)

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


@app.route('/logout')
def logout():
    sso_token = request.cookies.get(SSO_COOKIE_NAME)
    if sso_token:
        clear_sso_session(sso_token)

    # [버그수정] 예전엔 xmcda.store 루트의 /cdn-cgi/access/logout 하나만 호출했는데,
    # (1) path_cookie_attribute로 앱별 세션 쿠키가 경로별로 분리돼 있고
    # (2) admin_console은 admin.xmcda.store라는 별도 서브도메인이라
    # 이 한 번의 호출로는 다른 앱들의 세션이 전혀 지워지지 않고 남아있었음
    # (admin.xmcda.store가 로그아웃 후에도 재인증 없이 그대로 통과되던 원인).
    # xmcda.store와 admin.xmcda.store는 같은 등록 도메인(site)을 공유하는 서브도메인이라
    # SameSite 쿠키도 같이 전달되는 same-site 관계임을 이용해, 5개 앱의 로그아웃
    # 엔드포인트를 전부 숨은 이미지 태그로 호출한 뒤 최종 목적지로 이동시킨다.
    portal_domain = os.environ.get('DOMAIN_NAME', 'auth.xmcda.store').replace('auth.', '')
    logout_urls = [
        f"https://{portal_domain}/cdn-cgi/access/logout",
        f"https://{portal_domain}/dev/cdn-cgi/access/logout",
        f"https://{portal_domain}/marketing/cdn-cgi/access/logout",
        f"https://{portal_domain}/hr/cdn-cgi/access/logout",
        f"https://admin.{portal_domain}/cdn-cgi/access/logout",
    ]
    logout_pixels = "\n        ".join(
        f'<img src="{url}" style="display:none" onerror="this.remove()">' for url in logout_urls
    )

    response = make_response(f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"><title>로그아웃 중...</title></head>
    <body>
        {logout_pixels}
        <p>로그아웃 처리 중입니다. 잠시만 기다려주세요...</p>
        <script>
          setTimeout(function() {{
            window.location.href = "https://{portal_domain}/";
          }}, 1000);
        </script>
    </body>
    </html>
    """)
    response.delete_cookie(SSO_COOKIE_NAME)
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
