from flask import Flask, request, jsonify, redirect, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
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


def check_brute_force(email):
    from datetime import datetime, timedelta
    fifteen_min_ago = datetime.utcnow() - timedelta(minutes=15)
    recent_failures = LoginFailure.query.filter(
        LoginFailure.email == email,
        LoginFailure.attempted_at >= fifteen_min_ago,
    ).count()
    return recent_failures >= 5


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


# [기능추가] Access의 커스텀 거부 URL 리다이렉트에는 "원래 어디로 가려 했는지"를 담은
# 신뢰할 만한 값이 실려온다는 근거를 문서로 확인하지 못해서, 그 대신 브라우저가 이
# 페이지로 넘어오기 직전 있었던 곳(Referer 헤더)을 근거로 추정한다. 확실한 값은 아니라서
# 우리가 아는 앱 도메인(admin 서브도메인)에 해당할 때만 그리로 보내고, 그 외에는 항상
# 안전한 기본값(포털 홈)으로 보낸다.
def _resolve_return_url():
    portal_domain = os.environ.get('DOMAIN_NAME', 'auth.xmcda.store').replace('auth.', '')
    referrer = request.referrer or ''
    if f'admin.{portal_domain}' in referrer:
        return f'https://admin.{portal_domain}'
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
    if check_brute_force(email):
        return render_stepup_form(return_url, error="시도 횟수를 초과했습니다. 15분 후 다시 시도해주세요.", locked=True)
    return render_stepup_form(return_url)


@app.route('/stepup', methods=['POST'])
def stepup_verify():
    sso_token = request.cookies.get(SSO_COOKIE_NAME)
    email = get_sso_session_email(sso_token) if sso_token else None
    return_url = request.form.get('return_url') or _resolve_return_url()
    if not email:
        return """
        <p>로그인이 필요합니다. <a href="https://xmcda.store">포털에서 다시 로그인해주세요</a>.</p>
        """

    if check_brute_force(email):
        return render_stepup_form(return_url, error="시도 횟수를 초과했습니다. 15분 후 다시 시도해주세요.", locked=True)

    totp_input = request.form.get('totp_code', '').strip()
    client_ip = request.headers.get('CF-Connecting-IP', request.remote_addr)
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
        # [보안] 로그인 실패 기록과 같은 테이블(LoginFailure)에 그대로 남겨서, 기존
        # check_brute_force(15분에 5회) 잠금을 새 코드 없이 그대로 재사용한다.
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
    # (1) path_cookie_attribute로 6개 앱의 세션 쿠키가 경로별로 분리돼 있고
    # (2) admin_console/admin_api는 admin.xmcda.store라는 별도 서브도메인이라
    # 이 한 번의 호출로는 다른 앱들의 세션이 전혀 지워지지 않고 남아있었음
    # (admin.xmcda.store가 로그아웃 후에도 재인증 없이 그대로 통과되던 원인).
    # xmcda.store와 admin.xmcda.store는 같은 등록 도메인(site)을 공유하는 서브도메인이라
    # SameSite 쿠키도 같이 전달되는 same-site 관계임을 이용해, 6개 앱의 로그아웃
    # 엔드포인트를 전부 숨은 이미지 태그로 호출한 뒤 최종 목적지로 이동시킨다.
    portal_domain = os.environ.get('DOMAIN_NAME', 'auth.xmcda.store').replace('auth.', '')
    logout_urls = [
        f"https://{portal_domain}/cdn-cgi/access/logout",
        f"https://{portal_domain}/dev/cdn-cgi/access/logout",
        f"https://{portal_domain}/marketing/cdn-cgi/access/logout",
        f"https://{portal_domain}/hr/cdn-cgi/access/logout",
        f"https://admin.{portal_domain}/cdn-cgi/access/logout",
        f"https://admin.{portal_domain}/api/db-data/cdn-cgi/access/logout",
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
