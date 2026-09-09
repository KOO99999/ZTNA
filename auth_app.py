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
    current_hour_utc = time.gmtime().tm_hour
    signals = {
        "brute_force": brute_force_flag,
        "night_access": current_hour_utc < 5,
    }
    risk_result = evaluate_login_risk(email, {**signals, "security_mfa_passed": totp_ok})

    if not risk_result.get("allow", False):
        print(f"[LOGIN_BLOCKED] identity={email} action={risk_result.get('action')}")
        return render_credentials_form(
            client_id, redirect_uri, state, response_type, scope,
            error=f"보안 정책에 의해 로그인이 차단되었습니다 ({risk_result.get('action')})."
        )

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
            return finalize_login(sso_email, client_id, redirect_uri, state, response_type, scope, totp_ok=True)

        return render_credentials_form(client_id, redirect_uri, state, response_type, scope)

    client_id = request.form.get('client_id', '')
    redirect_uri = request.form.get('redirect_uri', '')
    state = request.form.get('state', '')
    response_type = request.form.get('response_type', 'code')
    scope = request.form.get('scope', 'openid')

    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    client_ip = request.headers.get('CF-Connecting-IP', request.remote_addr)

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

    # SSO 세션(sso_session)을 지우는 것만으로는 Cloudflare Access가 별도로 발급한
    # CF_Authorization 세션까지 지워지지 않음 (IdP 세션과 SP 세션이 분리되어 있기 때문).
    # Cloudflare Access의 공식 front-channel 로그아웃 엔드포인트(/cdn-cgi/access/logout)로
    # 리다이렉트시켜 두 세션을 순차적으로 정리한다 (Chained Logout).
    portal_domain = os.environ.get('DOMAIN_NAME', 'auth.xmcda.store').replace('auth.', '')
    response = make_response(redirect(f"https://{portal_domain}/cdn-cgi/access/logout"))
    response.delete_cookie(SSO_COOKIE_NAME)
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
