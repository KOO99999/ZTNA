from flask import Flask, request, jsonify, redirect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
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
dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-2')
table = dynamodb.Table('risk_score_log')

# ==========================================
# RDS(MySQL, login_server DB) 연결 설정
#   DB_HOST/DB_NAME/DB_USER/DB_PASSWORD는 ec2_app.tf가 부팅스크립트(user_data_app.sh.tpl)를
#   통해 EC2의 .env 파일로 넘겨준 값을, 부팅스크립트가 환경변수로 export해서 여기서 읽음
# ==========================================
DB_HOST = os.environ.get('DB_HOST')
DB_NAME = os.environ.get('DB_NAME')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')

app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# ==========================================
# 로그인서버 테이블 정의 (SQLAlchemy 모델)
#   실제 CREATE TABLE은 파일 하단 db.create_all()이 앱 기동 시 자동 수행
#   (테이블이 이미 있으면 건드리지 않음 — 매번 재기동해도 안전)
# ==========================================
class Account(db.Model):
    __tablename__ = 'accounts'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    # employee/admin — 추후 '/general' 로그인 전환 결정 시 admin_viewer/admin_operator 등으로 세분화 검토
    role = db.Column(db.String(32), default='employee', nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class BackupCode(db.Model):
    __tablename__ = 'backup_codes'

    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)
    code_hash = db.Column(db.String(255), nullable=False)  # 평문 저장 금지, 해시만 저장
    used = db.Column(db.Boolean, default=False, nullable=False)  # 1회용 소진 여부
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class LoginFailure(db.Model):
    __tablename__ = 'login_failures'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    attempted_at = db.Column(db.DateTime, server_default=db.func.now())
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6까지 고려한 길이


with app.app_context():
    db.create_all()


# ==========================================
# 로그인 시도 시점 위험점수 평가 — Flask가 Lambda(/evaluate)를 "직접" 호출
#   (Worker를 거치지 않음. /authorize는 Access가 보호하는 리소스가 아니라서
#   external_evaluation 자동 호출 대상이 아니므로, 로그인서버가 직접 챙겨야 함.
#   같은 AWS 계정 내부 통신이라 JWT 서명 불필요 — API Gateway 공유 비밀키 인증만 사용)
# ==========================================
PDP_EVALUATE_URL = os.environ.get('PDP_EVALUATE_URL')
EVALUATE_SHARED_SECRET = os.environ.get('EVALUATE_SHARED_SECRET')

def evaluate_login_risk(identity, signals):
    """로그인 시도 자체의 위험도를 Lambda에 물어봄. 실패 시 fail-closed(차단)로 처리."""
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


# ==========================================
# OIDC id_token 서명용 RSA 키 쌍
#   Worker(index.js)가 쓰는 키와는 별개(그쪽은 external_evaluation 응답 서명용,
#   이건 로그인서버가 발급하는 신원 토큰 서명용) — 앱 기동 시 1회 생성해 메모리에 유지.
#   주의(8주 프로젝트 범위 내 단순화): 서버 재기동 시 키가 바뀌므로, 재기동 직후에는
#   이전에 발급된 id_token 검증이 깨질 수 있음. 다음 단계로 키를 파일/Secrets Manager에
#   영속화하는 것을 검토할 것.
# ==========================================
_rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWT_PRIVATE_KEY = _rsa_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
JWT_PUBLIC_NUMBERS = _rsa_key.public_key().public_numbers()
JWT_KID = "zt-login-server-key-1"

OIDC_ISSUER = f"https://{os.environ.get('DOMAIN_NAME', 'xmcda.store')}"

# 인가 코드(authorization code)와 access_token을 임시 보관하는 메모리 저장소.
# 8주 프로젝트 범위 단순화: App 서버가 1대뿐이라 메모리로 충분하나, 서버가 여러 대로
# 늘어나면(오토스케일링 등) 공유 저장소(예: 검토 중이던 ElastiCache Redis)로 옮겨야 함.
AUTH_CODES = {}   # code -> {"email": ..., "expires_at": ...}
ACCESS_TOKENS = {}  # access_token -> {"email": ..., "expires_at": ...}

def render_page(title, min_score, content_html, is_public=False):
    user_email = request.headers.get('Cf-Access-Authenticated-User-Email')

    if is_public and not user_email:
        user_status_html = "🌐 <strong>접속 상태:</strong> 게스트 (인증 불필요 오픈 서비스)"
    else:
        email_str = user_email if user_email else "인증 정보 없음"
        user_status_html = f"🔑 <strong>인증된 관리자 계정:</strong> {email_str}<br>🛡️ <strong>허용 위험점수(이하 통과):</strong> {min_score}점"

    inactivity_script = """
    <script>
        let inactivityTimer;
        const INACTIVITY_LIMIT = 15 * 60 * 1000; // 15분

        function resetInactivityTimer() {
            clearTimeout(inactivityTimer);
            inactivityTimer = setTimeout(onInactivityTimeout, INACTIVITY_LIMIT);
        }

        function onInactivityTimeout() {
            alert("⚠️ 장시간 사용자 활동이 없어 신뢰 점수가 차감되었습니다.\\n보안을 위해 다시 로그인해 주세요.");
            window.location.href = "/cdn-cgi/access/logout";
        }

        window.onload = resetInactivityTimer;
        document.onmousemove = resetInactivityTimer;
        document.onkeypress = resetInactivityTimer;
        document.onclick = resetInactivityTimer;
        document.onscroll = resetInactivityTimer;
    </script>
    """ if not is_public else ""

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>{title}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background-color: #f4f6f9; color: #333; }}
            .card {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 650px; margin: 0 auto; }}
            .badge {{ display: inline-block; padding: 6px 14px; background-color: #007bff; color: white; border-radius: 20px; font-size: 0.85em; font-weight: bold; }}
            .badge-public {{ background-color: #28a745; }}
            .user-info {{ background: #e9ecef; padding: 12px 18px; border-radius: 8px; margin-top: 15px; font-size: 0.9em; border-left: 4px solid #007bff; }}
            button {{ background: #28a745; color: white; border: none; padding: 10px 18px; border-radius: 6px; cursor: pointer; font-size: 0.95em; margin-top: 15px; font-weight: bold; }}
            button:hover {{ background: #218838; }}
            pre {{ background: #1e1e1e; color: #4ec9b0; padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 0.9em; }}
        </style>
        {inactivity_script}
    </head>
    <body>
        <div class="card">
            <span class="badge {'badge-public' if is_public else ''}">{'Public Access Area' if is_public else 'Zero Trust Protected Area'}</span>
            <h2>{title}</h2>
            <div class="user-info">
                {user_status_html}
            </div>
            <hr style="border: 0.5px solid #eee; margin: 20px 0;">
            {content_html}
        </div>
    </body>
    </html>
    """

@app.route('/')
@app.route('/general')
def general():
    html = """
    <p>누구나 무료로 이용할 수 있는 오픈 서비스 영역입니다.</p>
    <ul>
        <li>인증 절차 없이 즉시 접근 가능</li>
        <li>서비스 기본 정보 및 공개 게시판 제공</li>
    </ul>
    <a href="/admin"><button style="background-color: #dc3545;">관리자 콘솔 바로가기 (이메일 OTP 인증 필요)</button></a>
    """
    return render_page("[Public Tier] 일반 대시보드", 0, html, is_public=True)

@app.route('/admin')
def admin():
    html = """
    <p><strong>⚠️ 관리자 전용 영역입니다. (이메일 OTP 인증 완료됨)</strong></p>
    <p><small>💡 15분간 아무런 활동이 없으면 신뢰 점수 Decay 정책에 따라 자동 세션 만료 및 재인증이 유도됩니다.</small></p>
    <button onclick="fetchData('admin_logs')" style="background-color: #dc3545;">DynamoDB 감사 로그 전체 조회</button>
    <div id="result"></div>
    <script>
        function fetchData(datatype) {
            document.getElementById('result').innerHTML = '<p>DynamoDB 테이블 스캔 중...</p>';
            fetch('/api/db-data?type=' + datatype)
                .then(res => res.json())
                .then(data => {
                    document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                });
        }
    </script>
    """
    return render_page("[Admin Tier] 관리자 콘솔", 40, html, is_public=False)

@app.route('/api/db-data')
def get_db_data():
    data_type = request.args.get('type')
    user_email = request.headers.get('Cf-Access-Authenticated-User-Email')

    if not user_email:
        return jsonify({
            "status": "Denied",
            "message": "관리자 이메일 인증 헤더가 누락되어 DB 접근이 거부되었습니다."
        }), 403

    try:
        if data_type == 'admin_logs':
            response = table.scan(Limit=5)
            logs = response.get('Items', [])
            return jsonify({
                "status": "Success",
                "identity": user_email,
                "db_table": "risk_score_log",
                "fetched_logs_count": len(logs),
                "logs": logs
            })
        else:
            return jsonify({"status": "Error", "message": "유효하지 않은 데이터 요청입니다."}), 400
    except Exception as e:
        return jsonify({"status": "Error", "message": str(e)}), 500

# ==========================================
# 로그인서버 (OIDC Authorization Code Flow)
#   Cloudflare Access가 "이메일 OTP" 대신 이 서버를 IdP로 등록해 신원 확인을 위임함.
#   흐름: /authorize(로그인 화면+검증) -> Access가 /token 호출(코드->토큰 교환)
#         -> Access가 /userinfo 호출(신원 정보 조회) -> 이후 기존 external_evaluation
#         (Worker->Lambda) 위험점수 재검사는 이 흐름과 별개로 그대로 이어서 실행됨
# ==========================================

def render_login_form(client_id, redirect_uri, state, response_type, scope, error=None):
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
                <input type="email" name="email" required>

                <label>비밀번호</label>
                <input type="password" name="password" required>

                <label>TOTP 코드 (등록된 계정만)</label>
                <input type="text" name="totp_code" placeholder="6자리 코드 또는 백업코드">

                <button type="submit">로그인</button>
            </form>
        </div>
    </body>
    </html>
    """


@app.route('/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'GET':
        # Access가 로그인 화면을 요청하며 붙여 보내는 표준 OAuth/OIDC 파라미터
        client_id = request.args.get('client_id', '')
        redirect_uri = request.args.get('redirect_uri', '')
        state = request.args.get('state', '')
        response_type = request.args.get('response_type', 'code')
        scope = request.args.get('scope', 'openid')
        return render_login_form(client_id, redirect_uri, state, response_type, scope)

    # --- POST: 실제 로그인 시도 처리 ---
    client_id = request.form.get('client_id', '')
    redirect_uri = request.form.get('redirect_uri', '')
    state = request.form.get('state', '')
    response_type = request.form.get('response_type', 'code')
    scope = request.form.get('scope', 'openid')

    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    totp_input = request.form.get('totp_code', '').strip()
    client_ip = request.headers.get('CF-Connecting-IP', request.remote_addr)

    def reject(error_message, record_failure=True):
        if record_failure:
            db.session.add(LoginFailure(email=email, ip_address=client_ip))
            db.session.commit()
        return render_login_form(client_id, redirect_uri, state, response_type, scope, error=error_message)

    # 1) brute_force 판정 — 최근 15분 안에 이 이메일로 5회 이상 실패했는지 먼저 확인
    #    (자격증명 확인보다 먼저 체크: 공격자가 굳이 올바른 비번 없이도 시도 자체로
    #     계속 소모전을 거는 걸 막기 위함)
    #    DB 종류(MySQL/SQLite 등)를 안 타도록 SQL 함수 대신 파이썬에서 시각 계산
    from datetime import datetime, timedelta
    fifteen_min_ago = datetime.utcnow() - timedelta(minutes=15)
    recent_failures = LoginFailure.query.filter(
        LoginFailure.email == email,
        LoginFailure.attempted_at >= fifteen_min_ago,
    ).count()
    brute_force_flag = recent_failures >= 5

    # 2) 계정 조회 + 비밀번호 검증
    account = Account.query.filter_by(email=email).first()
    credentials_ok = bool(account) and check_password_hash(account.password_hash, password)

    # 3) TOTP 검증 (계정에 TOTP가 켜져 있는 경우에만 요구)
    totp_ok = True
    if credentials_ok and account.totp_enabled:
        totp_ok = False
        if account.totp_secret and pyotp.TOTP(account.totp_secret).verify(totp_input, valid_window=1):
            totp_ok = True
        else:
            # 백업코드로 대체 시도 (해시 비교, 맞으면 그 코드는 즉시 소진 처리)
            for bc in BackupCode.query.filter_by(account_id=account.id, used=False).all():
                if check_password_hash(bc.code_hash, totp_input):
                    bc.used = True
                    db.session.commit()
                    totp_ok = True
                    break

    # 4) 로그인 시도 자체의 위험도를 Lambda에 직접 물어봄 (Worker 경유 안 함)
    #    night_access: 현재 서버 시각(UTC) 기준 0~5시를 야간으로 간주 — 추후 KST 등
    #    타임존 보정 필요 시 조정. unknown_location/device_fingerprint_mismatch는
    #    사용자별 과거 로그인 기록(위치/기기 이력) 축적 로직이 아직 없어 이번 단계는 보류.
    current_hour_utc = time.gmtime().tm_hour
    signals = {
        "brute_force": brute_force_flag,
        "night_access": current_hour_utc < 5,
    }
    risk_result = evaluate_login_risk(email, {**signals, "security_mfa_passed": totp_ok and credentials_ok})

    # 5) 최종 판정 — 자격증명/TOTP가 맞아도 위험점수가 차단이면 로그인 거부
    if not credentials_ok:
        return reject("이메일 또는 비밀번호가 올바르지 않습니다.")
    if not totp_ok:
        return reject("TOTP 코드(또는 백업코드)가 올바르지 않습니다.", record_failure=False)
    if not risk_result.get("allow", False):
        # 자격증명은 맞았으므로 계정 자체를 실패로 기록하진 않되, 로그에는 남김
        print(f"[LOGIN_BLOCKED] identity={email} action={risk_result.get('action')}")
        return render_login_form(
            client_id, redirect_uri, state, response_type, scope,
            error=f"보안 정책에 의해 로그인이 차단되었습니다 ({risk_result.get('action')})."
        )

    # 6) 통과 — 인가 코드 발급 후 Access(redirect_uri)로 돌려보냄
    auth_code = secrets.token_urlsafe(32)
    AUTH_CODES[auth_code] = {"email": email, "expires_at": time.time() + 60}

    return redirect(f"{redirect_uri}?code={auth_code}&state={state}")


@app.route('/token', methods=['POST'])
def token():
    code = request.form.get('code')
    grant_type = request.form.get('grant_type')

    if grant_type != 'authorization_code' or not code:
        return jsonify({"error": "unsupported_grant_type"}), 400

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
    # id_token 서명을 Access가 검증할 때 쓰는 공개키 (JWK 형식)
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
