from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import boto3
import os

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

# TODO(다음 세션): /authorize, /token, /userinfo — OIDC 로그인서버 라우트 추가 예정
#   (accounts/backup_codes/login_failures 테이블은 이제 준비됨, 위 모델 사용)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
