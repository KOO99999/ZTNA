from flask import Flask, request, jsonify, g
import base64
import json
import os

import boto3

from zt_jwt import JwtVerifyError, log_jwt_failure, verify_access_jwt

app = Flask(__name__)
dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-2')
table = dynamodb.Table('risk_score_log')


AUTH_DOMAIN = os.environ.get("AUTH_DOMAIN", "auth.xmcda.store")

# [역할 분담] 위험도 판단(Lambda 호출, 캐시, 차단/재인증 응답)은 nginx 앞단의 판단 서비스(auth_gate.py)가
# 요청마다 하고, 통과한 요청만 이 앱에 도착한다. 그래서 이 앱은 Lambda를 부르지 않고 비밀키도 갖지 않는다.
# 대신 신원은 여기서도 Cloudflare Access JWT의 서명을 직접 검증한다(zt_jwt.py) - 앞단을 우회해 앱에
# 닿는 요청이나 위조된 헤더가 있어도 서명 검증을 통과한 이메일만 신원으로 인정하는 이중 확인이다.


def _status_page(title, message, code):
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title></head>
    <body style="font-family:'Segoe UI',Tahoma,sans-serif;margin:40px;background:#f4f6f9;">
    <div style="background:white;padding:30px;border-radius:12px;max-width:520px;margin:60px auto;box-shadow:0 4px 6px rgba(0,0,0,0.1);">
    <h2>{title}</h2><p>{message}</p>
    <p><a href="https://{AUTH_DOMAIN}/logout">로그아웃</a></p></div></body></html>"""
    return html, code


def _threshold_from_gate():
    """판단 서비스가 nginx를 통해 알려준 '이 요청에 적용된 임계값'(화면 표시용). 정수가 아니면 None."""
    raw = request.headers.get('X-ZT-Threshold', '')
    return int(raw) if raw.isdigit() and len(raw) <= 4 else None


@app.before_request
def identity_gate():
    # 등록된 라우트가 아니면(404) 판단할 필요 없음
    if request.endpoint is None:
        return None

    # 신원은 서명 검증을 통과한 JWT의 email만 사용한다(평문 이메일 헤더는 쓰지 않음).
    # 검증 실패 = 기록 후 즉시 차단.
    try:
        claims = verify_access_jwt(request.headers.get('Cf-Access-Jwt-Assertion'))
    except JwtVerifyError as e:
        log_jwt_failure(e.reason, request.host, request.path, request.remote_addr,
                        request.headers.get('Cf-Connecting-Ip'))
        if request.path.startswith('/api/'):
            return jsonify({"status": "Denied", "message": "인증 토큰 검증에 실패하여 접근이 거부되었습니다."}), 403
        return _status_page("접근이 거부되었습니다", "인증 정보를 확인할 수 없는 요청입니다.", 403)
    g.identity = claims["email"]
    g.threshold = _threshold_from_gate()
    return None


if os.environ.get("ZT_DEBUG_HEADERS") == "1":
    # [임시] CF-IPCountry 등 헤더가 Cloudflare -> nginx -> Flask까지 실제로 도착하는지 확인하는
    # 용도. 환경변수가 켜졌을 때만 등록되고(기본 꺼짐), 쿠키/토큰 값은 가린다. 확인이 끝나면
    # 환경변수를 끄거나 이 블록을 삭제할 것.
    @app.route('/debug-headers')
    def debug_headers():
        hidden = ('cookie', 'authorization', 'cf-access-jwt-assertion')
        headers = {}
        for name, value in request.headers.items():
            headers[name] = f"[가림, {len(value)}자]" if name.lower() in hidden else value

        jwt_info = {}
        token = request.headers.get('Cf-Access-Jwt-Assertion')
        if token:
            try:
                part = token.split('.')[1]
                payload = json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
                jwt_info = {"claim_keys": sorted(payload.keys()), "country": payload.get("country")}
            except Exception as e:
                jwt_info = {"error": str(e)}

        return jsonify({
            "host": request.host,
            "path": request.path,
            "remote_addr": request.remote_addr,
            "CF-IPCountry": request.headers.get('CF-IPCountry'),
            "jwt_info(서명 미검증, 확인용)": jwt_info,
            "headers": headers,
        })


def render_page(title, content_html, is_public=False):
    user_email = getattr(g, 'identity', None)   # 서명 검증된 JWT의 email(게이트에서 설정)
    # 허용 점수는 화면에 직접 적어두지 않고 Lambda가 이 요청에 실제로 적용한 임계값을 보여준다
    # (페이지마다 옛 숫자를 따로 적어두면 RESOURCE_THRESHOLDS가 바뀔 때 어긋남).
    # 값은 판단 서비스가 nginx를 통해 넘겨준 X-ZT-Threshold 헤더에서 읽는다(앱이 Lambda를 부르지 않음).
    threshold = getattr(g, 'threshold', None)
    threshold_str = f"{threshold}점" if threshold is not None else "확인 불가"

    if is_public and not user_email:
        user_status_html = "🌐 <strong>접속 상태:</strong> 게스트 (인증 불필요 오픈 서비스)"
    else:
        email_str = user_email if user_email else "인증 정보 없음"
        user_status_html = f"🔑 <strong>인증된 관리자 계정:</strong> {email_str}<br>🛡️ <strong>허용 위험점수(이하 통과):</strong> {threshold_str}"
        # 로그아웃: SSO 세션(auth_app.py)과 Cloudflare Access 세션을 순차 정리하기 위해
        # 반드시 auth.xmcda.store/logout으로 보내야 함 (chained logout, portal_app.py엔 /logout 라우트 없음)
        user_status_html += '<br><a href="https://auth.xmcda.store/logout">로그아웃</a>'

    inactivity_script = """
    <script>
        let inactivityTimer;
        const INACTIVITY_LIMIT = 15 * 60 * 1000; // 15분

        function resetInactivityTimer() {
            clearTimeout(inactivityTimer);
            inactivityTimer = setTimeout(onInactivityTimeout, INACTIVITY_LIMIT);
        }

        function onInactivityTimeout() {
            alert("⚠️ 장시간 사용자 활동이 없어 위험 점수가 가산되었습니다.\\n보안을 위해 다시 로그인해 주세요.");
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
def general():
    # [정리] admin.xmcda.store로 들어온 요청은 여기서 관리자 콘솔을 보여준다.
    # 서브도메인 자체가 "어느 건물이냐"를 정하니, 그 건물의 root('/')가 관리자
    # 페이지가 되는 게 자연스러움(admin.example.com/admin처럼 경로를 또 붙이는 건
    # 불필요한 중복). Flask는 기본적으로 도메인을 구분 안 해서, 이 체크를 직접 함.
    if request.host.startswith('admin.'):
        return admin_console()

    html = """
    <p>전 직원 공통 포털 홈입니다.</p>
    <ul>
        <li>Cloudflare Access가 전체 직원(all_employees 그룹) 계정만 통과시킴</li>
        <li>서비스 기본 정보 및 공개 게시판 제공</li>
    </ul>
    <a href="https://admin.xmcda.store"><button style="background-color: #dc3545;">관리자 콘솔 바로가기</button></a>
    """
    return render_page("[Portal] 전사 공통 대시보드", html, is_public=False)

def admin_console():
    html = """
    <p><strong>⚠️ 관리자 전용 영역입니다.</strong></p>
    <p><small>💡 15분간 아무런 활동이 없으면 위험 점수 History Decay 정책에 따라 자동 세션 만료 및 재인증이 유도됩니다.</small></p>
    <button onclick="fetchData('admin_logs')" style="background-color: #dc3545;">DynamoDB 감사 로그 전체 조회</button>
    <div id="result"></div>
    <script>
        function fetchData(datatype) {
            document.getElementById('result').innerHTML = '<p>DynamoDB 테이블 스캔 중...</p>';
            fetch('/api/db-data?type=' + datatype)
                .then(res => res.json().then(data => ({ status: res.status, data: data })))
                .then(({ status, data }) => {
                    // B 계층이 "추가 인증 필요"로 판단한 경우: 인증 페이지로 보냈다가 이 페이지로 돌아옴
                    if (status === 403 && data.status === 'StepUpRequired' && data.stepup_url) {
                        document.getElementById('result').innerHTML = '<p>추가 인증이 필요합니다. 인증 페이지로 이동합니다...</p>';
                        window.location.href = data.stepup_url;
                        return;
                    }
                    document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                })
                .catch(() => {
                    document.getElementById('result').innerHTML = '<p>요청에 실패했습니다. 세션이 만료되었을 수 있으니 페이지를 새로고침해 주세요.</p>';
                });
        }
    </script>
    """
    return render_page("[Admin Tier] 관리자 콘솔", html, is_public=False)

@app.route('/dev')
def dev_page():
    html = "<p>개발팀 전용 공간입니다. (Cloudflare Access가 개발팀 계정만 통과시킴)</p>"
    return render_page("[Dev Team] 개발팀 페이지", html, is_public=False)

@app.route('/marketing')
def marketing_page():
    html = "<p>마케팅팀 전용 공간입니다. (Cloudflare Access가 마케팅팀 계정만 통과시킴)</p>"
    return render_page("[Marketing Team] 마케팅팀 페이지", html, is_public=False)

@app.route('/hr')
def hr_page():
    html = "<p>인사팀 전용 공간입니다. (Cloudflare Access가 인사팀 계정만 통과시킴)</p>"
    return render_page("[HR Team] 인사팀 페이지", html, is_public=False)

@app.route('/api/db-data')
def get_db_data():
    # [보안] admin과 동일한 이유 - admin_api Access 앱도 admin.xmcda.store 아래로
    # 옮겼으므로, xmcda.store/api/db-data로 직접 오는 요청은 여기서 거부.
    if not request.host.startswith('admin.'):
        return jsonify({"status": "Denied", "message": "잘못된 경로입니다."}), 404

    data_type = request.args.get('type')
    user_email = getattr(g, 'identity', None)   # 서명 검증된 JWT의 email(게이트에서 설정)

    if not user_email:
        return jsonify({
            "status": "Denied",
            "message": "검증된 신원 정보가 없어 DB 접근이 거부되었습니다."
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
