from flask import Flask, request, jsonify, redirect, g
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
import base64
import json
import os
import threading
import time
import uuid

import boto3
import requests

app = Flask(__name__)
dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-2')
table = dynamodb.Table('risk_score_log')


# ==========================================================================
# B 계층: 세션 중 위험도 재확인
#
# Cloudflare Access(A 계층)는 세션을 새로 만들 때만 Worker -> Lambda 평가를 하고, 세션이
# 살아있는 동안(현재 15분)은 다시 평가하지 않는다. 그 사이의 빈틈을 메우기 위해, 이 앱이
# 페이지/API 요청을 처리하기 직전에 같은 Lambda(PDP)에 직접 물어본다.
#
# [설계 원칙] 판단(점수 계산, 임계값 비교)은 여기서 하지 않는다. 원본 값(시각, 국가, 접속
# 경로)만 Lambda로 넘기고 결과를 집행(통과/차단/재인증 안내)할 뿐이다 - Worker와 동일.
# Lambda 호출은 전부 check_risk() 한 곳을 거치므로, 나중에 로컬 실행 방식으로 옮길 때는
# 이 함수 안쪽만 바꾸면 된다.
# ==========================================================================
PDP_EVALUATE_URL = os.environ.get("PDP_EVALUATE_URL")
EVALUATE_SHARED_SECRET = os.environ.get("EVALUATE_SHARED_SECRET")
AUTH_DOMAIN = os.environ.get("AUTH_DOMAIN", "auth.xmcda.store")
PDP_TIMEOUT_SECONDS = 3

# 등급별 캐시 시간(초). 팀이 정한 값이며 표준에 근거가 있는 숫자가 아니다. 키는 Lambda가
# 응답으로 돌려주는 resource_tier 이름이고, 0이면 캐시하지 않고 매 요청마다 Lambda에 묻는다.
# Lambda가 알려주는 등급 이름을 쓰므로 이 앱은 경로별 임계값/등급 표를 따로 갖지 않는다.
# 등급을 모르는 경우(None)도 캐시하지 않는다.
CACHE_TTL_SECONDS = {
    "top_secret": 0,       # 관리자 콘솔, 감사 로그 API: 매 요청 검사
    "confidential": 90,    # 인사, 개발
    "internal": 300,       # 마케팅, 포털 공통
}

# 야간 접속 판정 기준(KST 22시~06시). risk_score_engine.py의 night_access 판정과 같은 값이어야
# 하며, 거기서 바꾸면 여기도 같이 바꿔야 한다. 캐시가 이 경계를 넘어 살아있으면, 21:58에 받은
# "통과"가 22:00 이후에도 쓰이는 빈틈이 생기므로 캐시 만료를 이 경계에서 끊는다.
NIGHT_START_HOUR_KST = 22
NIGHT_END_HOUR_KST = 6
KST = timezone(timedelta(hours=9))

_cache = {}
_cache_lock = threading.Lock()
_CACHE_MAX_ENTRIES = 1000


def seconds_until_night_boundary(now_utc):
    """지금부터 다음 야간 경계(KST 06:00 또는 22:00)까지 남은 초."""
    now_kst = now_utc.astimezone(KST)
    boundaries = []
    for hour in (NIGHT_END_HOUR_KST, NIGHT_START_HOUR_KST):
        boundary = now_kst.replace(hour=hour, minute=0, second=0, microsecond=0)
        if boundary <= now_kst:
            boundary += timedelta(days=1)
        boundaries.append(boundary)
    return (min(boundaries) - now_kst).total_seconds()


def _call_pdp(identity, country, resource_path):
    """Lambda(PDP) 호출. 실패하면 fail-closed(차단) 결과를 돌려준다 - Worker와 같은 정책."""
    if not PDP_EVALUATE_URL or not EVALUATE_SHARED_SECRET:
        print("[B_PDP_CONFIG_MISSING] PDP_EVALUATE_URL/EVALUATE_SHARED_SECRET 환경변수 없음", flush=True)
        return {"allow": False, "action": "pdp_unavailable", "error": True}
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
                "request_timestamp": datetime.now(timezone.utc).isoformat(),
                "geo_country": country,
                "resource_path": resource_path,
                "source": "B",
            },
            timeout=PDP_TIMEOUT_SECONDS,
        )
        if resp.status_code != 200:
            print(f"[B_PDP_HTTP_ERROR] status={resp.status_code}", flush=True)
            return {"allow": False, "action": "pdp_unavailable", "error": True}
        data = resp.json()
        return {
            "allow": data.get("allow") is True,
            "action": data.get("action", "unknown"),
            "score": data.get("score"),
            "resource_threshold": data.get("resource_threshold"),
            "resource_tier": data.get("resource_tier"),
            "error": False,
        }
    except Exception as e:
        print(f"[B_PDP_CALL_FAILED] {e}", flush=True)
        return {"allow": False, "action": "pdp_unavailable", "error": True}


def check_risk(identity, country, resource_path):
    """이 앱에서 Lambda를 부르는 유일한 통로.

    캐시 규칙:
      1) 허용 결과만 저장한다. 차단/step-up 필요 결과를 저장하면 /stepup에서 재인증을
         마치고 돌아와도 옛 결과가 남아 계속 막힌다.
      2) 같은 사용자라도 국가가 직전과 다르면 캐시를 버리고 즉시 다시 묻는다.
      3) 만료는 min(등급별 캐시 시간, 다음 야간 경계까지 남은 시간).
    """
    now = time.time()
    key = (identity, resource_path)

    with _cache_lock:
        entry = _cache.get(key)
        if entry:
            if entry["expires_at"] > now and entry["country"] == country:
                return {**entry["result"], "from_cache": True}
            del _cache[key]

    result = _call_pdp(identity, country, resource_path)
    result["from_cache"] = False

    if result["allow"] and not result["error"]:
        ttl = CACHE_TTL_SECONDS.get(result.get("resource_tier"), 0)
        if ttl > 0:
            until_boundary = seconds_until_night_boundary(datetime.fromtimestamp(now, timezone.utc))
            with _cache_lock:
                if len(_cache) >= _CACHE_MAX_ENTRIES:
                    for k in [k for k, v in _cache.items() if v["expires_at"] <= now]:
                        del _cache[k]
                if len(_cache) < _CACHE_MAX_ENTRIES:
                    _cache[key] = {
                        "expires_at": now + min(ttl, until_boundary),
                        "country": country,
                        "result": {k: v for k, v in result.items() if k != "from_cache"},
                    }
    return result


def _resource_path_for_request():
    """이 요청이 어느 자원인지. index.js(Worker)의 extractResourcePath와 같은 규칙:
    admin 서브도메인이면 /admin 또는 /api/db-data, 그 외에는 요청 경로 그대로."""
    path = request.path
    if request.host.startswith('admin.'):
        return '/api/db-data' if path == '/api/db-data' else '/admin'
    return path.rstrip('/') or '/'


def _stepup_url(is_api):
    # fetch 호출(API)은 인증 후 그 API 주소가 아니라 호출한 페이지(관리자 콘솔)로 돌아가야 함
    if is_api:
        return_url = f"https://{request.host}/"
    else:
        query = request.query_string.decode('utf-8', 'ignore')
        return_url = f"https://{request.host}{request.path}" + (f"?{query}" if query else "")
    return f"https://{AUTH_DOMAIN}/stepup?return_url={quote(return_url, safe='')}"


def _status_page(title, message, code):
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title></head>
    <body style="font-family:'Segoe UI',Tahoma,sans-serif;margin:40px;background:#f4f6f9;">
    <div style="background:white;padding:30px;border-radius:12px;max-width:520px;margin:60px auto;box-shadow:0 4px 6px rgba(0,0,0,0.1);">
    <h2>{title}</h2><p>{message}</p>
    <p><a href="https://{AUTH_DOMAIN}/logout">로그아웃</a></p></div></body></html>"""
    return html, code


def _deny_response(result):
    is_api = request.path.startswith('/api/')
    action = result.get("action", "")

    if action == "step_up_mfa_required":
        url = _stepup_url(is_api)
        if is_api:
            return jsonify({"status": "StepUpRequired", "message": "추가 인증이 필요합니다.", "stepup_url": url}), 403
        return redirect(url, code=302)

    # 차단 사유(점수, 신호)는 일부러 노출하지 않는다 - 공격자에게 우회 단서를 주지 않기 위해
    if result.get("error"):
        if is_api:
            return jsonify({"status": "Error", "message": "위험 판단 서버에 연결할 수 없어 접근을 차단했습니다."}), 503
        return _status_page("일시적으로 확인할 수 없습니다",
                            "위험 판단 서버에 연결할 수 없어 접근을 차단했습니다. 잠시 후 다시 시도해 주세요.", 503)

    if is_api:
        return jsonify({"status": "Denied", "message": "보안 정책에 따라 접근이 차단되었습니다."}), 403
    return _status_page("접근이 차단되었습니다", "보안 정책에 따라 이 페이지에 대한 접근이 차단되었습니다.", 403)


@app.before_request
def zero_trust_gate():
    # 등록된 라우트가 아니면(404) 판단할 필요 없음
    if request.endpoint is None:
        return None

    identity = request.headers.get('Cf-Access-Authenticated-User-Email')
    if not identity:
        # Access를 거치지 않은 요청이라는 뜻 - 판단 이전에 차단
        if request.path.startswith('/api/'):
            return jsonify({"status": "Denied", "message": "관리자 이메일 인증 헤더가 누락되어 접근이 거부되었습니다."}), 403
        return _status_page("접근이 거부되었습니다", "인증 정보가 없는 요청입니다.", 403)

    # [실측 필요] CF-IPCountry가 실제로 이 앱까지 도착하는지는 /debug-headers로 확인할 것.
    # 없으면 None이 전달되고, Lambda는 geo_country가 없으면 위치 이상으로 보지 않는다(오탐 방지).
    country = request.headers.get('CF-IPCountry')

    result = check_risk(identity, country, _resource_path_for_request())
    g.risk = result
    if result["allow"]:
        return None
    return _deny_response(result)


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
    user_email = request.headers.get('Cf-Access-Authenticated-User-Email')
    # 허용 점수는 화면에 직접 적어두지 않고 Lambda가 이 요청에 실제로 적용한 임계값을 보여준다
    # (페이지마다 옛 숫자를 따로 적어두면 RESOURCE_THRESHOLDS가 바뀔 때 어긋남)
    threshold = getattr(g, 'risk', {}).get('resource_threshold')
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
