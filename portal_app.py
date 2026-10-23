from flask import Flask, request, jsonify, g, redirect
import base64
import hashlib
import hmac
import html as _html
import json
import os
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import boto3

from zt_jwt import JwtVerifyError, log_jwt_failure, verify_access_jwt

app = Flask(__name__)
dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-2')
table = dynamodb.Table('risk_score_log')
lambda_client = boto3.client('lambda', region_name='ap-northeast-2')

# 관리자 콘솔 설정. ADMIN_EMAILS는 Terraform의 admin_allowed_emails와 같은 값(쉼표 구분)이다.
# Cloudflare Access가 이미 걸러주지만, 영향이 큰 기능(위험 상태 해제)이라 앱에서도 한 번 더 확인한다.
ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "").split(",") if e.strip()}
RISK_ADMIN_FUNCTION = os.environ.get("RISK_ADMIN_FUNCTION", "")
# 포털 홈의 "내 업무 앱" 목록용 계정 소속 표("이메일=소속;..."). Terraform locals.account_departments_env와 같은 값으로,
# 로그인 서버가 DB 소속을 맞출 때 쓰는 목록과 같다. 링크를 보여줄지만 정하며 접근 허용/차단은 Access가 한다.
ACCOUNT_DEPARTMENTS = {}
for _item in os.environ.get("ACCOUNT_DEPARTMENTS", "").split(";"):
    _email, _sep, _dept = _item.partition("=")
    if _sep and _email.strip() and _dept.strip():
        ACCOUNT_DEPARTMENTS[_email.strip().lower()] = _dept.strip()
# 소속 -> 보여줄 앱 (서브도메인 이름, 화면 이름)
DEPARTMENT_APPS = {
    "dev": [("dev", "개발팀 페이지", "💻", "소스코드·서버 접근 업무", "기밀")],
    "marketing": [("marketing", "마케팅팀 페이지", "📣", "캠페인·홍보 자료", "내부")],
    "hr": [("hr", "인사팀 페이지", "🗂️", "인사·개인정보 업무", "기밀")],
    "admin": [("admin", "관리자 콘솔", "🛡️", "감사 로그·위험 상태 해제", "최고기밀")],
}
# 해제 폼의 CSRF 토큰 서명 키. 서버 시작 때 만들어 환경변수로 넘긴다(여러 워커가 같은 값을 써야 함).
# 없으면 프로세스마다 임의 값(단일 워커에서만 동작) - 키를 못 읽어도 위조 토큰은 못 만든다.
CSRF_SECRET = (os.environ.get("CSRF_SECRET") or base64.b64encode(os.urandom(32)).decode()).encode()
CSRF_TTL_SECONDS = 30 * 60
LOG_SCAN_CAP = 3000      # 감사 로그는 최대 이만큼만 읽어서 최근 순으로 정렬
LOG_SHOW = 50            # 화면에는 최근 이만큼만 표시
KST = timezone(timedelta(hours=9))


AUTH_DOMAIN = os.environ.get("AUTH_DOMAIN", "auth.xmcda.store")
PORTAL_DOMAIN = AUTH_DOMAIN.replace("auth.", "", 1)

# [역할 분담] 위험도 판단(Lambda 호출, 캐시, 차단/재인증 응답)은 nginx 앞단의 판단 서비스(auth_gate.py)가
# 요청마다 하고, 통과한 요청만 이 앱에 도착한다. 그래서 이 앱은 Lambda를 부르지 않고 비밀키도 갖지 않는다.
# 대신 신원은 여기서도 Cloudflare Access JWT의 서명을 직접 검증한다(zt_jwt.py) - 앞단을 우회해 앱에
# 닿는 요청이나 위조된 헤더가 있어도 서명 검증을 통과한 이메일만 신원으로 인정하는 이중 확인이다.


def esc(value):
    """화면에 넣는 모든 값은 이 함수를 거친다(저장된 로그의 resource_path 같은 값이 HTML로 해석되는 것 방지)."""
    return _html.escape(str(value), quote=True)


def _csrf_token(identity, ts=None):
    ts = str(int(time.time()) if ts is None else ts)
    mac = hmac.new(CSRF_SECRET, f"{identity}|{ts}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{mac}"


def _csrf_valid(identity, token):
    try:
        ts, _mac = (token or "").split(".", 1)
        age = time.time() - int(ts)
    except (ValueError, AttributeError):
        return False
    if age < 0 or age > CSRF_TTL_SECONDS:
        return False
    return hmac.compare_digest(_csrf_token(identity, ts), token)


def _same_origin():
    """POST 요청의 Origin(없으면 Referer) 호스트가 이 요청의 호스트와 같아야 한다. 둘 다 없으면 거부."""
    source = request.headers.get("Origin") or request.headers.get("Referer")
    if not source:
        return False
    return urlparse(source).netloc.lower() == request.host.lower()


def _is_admin(identity):
    return bool(identity) and identity.lower() in ADMIN_EMAILS


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    resp.headers["Referrer-Policy"] = "same-origin"
    # 모든 화면을 브라우저가 저장하지 않게 한다. 저장되면 로그아웃 후 '뒤로 가기'로 이전 화면이 그대로
    # 다시 보인다(공용 PC에서 다음 사람이 볼 수 있음). no-store면 뒤로 가기도 서버에 다시 요청하므로
    # Access가 로그인 화면으로 보낸다. (예전엔 admin 화면에만 붙어 있었음)
    resp.headers["Cache-Control"] = "no-store"
    return resp


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


def render_page(title, content_html, is_public=False, wide=False):
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
        user_status_html = f"🔑 <strong>로그인 계정:</strong> {esc(email_str)}<br>🛡️ <strong>허용 위험점수(이하 통과):</strong> {threshold_str}"
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
        <title>{esc(title)}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background-color: #f4f6f9; color: #333; }}
            .card {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: {'1100px' if wide else '650px'}; margin: 0 auto; }}
            .badge {{ display: inline-block; padding: 6px 14px; background-color: #007bff; color: white; border-radius: 20px; font-size: 0.85em; font-weight: bold; }}
            .badge-public {{ background-color: #28a745; }}
            .user-info {{ background: #e9ecef; padding: 12px 18px; border-radius: 8px; margin-top: 15px; font-size: 0.9em; border-left: 4px solid #007bff; }}
            button {{ background: #28a745; color: white; border: none; padding: 10px 18px; border-radius: 6px; cursor: pointer; font-size: 0.95em; margin-top: 15px; font-weight: bold; }}
            button:hover {{ background: #218838; }}
            table {{ border-collapse: collapse; width: 100%; font-size: 0.85em; margin-top: 8px; }}
            th, td {{ border: 1px solid #ddd; padding: 6px 8px; text-align: left; word-break: break-all; }}
            th {{ background: #f1f3f5; }}
            .msg {{ padding: 10px 14px; border-radius: 6px; background: #fff3cd; margin: 12px 0; }}
            .msg-ok {{ background: #d4edda; }}
            .msg-err {{ background: #f8d7da; }}
            button.small {{ margin-top: 0; padding: 4px 10px; font-size: 0.85em; background: #dc3545; }}
            pre {{ background: #1e1e1e; color: #4ec9b0; padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 0.9em; }}
            .section-title {{ margin: 24px 0 12px; font-size: 1.05em; }}
            .app-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 14px; }}
            .app-tile {{ display: flex; flex-direction: column; gap: 6px; padding: 18px; border: 1px solid #e3e7ee; border-radius: 12px;
                         background: #fafbfd; color: inherit; text-decoration: none; transition: box-shadow .15s, transform .15s, border-color .15s; }}
            .app-tile:hover {{ border-color: #007bff; box-shadow: 0 6px 16px rgba(0,123,255,0.15); transform: translateY(-2px); }}
            .app-icon {{ font-size: 1.8em; line-height: 1; }}
            .app-name {{ font-weight: bold; font-size: 1.05em; }}
            .app-desc {{ color: #666; font-size: 0.85em; }}
            .app-meta {{ color: #999; font-size: 0.75em; margin-top: 4px; }}
            .app-tier {{ display: inline-block; background: #e7f1ff; color: #0056b3; border-radius: 10px; padding: 1px 8px; margin-right: 6px; font-weight: bold; }}
            .app-empty {{ color: #666; background: #f8f9fa; padding: 14px; border-radius: 8px; }}
        </style>
        <script>
          // 로그아웃 후 '뒤로 가기'로 브라우저가 저장해 둔 화면(bfcache)을 그대로 꺼내 보여주는 경우가 있다
          // (Cache-Control: no-store만으로는 브라우저에 따라 막히지 않음). 저장된 화면으로 돌아오면
          // 다시 불러오게 해서, 서버(Access)가 지금 로그인 상태인지 다시 확인하게 한다.
          window.addEventListener('pageshow', function (e) {{ if (e.persisted) window.location.reload(); }});
        </script>
        {inactivity_script}
    </head>
    <body>
        <div class="card">
            <span class="badge {'badge-public' if is_public else ''}">{'Public Access Area' if is_public else 'Zero Trust Protected Area'}</span>
            <h2>{esc(title)}</h2>
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
    # [서브도메인 분리] dev/marketing/hr도 admin과 같은 방식으로 호스트가 곧 앱이다.
    host = request.host.split(':')[0].lower()
    for team, page in TEAM_PAGES.items():
        if host == f"{team}.{PORTAL_DOMAIN}":
            return page()

    # 내 소속에서 쓸 수 있는 앱만 링크로 보여준다(Okta 대시보드·Microsoft My Apps처럼 "내 앱" 목록).
    # 표시만 정하는 것이고, 링크를 직접 입력해도 실제 허용/차단은 각 앱의 Access 정책이 한다.
    dept = ACCOUNT_DEPARTMENTS.get((getattr(g, "identity", "") or "").lower())
    apps = DEPARTMENT_APPS.get(dept, [])
    if apps:
        tiles = "".join(
            f'<a class="app-tile" href="https://{sub}.{PORTAL_DOMAIN}/">'
            f'<span class="app-icon">{icon}</span>'
            f'<span class="app-name">{esc(name)}</span>'
            f'<span class="app-desc">{esc(desc)}</span>'
            f'<span class="app-meta"><span class="app-tier">{esc(tier)}</span>{esc(sub)}.{esc(PORTAL_DOMAIN)}</span>'
            f'</a>'
            for sub, name, icon, desc, tier in apps)
        app_html = f'<h3 class="section-title">내 업무 앱</h3><div class="app-grid">{tiles}</div>'
    else:
        app_html = ('<h3 class="section-title">내 업무 앱</h3>'
                    '<p class="app-empty">사용할 수 있는 업무 앱이 없습니다. 필요하면 관리자에게 요청하세요.</p>')
    html = """
    <p>전 직원 공통 포털 홈입니다.</p>
    <ul>
        <li>Cloudflare Access가 전체 직원(all_employees 그룹) 계정만 통과시킴</li>
        <li>서비스 기본 정보 및 공개 게시판 제공</li>
    </ul>
    """ + app_html
    return render_page("[Portal] 전사 공통 대시보드", html, is_public=False)

ADMIN_MESSAGES = {
    "released": ("ok", "해제했습니다. 해당 사용자는 다음 요청부터 이 신호로 막히지 않습니다."),
    "released_noaudit": ("err", "해제는 됐지만 감사 기록 저장에 실패했습니다. 판정 로그를 확인하세요."),
    "not_active": ("err", "이미 해제되었거나 활성 상태가 아닙니다."),
    "self_release": ("err", "본인의 신호는 직접 해제할 수 없습니다. 다른 관리자에게 요청하세요."),
    "invalid": ("err", "잘못된 요청입니다."),
    "failed": ("err", "처리에 실패했습니다. 잠시 후 다시 시도하세요."),
    "csrf": ("err", "요청을 확인할 수 없습니다(페이지를 새로고침한 뒤 다시 시도하세요)."),
    "forbidden": ("err", "관리자 권한이 없습니다."),
}


def _invoke_risk_admin(payload):
    """risk_admin Lambda를 AWS 권한(인스턴스 역할)으로 직접 호출. 실패하면 None."""
    if not RISK_ADMIN_FUNCTION:
        return None
    try:
        resp = lambda_client.invoke(FunctionName=RISK_ADMIN_FUNCTION, InvocationType="RequestResponse",
                                    Payload=json.dumps(payload).encode())
        if resp.get("FunctionError"):
            print("risk_admin 함수 오류:", resp.get("FunctionError"))
            return None
        return json.loads(resp["Payload"].read())
    except Exception as e:
        print("risk_admin 호출 실패:", str(e))
        return None


def _fmt_ts(value):
    try:
        return datetime.fromtimestamp(int(value), KST).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OverflowError, OSError):
        return "-"


def _recent_logs():
    """risk_score_log를 읽어(최대 LOG_SCAN_CAP건) 최근 순으로 정렬. (목록, 잘렸는지) 반환. 실패하면 (None, False)."""
    items, kwargs, truncated = [], {}, False
    try:
        while True:
            resp = table.scan(**kwargs)
            items.extend(resp.get("Items", []))
            last = resp.get("LastEvaluatedKey")
            if len(items) >= LOG_SCAN_CAP:
                truncated = bool(last) or len(items) > LOG_SCAN_CAP
                items = items[:LOG_SCAN_CAP]
                break
            if not last:
                break
            kwargs["ExclusiveStartKey"] = last
    except Exception as e:
        print("감사 로그 조회 실패:", str(e))
        return None, False
    items.sort(key=lambda it: int(it.get("timestamp", 0) or 0), reverse=True)
    return items[:LOG_SHOW], truncated


def admin_console():
    identity = g.identity
    if not _is_admin(identity):
        return _status_page("접근이 거부되었습니다", "관리자 권한이 필요한 영역입니다.", 403)

    kind, text = ADMIN_MESSAGES.get(request.args.get("msg", ""), (None, None))
    msg_html = f'<div class="msg msg-{kind}">{esc(text)}</div>' if kind else ""

    # --- 위험 상태가 걸린 사용자 ---
    listing = _invoke_risk_admin({"action": "list", "actor": identity})
    if not listing or not listing.get("ok"):
        risk_html = '<p class="msg msg-err">위험 상태 목록을 불러오지 못했습니다.</p>'
    elif not listing.get("items"):
        risk_html = "<p>현재 위험 상태가 걸린 사용자는 없습니다.</p>"
    else:
        token = _csrf_token(identity)
        rows = ""
        for it in listing["items"]:
            rows += (f"<tr><td>{esc(it.get('identity'))}</td><td>{esc(it.get('signal'))}</td>"
                     f"<td>{esc(_fmt_ts(it.get('set_at')))}</td><td>{esc(_fmt_ts(it.get('last_seen')))}</td>"
                     f"<td>{esc(it.get('source'))}</td><td>"
                     f'<form method="post" action="/risk/release" style="margin:0" onsubmit="return confirm(\'이 신호를 해제할까요?\');">'
                     f'<input type="hidden" name="csrf" value="{esc(token)}">'
                     f'<input type="hidden" name="identity" value="{esc(it.get("identity"))}">'
                     f'<input type="hidden" name="signal" value="{esc(it.get("signal"))}">'
                     f'<button class="small" type="submit">해제</button></form></td></tr>')
        more = "<p><small>목록이 길어 일부만 표시했습니다.</small></p>" if listing.get("truncated") else ""
        risk_html = ("<table><tr><th>사용자</th><th>신호</th><th>걸린 시각</th><th>마지막 감지</th><th>출처</th><th></th></tr>"
                     + rows + "</table>" + more)

    # --- 최근 판정 로그: 빨간 버튼(/?logs=1)을 눌렀을 때만 읽는다(평소에는 DynamoDB를 조회하지 않음) ---
    if request.args.get("logs") == "1":
        logs, truncated = _recent_logs()
        if logs is None:
            log_body = '<p class="msg msg-err">감사 로그를 불러오지 못했습니다.</p>'
        elif not logs:
            log_body = "<p>기록이 없습니다.</p>"
        else:
            rows = ""
            for it in logs:
                reasons = it.get("reasons") or []
                reasons = ", ".join(str(r) for r in reasons) if isinstance(reasons, (list, tuple, set)) else str(reasons)
                rows += (f"<tr><td>{esc(_fmt_ts(it.get('timestamp')))}</td><td>{esc(it.get('identity', '-'))}</td>"
                         f"<td>{esc(it.get('resource_path', '-'))}</td><td>{esc(it.get('risk_score', '-'))}</td>"
                         f"<td>{esc(it.get('resource_threshold', '-'))}</td><td>{esc(it.get('action', '-'))}</td>"
                         f"<td>{esc(it.get('source', '-'))}</td><td>{esc(reasons)}</td></tr>")
            note = (f"최근 {len(logs)}건 (최신순)" +
                    (f" - 로그가 많아 최근 {LOG_SCAN_CAP}건 안에서만 정렬했습니다" if truncated else ""))
            log_body = (f"<p><small>{esc(note)}</small></p><table><tr><th>시각(KST)</th><th>사용자</th><th>자원</th><th>점수</th>"
                        "<th>임계값</th><th>판정</th><th>출처</th><th>사유</th></tr>" + rows + "</table>")
        log_html = ('<a href="/"><button type="button" style="background-color: #6c757d;">로그 닫기</button></a>' + log_body)
    else:
        log_html = '<a href="/?logs=1"><button type="button" style="background-color: #dc3545;">DynamoDB 감사 로그 조회</button></a>'

    html = f"""
    <p><strong>⚠️ 관리자 전용 영역입니다.</strong></p>
    <p><small>💡 접속 세션은 15분마다 위험도를 다시 판정하며, 30분 이상 사용하지 않으면 비밀번호와 2단계 인증으로 다시 로그인해야 합니다.</small></p>
    {msg_html}
    <h3>위험 상태가 걸린 사용자</h3>
    <p><small>해제하면 판정 기록이 남습니다. 본인 항목은 다른 관리자가 해제해야 합니다.</small></p>
    {risk_html}
    <h3>최근 판정 로그</h3>
    {log_html}
    """
    return render_page("[Admin Tier] 관리자 콘솔", html, is_public=False, wide=True)


@app.route('/risk/release', methods=['POST'])
def risk_release():
    if not request.host.startswith('admin.'):
        return _status_page("찾을 수 없음", "잘못된 경로입니다.", 404)
    identity = g.identity
    if not _is_admin(identity):
        return _status_page("접근이 거부되었습니다", "관리자 권한이 필요한 영역입니다.", 403)
    if not _same_origin() or not _csrf_valid(identity, request.form.get("csrf")):
        return redirect("/?msg=csrf", code=303)

    result = _invoke_risk_admin({"action": "release", "actor": identity,
                                 "identity": request.form.get("identity", ""),
                                 "signal": request.form.get("signal", "")})
    if result is None:
        code = "failed"
    elif result.get("ok"):
        code = "released" if result.get("audit", True) else "released_noaudit"
    else:
        code = result.get("error") if result.get("error") in ADMIN_MESSAGES else "failed"
    return redirect(f"/?msg={code}", code=303)


# [서브도메인 분리] 팀 페이지는 각 서브도메인(dev.xmcda.store 등)의 첫 화면으로만 연다.
# 예전 경로 주소(xmcda.store/dev 등)는 라우트 자체를 지웠다(404). 그 주소는 이제 포털 앱(전 직원 공통)
# 범위라, 거기서 팀 페이지를 보여주면 다른 팀 직원도 볼 수 있게 되기 때문이다.


def dev_page():
    html = "<p>개발팀 전용 공간입니다. (Cloudflare Access가 개발팀 계정만 통과시킴)</p>"
    return render_page("[Dev Team] 개발팀 페이지", html, is_public=False)

def marketing_page():
    html = "<p>마케팅팀 전용 공간입니다. (Cloudflare Access가 마케팅팀 계정만 통과시킴)</p>"
    return render_page("[Marketing Team] 마케팅팀 페이지", html, is_public=False)

def hr_page():
    html = "<p>인사팀 전용 공간입니다. (Cloudflare Access가 인사팀 계정만 통과시킴)</p>"
    return render_page("[HR Team] 인사팀 페이지", html, is_public=False)


TEAM_PAGES = {"dev": dev_page, "marketing": marketing_page, "hr": hr_page}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
