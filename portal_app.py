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
from zt_mtls import build_server_context, client_allowed, client_cert_cn, mtls_settings
from zt_ui import TIER_LABELS, alert, app_shell, icon, link_button, status_page, tier_chip

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
# 소속 -> 포털 홈에 보여 줄 업무 앱 (서브도메인, 이름, 아이콘, 설명, 보안 등급). 등급은 엔진 RESOURCE_TIERS와 같은 구성.
DEPARTMENT_APPS = {
    "dev": [("dev", "개발 워크스페이스", "code", "소스코드·서버 접근 업무", "기밀")],
    "marketing": [("marketing", "마케팅 워크스페이스", "megaphone", "캠페인·홍보 자료", "내부")],
    "hr": [("hr", "인사 워크스페이스", "users", "인사·개인정보 업무", "기밀")],
    "admin": [("admin", "관리자 콘솔", "settings", "위험 상태 해제·판정 기록", "최고기밀")],
}
# 팀 앱 첫 화면 정보 (서브도메인 -> 이름, 아이콘, 허용 소속 이름, 설명)
TEAM_INFO = {
    "dev": ("개발 워크스페이스", "code", "개발팀", "개발팀 전용 업무 공간입니다. 소스코드와 서버 접근 업무를 다룹니다."),
    "marketing": ("마케팅 워크스페이스", "megaphone", "마케팅팀", "마케팅팀 전용 업무 공간입니다. 캠페인과 홍보 자료를 다룹니다."),
    "hr": ("인사 워크스페이스", "users", "인사팀", "인사팀 전용 업무 공간입니다. 임직원 개인정보를 다루므로 접근 기록이 모두 남습니다."),
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
    return status_page(title, message, f"https://{AUTH_DOMAIN}/logout", home_href=f"https://{PORTAL_DOMAIN}/"), code


def _tier_from_gate():
    """판단 서비스가 알려준 이 요청의 보안 등급(엔진 등급 이름). 아는 값이 아니면 None."""
    raw = request.headers.get('X-ZT-Tier', '')
    return raw if raw in TIER_LABELS else None


def _threshold_from_gate():
    """판단 서비스가 nginx를 통해 알려준 '이 요청에 적용된 임계값'(화면 표시용). 정수가 아니면 None."""
    raw = request.headers.get('X-ZT-Threshold', '')
    return int(raw) if raw.isdigit() and len(raw) <= 4 else None


# [Web->WAS mTLS] 웹 서버(nginx)의 클라이언트 인증서로 들어온 요청만 받는다(zt_mtls.py). 연결 단계에서 내부 CA
# 서명이 없는 인증서는 이미 거부되고, 여기서는 그 인증서의 이름이 웹 서버(MTLS_ALLOWED_CLIENT)인지 한 번 더 본다.
MTLS = mtls_settings()


@app.before_request
def mtls_client_gate():
    if MTLS and not client_allowed(request.environ, MTLS[3]):
        print(f"[MTLS_CLIENT_REJECTED] cn={client_cert_cn(request.environ)!r} remote={request.remote_addr}", flush=True)
        return "forbidden", 403
    return None


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
    g.tier = _tier_from_gate()
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


# 15분 동안 아무 입력이 없으면 로그아웃한다(13분에 미리 알림, "계속 사용"을 누르면 연장).
# 로그아웃은 로그인 서버의 /logout으로 보내 모든 앱의 세션을 같이 지운다(앱 하나만 지우면 다른 앱 세션이 남음).
_INACTIVITY_SCRIPT = """<div class="toast" id="idle-toast" role="status"><div><b>곧 자동 로그아웃됩니다</b>
<div class="small" style="opacity:.8;margin-top:2px">2분 동안 입력이 없으면 보안을 위해 로그아웃합니다.</div></div>
<button class="btn btn-secondary" type="button" id="idle-keep">계속 사용</button></div>
<script>
(function(){var WARN=13*60*1000,LIMIT=15*60*1000,t1,t2,toast=document.getElementById('idle-toast');
var out=document.querySelector('[data-logout]');var url=out?out.getAttribute('href'):'/';
function reset(){clearTimeout(t1);clearTimeout(t2);toast.classList.remove('show');
t1=setTimeout(function(){toast.classList.add('show');},WARN);t2=setTimeout(function(){window.location.href=url;},LIMIT);}
['mousemove','keydown','click','scroll','touchstart'].forEach(function(ev){document.addEventListener(ev,function(){if(!toast.classList.contains('show'))reset();},{passive:true});});
document.getElementById('idle-keep').addEventListener('click',reset);reset();})();
</script>"""

# 로그아웃 후 '뒤로 가기'로 브라우저가 저장해 둔 화면(bfcache)을 그대로 꺼내 보여주는 경우가 있다
# (Cache-Control: no-store만으로는 브라우저에 따라 막히지 않음). 저장된 화면으로 돌아오면 다시 불러오게 한다.
_BFCACHE_SCRIPT = "<script>window.addEventListener('pageshow',function(e){if(e.persisted)window.location.reload();});</script>"


def session_card():
    """내 세션 정보: 계정, 이 서비스의 보안 등급, 이 요청에 실제로 적용된 허용 위험점수(판단 서비스가 알려준 값)."""
    threshold = getattr(g, 'threshold', None)
    threshold_str = f"{threshold}점 이하" if threshold is not None else "확인 불가"
    tier = getattr(g, 'tier', None)
    tier_html = tier_chip(tier) if tier else '<span class="muted">확인 불가</span>'
    return f"""<section class="card"><h2 class="card-title">{icon("shield-check", 18)}내 접속 보안 상태</h2>
      <dl class="kv" style="margin-bottom:12px">
        <dt>로그인 계정</dt><dd>{esc(getattr(g, 'identity', None) or '-')}</dd>
        <dt>이 서비스 보안 등급</dt><dd>{tier_html}</dd>
        <dt>허용 위험점수</dt><dd>{esc(threshold_str)}</dd>
      </dl>
      <p class="small muted">접속 위치·시간·기기·IP 평판으로 매 요청 위험도를 다시 계산합니다.
      평소와 다르면 추가 인증을 요청하며, 15분 동안 사용하지 않으면 자동으로 로그아웃됩니다.</p></section>"""


def render_page(title, content_html, heading=None, desc=None, crumb=None, wide=False, actions_html=""):
    """업무 화면 공통 틀(zt_ui.app_shell) + 자동 로그아웃 + 뒤로 가기 캐시 방지."""
    return app_shell(title, content_html, user=getattr(g, 'identity', None), heading=heading or title, desc=desc,
                     crumb=crumb, wide=wide, actions_html=actions_html, home_href=f"https://{PORTAL_DOMAIN}/",
                     logout_href=f"https://{AUTH_DOMAIN}/logout", head_extra=_BFCACHE_SCRIPT, foot_html=_INACTIVITY_SCRIPT)


def _crumb(*parts):
    home = f'<a href="https://{esc(PORTAL_DOMAIN)}/">{icon("home", 14)} 홈</a>'
    return " / ".join([home] + [esc(p) for p in parts])


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
    identity = (getattr(g, "identity", "") or "").lower()
    dept = ACCOUNT_DEPARTMENTS.get(identity)
    apps = DEPARTMENT_APPS.get(dept, [])
    if apps:
        tiles = "".join(
            f'<a class="app-tile" href="https://{sub}.{PORTAL_DOMAIN}/">'
            f'<span class="app-icon">{icon(ic, 22)}</span>'
            f'<span class="app-name">{esc(name)}</span>'
            f'<span class="app-desc">{esc(desc)}</span>'
            f'<span class="app-foot">{tier_chip(label=tier)}<span>{icon("arrow-right", 16)}</span></span>'
            f'</a>'
            for sub, name, ic, desc, tier in apps)
        app_html = f'<div class="app-grid">{tiles}</div>'
    else:
        app_html = '<div class="empty">사용할 수 있는 업무 앱이 없습니다. 필요하면 소속 부서장을 통해 권한을 요청하세요.</div>'
    notices = (
        ("alert", "피싱 메일 주의", "회사 로그인 화면은 auth 주소에서만 열립니다. 메일 링크로 열린 로그인 화면에는 비밀번호를 입력하지 마세요."),
        ("device", "회사 기기 보안 유지", "보안 에이전트(WARP) 연결과 Windows 방화벽을 켠 상태로 업무 시스템을 이용하세요."),
        ("logout", "공용 PC 사용 후 로그아웃", "자리를 비울 때는 오른쪽 위 로그아웃을 누르고 브라우저 창을 닫아 주세요."),
    )
    notice_html = "".join(f'<li>{icon(ic, 18)}<div><b>{esc(t)}</b><div class="small muted">{esc(d)}</div></div></li>'
                          for ic, t, d in notices)
    name = identity.split("@")[0] if identity else "사용자"
    html = f"""<div class="grid grid-2">
      <section class="card"><h2 class="card-title">{icon("folder", 18)}내 업무 앱
        <span class="right small muted">소속에 따라 보이는 앱이 다릅니다</span></h2>{app_html}</section>
      <div class="grid" style="align-content:start">{session_card()}
        <section class="card"><h2 class="card-title">{icon("info", 18)}보안 공지</h2><ul class="list">{notice_html}</ul></section>
      </div></div>"""
    return render_page("워크스페이스 홈", html, heading=f"안녕하세요, {name}님",
                       desc="필요한 업무 앱을 선택하세요. 접속할 때마다 보안 상태를 확인합니다.")


# 관리자 화면에서 신호/판정 코드를 사람이 읽는 이름으로 (코드도 작게 같이 보여 준다 - 관리자는 로그와 대조해야 하므로)
SIGNAL_LABELS = {
    "threat_intel_match": "위험 IP 접속", "waf_sqli": "SQL 삽입 공격", "waf_attack": "웹 공격(XSS 등)",
}
ACTION_LABELS = {
    "allow": ("허용", "chip-ok"), "step_up_mfa_verified": ("재인증 후 허용", "chip-ok"),
    "step_up_mfa_required": ("추가 인증 요구", "chip-warn"), "session_reauth_required": ("재로그인 요구", "chip-warn"),
    "block": ("차단", "chip-danger"), "block_until_mfa": ("차단(보안 신호)", "chip-danger"), "block_device": ("차단(기기)", "chip-danger"),
    "risk_release": ("관리자 해제", "chip-brand"), "device_session_revoked": ("세션 강제 종료", "chip-danger"),
}


def _action_chip(action):
    label, cls = ACTION_LABELS.get(action, (action or "-", ""))
    return f'<span class="chip {cls}">{esc(label)}</span>'


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
    msg_html = alert("ok" if kind == "ok" else "error", text) if kind else ""

    # --- 위험 상태가 걸린 사용자 ---
    listing = _invoke_risk_admin({"action": "list", "actor": identity})
    if not listing or not listing.get("ok"):
        risk_html = alert("error", "위험 상태 목록을 불러오지 못했습니다. 잠시 후 다시 시도하세요.")
    elif not listing.get("items"):
        risk_html = f'<div class="empty">{icon("check", 20)} 현재 위험 상태가 걸린 사용자는 없습니다.</div>'
    else:
        token = _csrf_token(identity)
        rows = ""
        for it in listing["items"]:
            rows += (f"<tr><td>{esc(it.get('identity'))}</td><td><span class=\"chip chip-danger\">{esc(SIGNAL_LABELS.get(it.get('signal'), it.get('signal')))}</span>"
                     f"<div class=\"small muted mono\">{esc(it.get('signal'))}</div></td>"
                     f"<td>{esc(_fmt_ts(it.get('set_at')))}</td><td>{esc(_fmt_ts(it.get('last_seen')))}</td>"
                     f"<td>{esc(it.get('source'))}</td><td>"
                     f'<form method="post" action="/risk/release" style="margin:0" onsubmit="return confirm(\'이 신호를 해제할까요?\');">'
                     f'<input type="hidden" name="csrf" value="{esc(token)}">'
                     f'<input type="hidden" name="identity" value="{esc(it.get("identity"))}">'
                     f'<input type="hidden" name="signal" value="{esc(it.get("signal"))}">'
                     f'<button class="btn btn-danger btn-sm" type="submit">해제</button></form></td></tr>')
        more = '<p class="small muted" style="margin-top:8px">목록이 길어 일부만 표시했습니다.</p>' if listing.get("truncated") else ""
        risk_html = ('<div class="table-wrap"><table class="table"><tr><th>사용자</th><th>신호</th><th>걸린 시각</th><th>마지막 감지</th><th>출처</th><th></th></tr>'
                     + rows + "</table></div>" + more)

    # --- 최근 판정 로그: 빨간 버튼(/?logs=1)을 눌렀을 때만 읽는다(평소에는 DynamoDB를 조회하지 않음) ---
    if request.args.get("logs") == "1":
        logs, truncated = _recent_logs()
        if logs is None:
            log_body = alert("error", "판정 기록을 불러오지 못했습니다. 잠시 후 다시 시도하세요.")
        elif not logs:
            log_body = '<div class="empty">기록이 없습니다.</div>' 
        else:
            rows = ""
            for it in logs:
                reasons = it.get("reasons") or []
                reasons = ", ".join(str(r) for r in reasons) if isinstance(reasons, (list, tuple, set)) else str(reasons)
                rows += (f"<tr><td>{esc(_fmt_ts(it.get('timestamp')))}</td><td>{esc(it.get('identity', '-'))}</td>"
                         f"<td>{esc(it.get('resource_path', '-'))}</td><td>{esc(it.get('risk_score', '-'))}</td>"
                         f"<td>{esc(it.get('resource_threshold', '-'))}</td><td>{_action_chip(it.get('action'))}</td>"
                         f"<td>{esc(it.get('source', '-'))}</td><td class=\"wrap small\">{esc(reasons)}</td></tr>")
            note = (f"최근 {len(logs)}건 (최신순)" +
                    (f" - 로그가 많아 최근 {LOG_SCAN_CAP}건 안에서만 정렬했습니다" if truncated else ""))
            log_body = (f'<p class="small muted" style="margin-bottom:8px">{esc(note)}</p><div class="table-wrap"><table class="table">'
                        "<tr><th>시각(KST)</th><th>사용자</th><th>자원</th><th>점수</th>"
                        "<th>임계값</th><th>판정</th><th>출처</th><th>사유</th></tr>" + rows + "</table></div>")
        log_tools = link_button("/", "닫기", "secondary btn-sm", "list")
    else:
        log_body = ('<div class="empty">판정 기록은 필요할 때만 불러옵니다(평소에는 기록 저장소를 조회하지 않음). '
                    '실시간 분석은 관제 콘솔(Kibana)을 이용하세요.</div>')
        log_tools = link_button("/?logs=1", "판정 로그 불러오기", "primary btn-sm", "list")

    html = f"""{msg_html}
    <div class="grid">
      <div class="grid grid-2">
        <section class="card"><h2 class="card-title">{icon("alert", 18)}위험 상태가 걸린 사용자</h2>
          <p class="small muted" style="margin:-6px 0 12px">해제하면 기록이 남습니다. 본인 항목은 다른 관리자가 해제해야 합니다.</p>{risk_html}</section>
        <div class="grid" style="align-content:start">{session_card()}</div>
      </div>
      <section class="card"><h2 class="card-title">{icon("list", 18)}최근 판정 기록<span class="right">{log_tools}</span></h2>{log_body}</section>
    </div>"""
    return render_page("관리자 콘솔", html, crumb=_crumb("관리자 콘솔"), wide=True,
                       desc="MFA로 풀리지 않는 보안 신호가 걸린 사용자를 확인하고 해제합니다. 모든 작업은 기록됩니다.",
                       actions_html=tier_chip("top_secret"))


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


def team_page(team):
    """팀 앱 첫 화면: 이 서비스가 어떤 조건으로 보호되는지(접근 정책)와 팀 공지 자리."""
    name, ic, members, desc = TEAM_INFO[team]
    tier = getattr(g, 'tier', None)
    threshold = getattr(g, 'threshold', None)
    policy = (
        ("users", "허용 대상", f"{members} 소속 계정"),
        ("lock", "로그인", "회사 계정 + 2단계 인증(인증 앱)"),
        ("shield-check", "요청마다 재확인", "접속 위치·시간·기기·IP 평판으로 위험도를 다시 계산" +
         (f" (허용 위험점수 {threshold}점 이하)" if threshold is not None else "")),
        ("alert", "평소와 다르면", "추가 인증을 요구하고, 위험이 크면 차단해 보안 이벤트로 기록"),
    )
    policy_html = "".join(f'<li>{icon(i, 18)}<div><b>{esc(t)}</b><div class="small muted">{esc(d)}</div></div></li>'
                          for i, t, d in policy)
    html = f"""<div class="grid grid-2">
      <div class="grid" style="align-content:start">
        <section class="card"><h2 class="card-title">{icon(ic, 18)}팀 공지</h2>
          <div class="empty">등록된 공지가 없습니다.</div></section>
        <section class="card"><h2 class="card-title">{icon("shield", 18)}이 서비스의 접근 정책</h2><ul class="list">{policy_html}</ul></section>
      </div>
      <div class="grid" style="align-content:start">{session_card()}</div></div>"""
    return render_page(name, html, crumb=_crumb(name), desc=desc, actions_html=tier_chip(tier) if tier else "")


def dev_page():
    return team_page("dev")


def marketing_page():
    return team_page("marketing")


def hr_page():
    return team_page("hr")


TEAM_PAGES = {"dev": dev_page, "marketing": marketing_page, "hr": hr_page}

if __name__ == '__main__':
    ssl_context = build_server_context(*MTLS[:3]) if MTLS else None
    app.run(host='0.0.0.0', port=8080, ssl_context=ssl_context)
