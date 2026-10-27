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
import demo_data

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
# 포털 홈의 업무 앱 (서브도메인, 이름, 아이콘, 설명, 보안 등급, 색). 등급은 엔진 RESOURCE_TIERS와 같은 구성.
# 내 소속 앱만 링크가 걸리고, 나머지는 "권한 없음"으로 잠긴 타일(링크/주소 없음)로 보인다. 실제 허용/차단은 각 앱의 Access 정책이 한다.
ALL_APPS = [
    ("dev", "개발팀", "code", "배포 이력 · 서버 목록", "기밀", "c-indigo"),
    ("hr", "인사팀", "users", "임직원 명부 · 인사 기록", "기밀", "c-pink"),
    ("marketing", "마케팅팀", "megaphone", "캠페인 · 홍보 자료", "내부", "c-amber"),
    ("admin", "관리자 콘솔", "settings", "위험 상태 · 판정 기록", "최고기밀", "c-sky"),
]
DEPARTMENT_APPS = {"dev": {"dev"}, "marketing": {"marketing"}, "hr": {"hr"}, "admin": {"admin"}}
DEPARTMENT_NAMES = {"dev": "개발팀", "marketing": "마케팅팀", "hr": "인사팀", "admin": "보안관리"}
COUNTRY_NAMES = {"KR": "대한민국", "US": "미국", "JP": "일본", "CN": "중국", "DE": "독일", "GB": "영국", "SG": "싱가포르"}
WEEKDAYS = "월화수목금토일"
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


# 로그아웃 후 '뒤로 가기'로 브라우저가 저장해 둔 화면(bfcache)을 그대로 꺼내 보여주는 경우가 있다
# (Cache-Control: no-store만으로는 브라우저에 따라 막히지 않음). 저장된 화면으로 돌아오면 다시 불러오게 한다.
_BFCACHE_SCRIPT = "<script>window.addEventListener('pageshow',function(e){if(e.persisted)window.location.reload();});</script>"


def render_page(title, content_html, heading=None, desc=None, crumb=None, wide=False, actions_html=""):
    """업무 화면 공통 틀(zt_ui.app_shell: 상단 바, 자동 로그아웃 카운트다운) + 뒤로 가기 캐시 방지."""
    return app_shell(title, content_html, user=getattr(g, 'identity', None), heading=heading or title, desc=desc,
                     crumb=crumb, wide=wide, actions_html=actions_html, home_href=f"https://{PORTAL_DOMAIN}/",
                     logout_href=f"https://{AUTH_DOMAIN}/logout", head_extra=_BFCACHE_SCRIPT)


def _crumb(*parts):
    home = f'<a href="https://{esc(PORTAL_DOMAIN)}/">홈</a>'
    return " / ".join([home] + [esc(p) for p in parts])


def _today_line(dept=None):
    now = datetime.now(KST)
    line = f"{now.month}월 {now.day}일 {WEEKDAYS[now.weekday()]}요일"
    return f"{line} · {DEPARTMENT_NAMES.get(dept, dept)}" if dept else line


def _greeting():
    h = datetime.now(KST).hour
    return "좋은 아침이에요" if 5 <= h < 12 else ("좋은 오후예요" if 12 <= h < 18 else "오늘도 수고 많으셨어요")


def _demo_note():
    return f'<span class="demo-note">{icon("info", 13)} 시연용 가상 데이터</span>'


def _stat(label, value, small=False):
    return f'<div class="stat"><div class="label">{esc(label)}</div><div class="value{" sm" if small else ""}">{value}</div></div>'


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

    identity = (getattr(g, "identity", "") or "").lower()
    dept = ACCOUNT_DEPARTMENTS.get(identity)
    mine = DEPARTMENT_APPS.get(dept, set())
    tiles = ""
    for sub, name, ic, desc, tier, color in ALL_APPS:
        inner = (f'<span class="bx {color}">{icon(ic, 24)}</span><span class="app-name">{esc(name)}</span>'
                 f'<span class="app-desc">{esc(desc)}</span>')
        if sub in mine:
            tiles += (f'<a class="app-tile" href="https://{sub}.{PORTAL_DOMAIN}/">{inner}'
                      f'<span class="app-foot">{tier_chip(label=tier)}<span class="faint">{icon("arrow-right", 18)}</span></span></a>')
        else:   # 권한 없는 앱: 주소를 화면에 남기지 않는다(링크 없음)
            tiles += (f'<div class="app-tile locked" aria-disabled="true">{inner}'
                      f'<span class="app-foot"><span class="chip">{icon("lock", 13)}권한 없음</span></span></div>')
    empty = ('' if mine else '<div class="empty" style="margin-bottom:14px">사용할 수 있는 업무 앱이 없습니다. '
             '필요하면 소속 부서장을 통해 권한을 요청하세요.</div>')
    notices = "".join(f'<li><span class="chip {"chip-" + kind if kind else ""}">{esc(tag)}</span>{esc(title)}<span class="end">{esc(date)}</span></li>'
                      for tag, kind, title, date in demo_data.NOTICES)
    country = request.headers.get("CF-IPCountry", "")
    place = COUNTRY_NAMES.get(country, country) if country and country != "XX" else "확인 불가"
    ip = request.headers.get("Cf-Connecting-Ip", "") or "확인 불가"
    me = (f'<div class="sec-item"><span class="bx">{icon("user", 20)}</span><div><b>{esc(identity or "-")}</b><span>로그인 계정</span></div></div>'
          f'<div class="sec-item"><span class="bx">{icon("globe", 20)}</span><div><b>{esc(place)}</b><span>현재 접속 위치</span></div></div>'
          f'<div class="sec-item"><span class="bx">{icon("device", 20)}</span><div><b class="mono" style="font-size:14px">{esc(ip)}</b><span>현재 접속 IP</span></div></div>'
          f'<p class="small faint" style="margin-top:10px">본인이 접속한 기록이 아니라면 즉시 보안 관리자에게 알려 주세요.</p>')
    name = identity.split("@")[0] if identity else "사용자"
    html = f"""{empty}<div class="app-grid">{tiles}</div>
    <div class="grid grid-2" style="margin-top:14px">
      <section class="card"><h2 class="card-title">전사 공지<span class="right">{_demo_note()}</span></h2><ul class="list">{notices}</ul></section>
      <section class="card"><h2 class="card-title">내 접속 정보</h2>{me}</section>
    </div>"""
    return render_page("사내 포털", html, heading=f"{name}님, {_greeting()}", desc=_today_line(dept))


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

    # --- 최근 판정 기록: 버튼을 눌렀을 때만 읽는다(평소에는 기록 저장소를 조회하지 않음) ---
    #   버튼은 같은 주소의 /logs(표 조각)를 불러와 바로 아래에 펼친다(새로고침 없음). 스크립트가 꺼진 브라우저는 /?logs=1로 같은 표를 본다.
    opened = request.args.get("logs") == "1"
    log_panel = _logs_fragment() if opened else ""
    log_tools = (f'<a class="btn btn-soft btn-sm" href="/?logs=1" data-logs-toggle aria-expanded="{"true" if opened else "false"}">'
                 f'{icon("list", 16)}<span>{"판정 로그 접기" if opened else "판정 로그 불러오기"}</span></a>')
    threshold = getattr(g, 'threshold', None)
    count = len(listing.get("items") or []) if listing and listing.get("ok") else None
    stats = (_stat("위험 상태 사용자", f"{count}명" if count is not None else "-")
             + _stat("이 화면 보안 등급", tier_chip("top_secret"), small=True)
             + _stat("허용 위험점수", esc(f"{threshold}점 이하" if threshold is not None else "확인 불가"), small=True)
             + _stat("자동 로그아웃", "15분 무활동", small=True))
    html = f"""{msg_html}
    <div class="grid grid-4" style="margin-bottom:14px">{stats}</div>
    <section class="card" style="margin-bottom:14px"><h2 class="card-title">위험 상태가 걸린 사용자</h2>
      <p class="card-desc">MFA로 풀리지 않는 보안 신호가 걸린 사용자입니다. 해제하면 기록이 남고, 본인 항목은 다른 관리자가 해제해야 합니다.</p>{risk_html}</section>
    <section class="card"><h2 class="card-title">최근 판정 기록<span class="right">{log_tools}</span></h2>
      <p class="card-desc">위험점수 판단 결과입니다. 실시간 분석과 알림은 관제 콘솔(Kibana)에서 봅니다.</p>
      <div data-panel id="log-panel">{log_panel}</div></section>
    <script>
    (function(){{var b=document.querySelector('[data-logs-toggle]'),panel=document.getElementById('log-panel');if(!b)return;
    b.addEventListener('click',function(e){{e.preventDefault();var label=b.querySelector('span');
      if(b.getAttribute('aria-expanded')==='true'){{panel.innerHTML='';b.setAttribute('aria-expanded','false');label.textContent='판정 로그 불러오기';return;}}
      label.textContent='불러오는 중...';
      fetch('/logs',{{credentials:'same-origin',headers:{{'Accept':'text/html'}}}}).then(function(r){{if(!r.ok)throw new Error(r.status);return r.text();}})
      .then(function(h){{panel.innerHTML=h;b.setAttribute('aria-expanded','true');label.textContent='판정 로그 접기';}})
      .catch(function(){{panel.innerHTML='<div class="alert alert-error">판정 기록을 불러오지 못했습니다. 잠시 후 다시 시도하세요.</div>';label.textContent='판정 로그 불러오기';}});
    }});}})();
    </script>"""
    return render_page("관리자 콘솔", html, crumb=_crumb("관리자 콘솔"), wide=True,
                       desc="보안 신호가 걸린 사용자를 확인·해제하고 판정 기록을 봅니다. 모든 작업은 기록됩니다.",
                       actions_html=tier_chip("top_secret"))


def _logs_fragment():
    """최근 판정 기록 표(HTML 조각). 관리자 콘솔이 /logs로 불러와 끼워 넣거나 /?logs=1일 때 바로 그린다."""
    logs, truncated = _recent_logs()
    if logs is None:
        return alert("error", "판정 기록을 불러오지 못했습니다. 잠시 후 다시 시도하세요.")
    if not logs:
        return '<div class="empty">기록이 없습니다.</div>'
    rows = ""
    for it in logs:
        reasons = it.get("reasons") or []
        reasons = ", ".join(str(r) for r in reasons) if isinstance(reasons, (list, tuple, set)) else str(reasons)
        rows += (f"<tr><td>{esc(_fmt_ts(it.get('timestamp')))}</td><td>{esc(it.get('identity', '-'))}</td>"
                 f"<td>{esc(it.get('resource_path', '-'))}</td><td><b>{esc(it.get('risk_score', '-'))}</b></td>"
                 f"<td>{esc(it.get('resource_threshold', '-'))}</td><td>{_action_chip(it.get('action'))}</td>"
                 f"<td>{esc(it.get('source', '-'))}</td><td class=\"wrap\">{esc(reasons)}</td></tr>")
    note = (f"최근 {len(logs)}건 (최신순)" +
            (f" - 기록이 많아 최근 {LOG_SCAN_CAP}건 안에서만 정렬했습니다" if truncated else ""))
    return (f'<p class="small muted" style="margin-bottom:10px">{esc(note)}</p><div class="table-wrap"><table class="table">'
            "<tr><th>시각(KST)</th><th>사용자</th><th>자원</th><th>점수</th>"
            "<th>임계값</th><th>판정</th><th>출처</th><th>사유</th></tr>" + rows + "</table></div>")


@app.route('/logs')
def logs_fragment():
    """관리자 콘솔 전용: 판정 기록 표 조각. 같은 Access 앱/같은 JWT 검증/같은 위험도 판단을 거친 요청만 여기 온다."""
    if not request.host.startswith('admin.'):
        return _status_page("찾을 수 없음", "잘못된 경로입니다.", 404)
    if not _is_admin(g.identity):
        return _status_page("접근이 거부되었습니다", "관리자 권한이 필요한 영역입니다.", 403)
    return _logs_fragment(), 200, {"Content-Type": "text/html; charset=utf-8"}


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


def _table(headers, rows_html):
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    return f'<div class="table-wrap"><table class="table"><tr>{head}</tr>{rows_html}</table></div>'


_STATUS_DOT = {"성공": "dot-ok", "정상": "dot-ok", "재직": "dot-ok", "진행 중": "dot-warn", "점검 중": "dot-warn", "준비": "dot-warn",
               "휴직": "dot-warn", "실패": "dot-bad", "경고": "dot-bad", "종료": ""}


def _status(text):
    return f'<span class="dot {_STATUS_DOT.get(text, "")}"></span>{esc(text)}'


def dev_page():
    d = demo_data.DEPLOYMENTS
    stats = (_stat("최근 배포", f"{len(d)}건") + _stat("실패", f"{sum(1 for x in d if x[3] == '실패')}건")
             + _stat("운영 서버", f"{sum(1 for x in demo_data.SERVERS if x[2] == '운영')}대") + _stat("진행 중", f"{sum(1 for x in d if x[3] == '진행 중')}건"))
    deploy = "".join(f"<tr><td><b>{esc(a)}</b></td><td class=\"mono\">{esc(b)}</td><td>{esc(c)}</td><td>{_status(r)}</td><td>{esc(t)}</td><td>{esc(o)}</td></tr>"
                     for a, b, c, r, t, o in d)
    servers = "".join(f"<tr><td class=\"mono\">{esc(h)}</td><td>{esc(r)}</td><td>{esc(e)}</td><td>{_status(st)}</td><td>{esc(c)}</td></tr>"
                      for h, r, e, st, c in demo_data.SERVERS)
    html = f"""<div class="grid grid-4" style="margin-bottom:14px">{stats}</div>
    <section class="card" style="margin-bottom:14px"><h2 class="card-title">최근 배포 이력<span class="right">{_demo_note()}</span></h2>
      {_table(("서비스", "버전", "환경", "결과", "시각", "담당"), deploy)}</section>
    <section class="card"><h2 class="card-title">서버 목록<span class="right">{_demo_note()}</span></h2>
      {_table(("호스트", "역할", "환경", "상태", "최근 점검"), servers)}</section>"""
    return render_page("개발팀", html, crumb=_crumb("개발팀"), desc="개발팀 전용 업무 공간입니다. 배포 이력과 서버 현황을 확인합니다.",
                       actions_html=tier_chip(getattr(g, 'tier', None)) if getattr(g, 'tier', None) else "")


def marketing_page():
    c = demo_data.CAMPAIGNS
    stats = (_stat("진행 중 캠페인", f"{sum(1 for x in c if x[4] == '진행 중')}건") + _stat("준비", f"{sum(1 for x in c if x[4] == '준비')}건")
             + _stat("총 예산", f"{sum(x[3] for x in c):,}만원") + _stat("종료", f"{sum(1 for x in c if x[4] == '종료')}건"))
    rows = "".join(f"<tr><td><b>{esc(n)}</b></td><td>{esc(ch)}</td><td>{esc(per)}</td><td>{b:,}만원</td><td>{_status(st)}</td>"
                   f"<td><div style=\"background:var(--line-2);border-radius:6px;height:8px;width:120px\">"
                   f"<div style=\"background:var(--brand);border-radius:6px;height:8px;width:{int(pct) * 120 // 100}px\"></div></div></td></tr>"
                   for n, ch, per, b, st, pct in c)
    html = f"""<div class="grid grid-4" style="margin-bottom:14px">{stats}</div>
    <section class="card"><h2 class="card-title">캠페인 현황<span class="right">{_demo_note()}</span></h2>
      {_table(("캠페인", "채널", "기간", "예산", "상태", "진행률"), rows)}</section>"""
    return render_page("마케팅팀", html, crumb=_crumb("마케팅팀"), desc="마케팅팀 전용 업무 공간입니다. 캠페인과 홍보 자료를 관리합니다.",
                       actions_html=tier_chip(getattr(g, 'tier', None)) if getattr(g, 'tier', None) else "")


def hr_page():
    """인사팀: 임직원 명부와 검색. 검색어는 목록에서만 거른다(SQL 없음). 웹 서버 WAF가 검색어를 먼저 검사한다(시연 표적)."""
    query = (request.args.get("q") or "")[:50]
    found = demo_data.search_employees(query)
    e = demo_data.EMPLOYEES
    stats = (_stat("전체 임직원", f"{len(e)}명") + _stat("부서", f"{len({x[2] for x in e})}개")
             + _stat("이번 달 입사", f"{sum(1 for x in e if x[4].startswith('2026-10'))}명") + _stat("휴직", f"{sum(1 for x in e if x[6] == '휴직')}명"))
    rows = "".join(f"<tr><td class=\"mono\">{esc(no)}</td><td><b>{esc(nm)}</b></td><td>{esc(dp)}</td><td>{esc(rk)}</td><td>{esc(jd)}</td>"
                   f"<td class=\"mono\">{esc(demo_data.masked_phone(ph))}</td><td>{_status(st)}</td></tr>"
                   for no, nm, dp, rk, jd, ph, st in found)
    table = _table(("사번", "이름", "부서", "직급", "입사일", "연락처", "상태"), rows) if found else '<div class="empty">검색 결과가 없습니다.</div>'
    result = (f'<span class="small muted">"{esc(query)}" 검색 결과 {len(found)}명</span>' if query else
              f'<span class="small muted">전체 {len(found)}명</span>')
    html = f"""<div class="grid grid-4" style="margin-bottom:14px">{stats}</div>
    <section class="card"><h2 class="card-title">임직원 명부<span class="right">{_demo_note()}</span></h2>
      <form class="toolbar" method="get" action="/" role="search">
        <label class="search">{icon("search", 18)}<input type="search" name="q" value="{esc(query)}" maxlength="50" placeholder="이름, 부서, 사번으로 검색"></label>
        <button class="btn btn-primary btn-sm" type="submit">검색</button>{result}</form>
      {table}
      <p class="small faint" style="margin-top:12px">개인정보 보호를 위해 연락처 일부를 가려서 표시합니다. 이 화면의 조회 기록은 모두 남습니다.</p></section>"""
    return render_page("인사팀", html, crumb=_crumb("인사팀"), desc="인사팀 전용 업무 공간입니다. 임직원 개인정보를 다룹니다.",
                       actions_html=tier_chip(getattr(g, 'tier', None)) if getattr(g, 'tier', None) else "")


TEAM_PAGES = {"dev": dev_page, "marketing": marketing_page, "hr": hr_page}

if __name__ == '__main__':
    ssl_context = build_server_context(*MTLS[:3]) if MTLS else None
    app.run(host='0.0.0.0', port=8080, ssl_context=ssl_context)
