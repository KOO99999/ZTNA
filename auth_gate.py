"""판단 서비스 (PDP 쪽 어댑터): nginx의 auth_request가 요청마다 먼저 묻는 곳.

nginx와 같은 서버에서 127.0.0.1로만 받는다. nginx는 이 서비스의 답(상태 코드)만 따른다.
  /auth    : JWT 서명 검증(zt_jwt) -> 위험도 확인(zt_risk) -> 200(통과) 또는 403(차단)
             통과하면 X-ZT-Identity/X-ZT-Threshold/X-ZT-Tier(화면 표시용)를 응답 헤더로 알려주고,
             차단 이유는 X-ZT-Action으로 알려준다. 어떤 오류든 통과(200)는 되지 않는다.
  /deny    : nginx가 차단 응답을 만들 때 부르는 곳(재인증 안내 리다이렉트, 차단/오류 화면)
  /healthz : 살아있는지 확인용

환경변수: CF_TEAM_DOMAIN, CF_ACCESS_AUDS (zt_jwt), PDP_EVALUATE_URL, EVALUATE_SHARED_SECRET (zt_risk),
          AUTH_DOMAIN
"""
import os
from urllib.parse import unquote, urlsplit

from flask import Flask, Response, jsonify, redirect, request

from zt_jwt import JwtVerifyError, log_jwt_failure, verify_access_jwt
from zt_risk import check_risk, log_event, resource_path_for, stepup_url
from zt_ui import status_page

AUTH_DOMAIN = os.environ.get("AUTH_DOMAIN", "auth.xmcda.store")

# [WAF 신원 연결] ModSecurity 감사 로그를 따라 읽어, 로그인한 사람의 공격을 엔진에 알린다(zt_waf.py).
# 위험도 캐시와 같은 프로세스에 있어야 알린 즉시 그 사람의 캐시를 지울 수 있다(gunicorn workers=1).
if os.environ.get("ZT_WAF_ENABLED") == "1":
    import zt_waf
    zt_waf.start()

app = Flask(__name__)


def _original_request():
    """nginx가 X-Original-URI/X-Original-Host로 알려준, 사용자가 실제로 요청한 호스트/경로/쿼리.
    앱(Flask)의 request.path와 같은 모양(퍼센트 디코딩 후)으로 맞춘다."""
    parts = urlsplit(request.headers.get("X-Original-URI", "/"))
    return request.headers.get("X-Original-Host", ""), unquote(parts.path) or "/", parts.query


def _deny_auth(action, headers=None):
    # auth_request는 2xx만 통과로 본다. 여기서는 항상 403 + 이유(X-ZT-Action)만 돌려준다.
    return Response("", 403, {"X-ZT-Action": action, **(headers or {})})


@app.route("/auth")
def auth():
    host, path, _query = _original_request()

    # 1) 신원: 서명 검증을 통과한 JWT의 email만 사용. 실패 = 기록 후 차단(Lambda 호출 없음).
    try:
        claims = verify_access_jwt(request.headers.get("Cf-Access-Jwt-Assertion"))
    except JwtVerifyError as e:
        log_jwt_failure(e.reason, host, path, request.headers.get("X-Real-IP"),
                        request.headers.get("Cf-Connecting-Ip"))
        return _deny_auth("jwt_invalid")
    identity = claims["email"]

    # 2) 위험도: 같은 Lambda(PDP)에 묻는다. 호출 실패/비정상 응답은 zt_risk가 차단으로 돌려준다.
    # session_country: Access 토큰(서명 검증됨)에 들어 있는 "로그인한 나라". 지금 요청 나라와 다르면 엔진이 탈취를 의심한다.
    result = check_risk(identity, request.headers.get("CF-IPCountry"), resource_path_for(host, path),
                        request.headers.get("CF-Connecting-IP"), claims.get("country"))
    if result["allow"]:
        # 앱은 위험도를 다시 묻지 않는다. 화면에 보여줄 "이 요청에 적용된 임계값"만 여기서 받아 간다
        # (nginx가 auth_request_set으로 꺼내 앱에 넘기며, 항상 이 값으로 덮어써서 클라이언트가 보낸
        # 같은 이름의 헤더는 앱에 닿지 않는다).
        headers = {"X-ZT-Identity": identity}
        if isinstance(result.get("resource_threshold"), (int, float)) and not isinstance(result.get("resource_threshold"), bool):
            headers["X-ZT-Threshold"] = str(int(result["resource_threshold"]))
        if isinstance(result.get("resource_tier"), str):
            headers["X-ZT-Tier"] = result["resource_tier"]
        return Response("ok", 200, headers)

    action = "pdp_unavailable" if result.get("error") else result.get("action", "denied")
    print(f"[ZT_DENY] action={action} identity={identity} host={host} path={path}", flush=True)
    # 점수/사유는 여기서 남기지 않는다(판단한 엔진이 decision 이벤트로 남김 - 같은 정보를 두 곳에 두지 않음)
    log_event("gate_deny", action=action, identity=identity, host=host, path=path,
              client_ip=request.headers.get("CF-Connecting-IP"))
    return _deny_auth(action)


def _status_page(title, message, code, tone="danger", badge="block"):
    """차단 안내 화면(로그인 서버/업무 앱과 같은 디자인, zt_ui). 차단 사유(점수, 신호)는 넣지 않는다."""
    html = status_page(title, message, f"https://{AUTH_DOMAIN}/logout", tone=tone, badge=badge,
                       home_href=None if badge == "globe" else f"https://{AUTH_DOMAIN.replace('auth.', '', 1)}/")
    return Response(html, code, {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
                                 "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"})


@app.route("/deny")
def deny():
    """nginx가 /auth의 차단 결과(X-ZT-Action)를 넘겨 부른다. 차단 사유(점수, 신호)는 노출하지 않는다."""
    action = request.headers.get("X-ZT-Action", "")
    host, path, query = _original_request()
    is_api = path.startswith("/api/")

    if action == "step_up_mfa_required":
        url = stepup_url(AUTH_DOMAIN, host, path, query, is_api)
        if is_api:
            return jsonify({"status": "StepUpRequired", "message": "추가 인증이 필요합니다.", "stepup_url": url}), 403
        return redirect(url, code=302)

    if action == "session_reauth_required":
        # 출입증(Access 토큰)이 로그인한 나라와 다른 곳에서 쓰이는 중: TOTP 재인증으로는 같은 토큰이 남으므로 다시 로그인해야 한다
        if is_api:
            return jsonify({"status": "ReauthRequired", "message": "로그인한 위치와 지금 위치가 달라 다시 로그인이 필요합니다."}), 403
        return _status_page("다시 로그인이 필요합니다",
                            "로그인한 위치와 지금 접속 위치가 달라 보안을 위해 세션을 사용할 수 없습니다. "
                            "로그아웃한 뒤 다시 로그인해 주세요.", 403, tone="warn", badge="globe")

    if action == "pdp_unavailable":
        if is_api:
            return jsonify({"status": "Error", "message": "위험 판단 서버에 연결할 수 없어 접근을 차단했습니다."}), 503
        return _status_page("일시적으로 확인할 수 없습니다",
                            "보안 확인 서비스에 연결할 수 없어 안전을 위해 접속을 막았습니다. 잠시 후 다시 시도해 주세요.", 503,
                            tone="warn", badge="clock")

    if action == "jwt_invalid":
        if is_api:
            return jsonify({"status": "Denied", "message": "인증 토큰 검증에 실패하여 접근이 거부되었습니다."}), 403
        return _status_page("접근이 거부되었습니다", "인증 정보를 확인할 수 없는 요청입니다.", 403)

    if is_api:
        return jsonify({"status": "Denied", "message": "보안 정책에 따라 접근이 차단되었습니다."}), 403
    return _status_page("접근이 차단되었습니다", "보안 정책에 따라 이 페이지에 대한 접근이 차단되었습니다.", 403)


@app.route("/healthz")
def healthz():
    return "ok", 200
