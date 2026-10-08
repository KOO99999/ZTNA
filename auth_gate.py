"""판단 서비스 (PDP 쪽 어댑터): nginx의 auth_request가 요청마다 먼저 묻는 곳.

nginx와 같은 서버에서 127.0.0.1로만 받는다. nginx는 이 서비스의 답(상태 코드)만 따른다.
  /auth    : JWT 서명 검증(zt_jwt) -> 위험도 확인(zt_risk) -> 200(통과) 또는 403(차단)
             차단 이유는 응답 헤더 X-ZT-Action으로 알려주고, 어떤 오류든 통과(200)는 되지 않는다.
  /deny    : nginx가 차단 응답을 만들 때 부르는 곳(재인증 안내 리다이렉트, 차단/오류 화면)
  /healthz : 살아있는지 확인용

환경변수: CF_TEAM_DOMAIN, CF_ACCESS_AUDS (zt_jwt), PDP_EVALUATE_URL, EVALUATE_SHARED_SECRET (zt_risk),
          AUTH_DOMAIN
"""
import os
from urllib.parse import unquote, urlsplit

from flask import Flask, Response, jsonify, redirect, request

from zt_jwt import JwtVerifyError, log_jwt_failure, verify_access_jwt
from zt_risk import check_risk, resource_path_for, stepup_url

AUTH_DOMAIN = os.environ.get("AUTH_DOMAIN", "auth.xmcda.store")

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
    result = check_risk(identity, request.headers.get("CF-IPCountry"), resource_path_for(host, path))
    if result["allow"]:
        return Response("ok", 200, {"X-ZT-Identity": identity})

    action = "pdp_unavailable" if result.get("error") else result.get("action", "denied")
    print(f"[ZT_DENY] action={action} identity={identity} host={host} path={path}", flush=True)
    return _deny_auth(action)


def _status_page(title, message, code):
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title></head>
    <body style="font-family:'Segoe UI',Tahoma,sans-serif;margin:40px;background:#f4f6f9;">
    <div style="background:white;padding:30px;border-radius:12px;max-width:520px;margin:60px auto;box-shadow:0 4px 6px rgba(0,0,0,0.1);">
    <h2>{title}</h2><p>{message}</p>
    <p><a href="https://{AUTH_DOMAIN}/logout">로그아웃</a></p></div></body></html>"""
    return Response(html, code, {"Content-Type": "text/html; charset=utf-8"})


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

    if action == "pdp_unavailable":
        if is_api:
            return jsonify({"status": "Error", "message": "위험 판단 서버에 연결할 수 없어 접근을 차단했습니다."}), 503
        return _status_page("일시적으로 확인할 수 없습니다",
                            "위험 판단 서버에 연결할 수 없어 접근을 차단했습니다. 잠시 후 다시 시도해 주세요.", 503)

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
