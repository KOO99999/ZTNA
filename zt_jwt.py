"""Cloudflare Access JWT 검증 (판단 서비스와 앱 공용).

환경변수: CF_TEAM_DOMAIN (예: your-team.cloudflareaccess.com), CF_ACCESS_AUDS (쉼표 구분 AUD 목록)
"""
import json
import os
import threading
import time

import jwt  # PyJWT (RS256 검증에 cryptography 필요)
import requests

# ==========================================================================
# Cloudflare Access JWT 서명 검증
#
# Cloudflare가 요청에 붙이는 Cf-Access-Jwt-Assertion은 Cloudflare 개인키로 서명되어 있어,
# 공개키(JWKS)로 "진짜 Cloudflare가 발급했고, 이 앱(aud)용이고, 만료 전인지"를 확인할 수 있다.
# 평문 헤더(Cf-Access-Authenticated-User-Email)는 누가 위조해도 앱이 알 수 없으므로,
# 신원(이메일)은 검증을 통과한 토큰 안의 email 값만 쓴다.
# 검증 실패는 기록(journalctl)하고 즉시 차단한다. 토큰 원문은 로그에 남기지 않는다.
#
# 이 모듈은 판단 서비스(auth_gate.py, nginx 옆)와 앱(portal_app.py)이 함께 쓴다. Flask에 의존하지 않는다.
# ==========================================================================
CF_TEAM_DOMAIN = (os.environ.get("CF_TEAM_DOMAIN") or "").strip().rstrip("/")
CF_ACCESS_AUDS = [a.strip() for a in (os.environ.get("CF_ACCESS_AUDS") or "").split(",") if a.strip()]
CF_ISSUER = f"https://{CF_TEAM_DOMAIN}" if CF_TEAM_DOMAIN else None
CF_CERTS_URL = f"{CF_ISSUER}/cdn-cgi/access/certs" if CF_ISSUER else None
JWKS_TIMEOUT_SECONDS = 3
JWKS_CACHE_SECONDS = 3600        # 정상 시 공개키 목록을 1시간 보관
JWKS_MIN_REFETCH_SECONDS = 60    # 모르는 kid가 계속 들어와도 1분에 한 번만 다시 받음(남용 방지)

_jwks = {"keys": {}, "fetched_at": 0.0}
_jwks_lock = threading.Lock()


class JwtVerifyError(Exception):
    """reason: 로그에 남기는 짧은 분류 이름(토큰 내용은 담지 않는다)."""
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _fetch_jwks():
    """Cloudflare 공개키 목록을 받아 {kid: 공개키객체}로 돌려준다. 테스트에서 대체하는 지점."""
    resp = requests.get(CF_CERTS_URL, timeout=JWKS_TIMEOUT_SECONDS)
    resp.raise_for_status()
    keys = {}
    for jwk in resp.json().get("keys", []):
        if jwk.get("kty") == "RSA" and jwk.get("kid"):
            keys[jwk["kid"]] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    return keys


def _get_signing_key(kid):
    now = time.time()
    with _jwks_lock:
        fresh = (now - _jwks["fetched_at"]) < JWKS_CACHE_SECONDS
        if kid in _jwks["keys"] and fresh:
            return _jwks["keys"][kid]
        # 캐시가 오래됐거나 모르는 kid(키 교체 가능성)면 다시 받되, 너무 자주는 안 받는다
        if (now - _jwks["fetched_at"]) >= JWKS_MIN_REFETCH_SECONDS:
            try:
                _jwks["keys"] = _fetch_jwks()
                _jwks["fetched_at"] = now
            except Exception as e:
                print(f"[JWT_JWKS_FETCH_FAILED] {type(e).__name__}", flush=True)
                if kid in _jwks["keys"]:
                    return _jwks["keys"][kid]   # 받기 실패해도 이미 아는 키면 계속 사용
                raise JwtVerifyError("jwks_unavailable")
        if kid in _jwks["keys"]:
            return _jwks["keys"][kid]
    raise JwtVerifyError("unknown_kid")


def verify_access_jwt(token):
    """검증에 성공하면 claims(dict)를, 실패하면 JwtVerifyError를 낸다."""
    if not CF_ISSUER or not CF_ACCESS_AUDS:
        raise JwtVerifyError("config_missing")
    if not token:
        raise JwtVerifyError("token_missing")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise JwtVerifyError("malformed")
    # 알고리즘은 토큰이 아니라 우리가 정한다(alg=none / HS256 위조 방지)
    if header.get("alg") != "RS256" or not header.get("kid"):
        raise JwtVerifyError("bad_alg_or_kid")
    key = _get_signing_key(header["kid"])
    try:
        claims = jwt.decode(
            token, key, algorithms=["RS256"],
            audience=CF_ACCESS_AUDS, issuer=CF_ISSUER,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError:
        raise JwtVerifyError("expired")
    except jwt.InvalidAudienceError:
        raise JwtVerifyError("bad_aud")
    except jwt.InvalidIssuerError:
        raise JwtVerifyError("bad_iss")
    except jwt.InvalidSignatureError:
        raise JwtVerifyError("bad_signature")
    except jwt.MissingRequiredClaimError:
        raise JwtVerifyError("missing_claim")
    except jwt.PyJWTError:
        raise JwtVerifyError("invalid")
    email = claims.get("email")
    if not isinstance(email, str) or not email:
        raise JwtVerifyError("no_email_claim")   # 서비스 토큰 등 사람 계정이 아닌 토큰
    return claims


def log_jwt_failure(reason, host, path, remote, cf_ip=None):
    # 토큰/쿠키 값은 남기지 않는다. 어떤 요청이 왜 막혔는지만 남긴다(journalctl에서 확인).
    print(f"[JWT_VERIFY_FAILED] reason={reason} host={host} path={path} "
          f"remote={remote} cf_ip={cf_ip}", flush=True)
