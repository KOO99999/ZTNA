"""위험도 확인 (Lambda PDP 호출 + 결과 캐시). nginx 앞단 판단 서비스(auth_gate.py)만 쓴다
(앱 서버에는 이 모듈도, Lambda 비밀키도 배포하지 않는다).

환경변수: PDP_EVALUATE_URL, EVALUATE_SHARED_SECRET
"""
from datetime import datetime, timezone
import os
import threading
import time
import uuid
from urllib.parse import quote

import requests

# ==========================================================================
# B 계층: 세션 중 위험도 재확인
#
# Cloudflare Access(A 계층)는 세션을 새로 만들 때만 Worker -> Lambda 평가를 하고, 세션이
# 살아있는 동안(현재 15분)은 다시 평가하지 않는다. 그 사이의 빈틈을 메우기 위해, 이 모듈이
# 요청을 통과시키기 직전에 같은 Lambda(PDP)에 직접 물어본다.
#
# [설계 원칙] 판단(점수 계산, 임계값 비교)은 여기서 하지 않는다. 원본 값(시각, 국가, 접속
# 경로)만 Lambda로 넘기고 결과를 집행(통과/차단/재인증 안내)할 뿐이다 - Worker와 동일.
# Lambda 호출은 전부 check_risk() 한 곳을 거치므로, 나중에 로컬 실행 방식으로 옮길 때는
# 이 함수 안쪽만 바꾸면 된다.
# ==========================================================================
PDP_EVALUATE_URL = os.environ.get("PDP_EVALUATE_URL")
EVALUATE_SHARED_SECRET = os.environ.get("EVALUATE_SHARED_SECRET")
PDP_TIMEOUT_SECONDS = 3

# [캐시 유효기간] 허용 결과를 몇 초 재사용할지는 Lambda(PDP)가 정해서 응답의 cache_ttl_seconds로
# 알려준다(등급별 시간, 야간 경계, 재인증 유효 시간까지 Lambda가 계산). 이 모듈은 그 값을 그대로
# 따르고 등급표도 야간 기준도 갖지 않는다. 값이 없거나 이상하면 캐시하지 않는다(안전한 쪽).
# MAX_CACHE_TTL_SECONDS는 정책이 아니라 안전 상한이다: Lambda 설정 실수로 아주 큰 값이 와도
# Access 세션 길이(15분)를 넘겨 '통과'를 재사용하지 않도록 막는다.
MAX_CACHE_TTL_SECONDS = 900

_cache = {}
_cache_lock = threading.Lock()
_CACHE_MAX_ENTRIES = 1000


def _call_pdp(identity, country, resource_path, client_ip=None):
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
                # 접속 IP(Cloudflare가 넣는 CF-Connecting-IP): 엔진이 IP 평판(AbuseIPDB)을 본다
                "client_ip": client_ip,
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
            "cache_ttl_seconds": data.get("cache_ttl_seconds"),
            "error": False,
        }
    except Exception as e:
        print(f"[B_PDP_CALL_FAILED] {e}", flush=True)
        return {"allow": False, "action": "pdp_unavailable", "error": True}


def check_risk(identity, country, resource_path, client_ip=None):
    """이 앱에서 Lambda를 부르는 유일한 통로.

    캐시 규칙:
      1) 허용 결과만 저장한다. 차단/step-up 필요 결과를 저장하면 /stepup에서 재인증을
         마치고 돌아와도 옛 결과가 남아 계속 막힌다.
      2) 같은 사용자라도 국가나 접속 IP가 직전과 다르면 캐시를 버리고 즉시 다시 묻는다
         (다른 IP에서 온 요청은 IP 평판을 새로 봐야 함).
      3) 만료 시간은 Lambda가 응답에 실어 보낸 cache_ttl_seconds(0이면 저장 안 함).
    """
    now = time.time()
    key = (identity, resource_path)

    with _cache_lock:
        entry = _cache.get(key)
        if entry:
            if entry["expires_at"] > now and entry["country"] == country and entry.get("client_ip") == client_ip:
                return {**entry["result"], "from_cache": True}
            del _cache[key]

    result = _call_pdp(identity, country, resource_path, client_ip)
    result["from_cache"] = False

    if result["allow"] and not result["error"]:
        ttl = result.get("cache_ttl_seconds")
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
            ttl = 0
        ttl = min(ttl, MAX_CACHE_TTL_SECONDS)
        if ttl > 0:
            with _cache_lock:
                if len(_cache) >= _CACHE_MAX_ENTRIES:
                    for k in [k for k, v in _cache.items() if v["expires_at"] <= now]:
                        del _cache[k]
                if len(_cache) < _CACHE_MAX_ENTRIES:
                    _cache[key] = {
                        "expires_at": now + ttl,
                        "country": country,
                        "client_ip": client_ip,
                        "result": {k: v for k, v in result.items() if k != "from_cache"},
                    }
    return result


def invalidate_identity(identity):
    """이 사람의 '통과' 캐시를 모두 지운다(WAF가 이 사람의 공격을 막았을 때 등 - 다음 요청은 엔진에 다시 묻는다)."""
    identity = (identity or "").strip().lower()
    with _cache_lock:
        for key in [k for k in _cache if str(k[0]).strip().lower() == identity]:
            del _cache[key]


def resource_path_for(host, path):
    """요청이 어느 자원인지 = "호스트+경로"(쿼리 제외). index.js(Worker)의 extractResourcePath와 같은 형식이고,
    등급 판단은 엔진(RESOURCE_TIERS)이 한다. 호스트는 소문자로, 포트가 붙어 있으면 뗀다."""
    host = (host or "").split(":")[0].strip().lower()
    path = (path or "/").split("?")[0]
    if not path.startswith("/"):
        path = "/" + path
    return host + path


def stepup_url(auth_domain, host, path, query, is_api):
    """추가 인증(step-up) 페이지 주소. 인증을 마치면 원래 페이지로 돌아오도록 return_url을 붙인다.
    fetch 호출(API)은 인증 후 그 API 주소가 아니라 호출한 페이지(관리자 콘솔)로 돌아가야 한다."""
    if is_api:
        return_url = f"https://{host}/"
    else:
        return_url = f"https://{host}{path}" + (f"?{query}" if query else "")
    return f"https://{auth_domain}/stepup?return_url={quote(return_url, safe='')}"
