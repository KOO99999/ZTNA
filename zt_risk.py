"""위험도 확인 (Lambda PDP 호출 + 결과 캐시). 판단 서비스(auth_gate.py)가 쓰고,
nginx 전환이 끝나기 전까지는 앱(portal_app.py)도 쓴다.

환경변수: PDP_EVALUATE_URL, EVALUATE_SHARED_SECRET
"""
from datetime import datetime, timedelta, timezone
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


def resource_path_for(host, path):
    """요청이 어느 자원인지. index.js(Worker)의 extractResourcePath와 같은 규칙:
    admin 서브도메인이면 /admin 또는 /api/db-data, 그 외에는 요청 경로 그대로."""
    if (host or "").startswith("admin."):
        return "/api/db-data" if path == "/api/db-data" else "/admin"
    return path.rstrip("/") or "/"


def stepup_url(auth_domain, host, path, query, is_api):
    """추가 인증(step-up) 페이지 주소. 인증을 마치면 원래 페이지로 돌아오도록 return_url을 붙인다.
    fetch 호출(API)은 인증 후 그 API 주소가 아니라 호출한 페이지(관리자 콘솔)로 돌아가야 한다."""
    if is_api:
        return_url = f"https://{host}/"
    else:
        return_url = f"https://{host}{path}" + (f"?{query}" if query else "")
    return f"https://{auth_domain}/stepup?return_url={quote(return_url, safe='')}"
