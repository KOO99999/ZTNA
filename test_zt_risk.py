"""
zt_risk.py(위험도 확인: Lambda 호출 + 결과 캐시)를 실제 AWS/네트워크 없이 검증.
캐시 유효기간은 Lambda가 응답의 cache_ttl_seconds로 정해서 보내므로(등급표/야간 경계 계산은
test_risk_score.py가 검증), 여기서는 "받은 값을 그대로 따르는지"와 캐시 규칙을 확인한다.
Lambda 호출(requests.post)은 가짜로 대체하고, 호출 횟수와 보낸 내용을 기록한다.
"""
import os
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

os.environ["PDP_EVALUATE_URL"] = "https://pdp.test/evaluate"
os.environ["EVALUATE_SHARED_SECRET"] = "test-secret-local-only"
sys.path.insert(0, '.')
import zt_risk as zr

KST = timezone(timedelta(hours=9))
fails = 0

def check(name, cond, detail=""):
    global fails
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f"\n    -> {detail}" if detail else ""))
    if not cond:
        fails += 1

def resp(tier="confidential", ttl=90, allow=True, action="allow", threshold=40, score=0, **extra):
    d = {"allow": allow, "action": action, "score": score, "resource_threshold": threshold, "resource_tier": tier}
    if ttl is not None:
        d["cache_ttl_seconds"] = ttl
    d.update(extra)
    return d

calls = []
next_response = resp()
next_status = 200
raise_error = False

def fake_post(url, headers=None, json=None, timeout=None):
    calls.append({"url": url, "headers": headers, "json": json, "timeout": timeout})
    if raise_error:
        raise RuntimeError("network down")
    r = MagicMock()
    r.status_code = next_status
    r.json.return_value = dict(next_response)
    return r

def reset(r=None, status=200, error=False):
    global next_response, next_status, raise_error
    calls.clear()
    zr._cache.clear()
    next_response = r or resp()
    next_status = status
    raise_error = error

def at(h, m=0, s=0):
    return datetime(2026, 10, 6, h, m, s, tzinfo=KST).timestamp()

zr.requests.post = fake_post

# ---------- 1. 캐시 규칙 ----------
with patch.object(zr.time, "time", return_value=at(14)):
    reset()
    zr.check_risk("hana@test.com", "KR", "/dev")
    r2 = zr.check_risk("hana@test.com", "KR", "/dev")
    check("같은 사용자/자원/국가 재요청은 캐시 사용 (Lambda 1회)", len(calls) == 1 and r2["from_cache"] is True, f"calls={len(calls)}")

    reset()
    zr.check_risk("hana@test.com", "KR", "/dev")
    zr.check_risk("hana@test.com", "KR", "/hr")
    check("자원이 다르면 캐시를 공유하지 않음", len(calls) == 2, f"calls={len(calls)}")

    reset()
    zr.check_risk("hana@test.com", "KR", "/dev")
    zr.check_risk("kim@test.com", "KR", "/dev")
    check("사용자가 다르면 캐시를 공유하지 않음", len(calls) == 2, f"calls={len(calls)}")

    reset()
    zr.check_risk("hana@test.com", "KR", "/dev")
    zr.check_risk("hana@test.com", "US", "/dev")
    check("국가가 바뀌면 캐시 시간 안이어도 즉시 재평가", len(calls) == 2 and calls[1]["json"]["geo_country"] == "US", f"calls={len(calls)}")

    reset()
    zr.check_risk("hana@test.com", None, "/dev")
    zr.check_risk("hana@test.com", "KR", "/dev")
    check("국가 값이 없다가 생겨도 재평가", len(calls) == 2, f"calls={len(calls)}")

    reset(resp("top_secret", ttl=0, threshold=20))
    for _ in range(3):
        zr.check_risk("hana@test.com", "KR", "/admin")
    check("Lambda가 cache_ttl_seconds=0을 주면 캐시 없이 매 요청 Lambda 호출", len(calls) == 3, f"calls={len(calls)}")

    reset(resp(allow=False, action="step_up_mfa_required", score=60, ttl=0))
    zr.check_risk("hana@test.com", "KR", "/dev")
    zr.check_risk("hana@test.com", "KR", "/dev")
    check("step-up 필요 결과는 캐시하지 않음 (재인증 후 바로 풀려야 함)", len(calls) == 2, f"calls={len(calls)}")

    # Lambda가 실수로 차단 응답에 ttl을 실어 보내도 차단은 절대 저장하지 않는다
    reset(resp(allow=False, action="block", score=100, ttl=90))
    zr.check_risk("hana@test.com", "KR", "/dev")
    zr.check_risk("hana@test.com", "KR", "/dev")
    check("차단 결과는 ttl이 붙어 와도 캐시하지 않음", len(calls) == 2, f"calls={len(calls)}")

    reset(resp(action="step_up_mfa_verified", score=60, ttl=30))
    zr.check_risk("hana@test.com", "KR", "/dev")
    r = zr.check_risk("hana@test.com", "KR", "/dev")
    check("step-up 재인증 후 통과(allow=True)는 Lambda가 준 ttl만큼 캐시", len(calls) == 1 and r["from_cache"], f"calls={len(calls)}")

    reset(error=True)
    r = zr.check_risk("hana@test.com", "KR", "/dev")
    zr.check_risk("hana@test.com", "KR", "/dev")
    check("Lambda 호출 실패 -> fail-closed, 실패는 캐시하지 않음", r["allow"] is False and r["error"] is True and len(calls) == 2, f"calls={len(calls)} result={r}")

    reset(status=500)
    r = zr.check_risk("hana@test.com", "KR", "/dev")
    check("Lambda가 200이 아니면 fail-closed", r["allow"] is False and r["error"] is True)

    reset(resp(tier=None, ttl=0))
    zr.check_risk("hana@test.com", "KR", "/mystery")
    zr.check_risk("hana@test.com", "KR", "/mystery")
    check("등급을 모르는 자원(Lambda가 ttl=0)은 캐시하지 않음", len(calls) == 2, f"calls={len(calls)}")

    reset({"allow": "true", "action": "allow"})
    r = zr.check_risk("hana@test.com", "KR", "/dev")
    check("allow가 정확히 True가 아니면(문자열 등) 허용으로 보지 않음", r["allow"] is False, f"allow={r['allow']}")

# ---------- 2. Lambda가 정한 유효기간을 그대로 따르는지 ----------
def probe(ttl_field, wait):
    """ttl_field를 Lambda 응답으로 받고, wait초 뒤에 같은 요청을 보냈을 때 Lambda 호출 횟수."""
    reset(resp(ttl=ttl_field) if ttl_field != "MISSING" else resp(ttl=None))
    with patch.object(zr.time, "time", return_value=at(14, 0, 0)):
        zr.check_risk("hana@test.com", "KR", "/dev")
    with patch.object(zr.time, "time", return_value=at(14, 0, 0) + wait):
        zr.check_risk("hana@test.com", "KR", "/dev")
    return len(calls)

check("ttl=30: 29초 후에는 캐시 사용", probe(30, 29) == 1)
check("ttl=30: 31초 후에는 재평가", probe(30, 31) == 2)
check("ttl=90: 89초 후 캐시 사용 / 91초 후 재평가", probe(90, 89) == 1 and probe(90, 91) == 2)
check("ttl=300: 299초 후 캐시 사용 / 301초 후 재평가", probe(300, 299) == 1 and probe(300, 301) == 2)
check("ttl 필드가 없으면(옛 Lambda) 캐시하지 않음", probe("MISSING", 1) == 2)
check("ttl이 문자열이면 캐시하지 않음", probe("90", 1) == 2)
check("ttl이 true(불리언)이면 캐시하지 않음", probe(True, 1) == 2)
check("ttl이 음수이면 캐시하지 않음", probe(-5, 1) == 2)
check("ttl이 너무 크면 안전 상한(900초)에서 끊김: 899초 후 사용 / 901초 후 재평가",
      probe(99999, 899) == 1 and probe(99999, 901) == 2)

# 캐시 크기 상한
reset()
with patch.object(zr.time, "time", return_value=at(14)):
    for i in range(zr._CACHE_MAX_ENTRIES + 50):
        zr.check_risk(f"u{i}@test.com", "KR", "/dev")
check("캐시 항목 수가 상한을 넘지 않음", len(zr._cache) <= zr._CACHE_MAX_ENTRIES, f"size={len(zr._cache)}")

# ---------- 3. 이 모듈에 정책(등급표, 야간 기준)이 남아 있지 않음 ----------
check("zt_risk에 등급별 캐시 시간표가 없음(Lambda가 정함)", not hasattr(zr, "CACHE_TTL_SECONDS"))
check("zt_risk에 야간 경계 계산이 없음(Lambda가 정함)", not hasattr(zr, "seconds_until_night_boundary"))

# ---------- 4. Lambda로 보내는 내용 ----------
reset()
zr.check_risk("hana@test.com", "KR", "/dev")
sent = calls[0]
check("Lambda 호출에 비밀키 헤더 포함", sent["headers"].get("X-Evaluate-Secret") == "test-secret-local-only")
check("Lambda 호출 본문: identity/geo_country/resource_path/source",
      sent["json"]["identity"] == "hana@test.com" and sent["json"]["geo_country"] == "KR"
      and sent["json"]["resource_path"] == "/dev" and sent["json"]["source"] == "B", sent["json"])
check("Lambda 호출 본문에 UTC ISO8601 request_timestamp 포함",
      sent["json"]["request_timestamp"].endswith("+00:00"), sent["json"]["request_timestamp"])
check("Lambda 호출 timeout 설정됨", sent["timeout"] == zr.PDP_TIMEOUT_SECONDS)

# ---------- 5. 자원 매핑 / step-up 주소 ----------
check("admin 서브도메인 / -> /admin", zr.resource_path_for("admin.xmcda.store", "/") == "/admin")
check("admin 서브도메인 /api/db-data -> /api/db-data", zr.resource_path_for("admin.xmcda.store", "/api/db-data") == "/api/db-data")
check("포털 홈 -> /", zr.resource_path_for("xmcda.store", "/") == "/")
check("끝의 슬래시 제거: /dev/ -> /dev", zr.resource_path_for("xmcda.store", "/dev/") == "/dev")
u = zr.stepup_url("auth.xmcda.store", "xmcda.store", "/hr", "x=1", False)
check("step-up 주소의 return_url이 원래 주소(쿼리 포함)", u == "https://auth.xmcda.store/stepup?return_url=https%3A%2F%2Fxmcda.store%2Fhr%3Fx%3D1", u)
u = zr.stepup_url("auth.xmcda.store", "admin.xmcda.store", "/api/db-data", "type=a", True)
check("API 호출의 step-up return_url은 API가 아니라 관리자 페이지", u.endswith("return_url=https%3A%2F%2Fadmin.xmcda.store%2F"), u)

# ---------- 6. 설정 누락 -> fail-closed ----------
saved = (zr.PDP_EVALUATE_URL, zr.EVALUATE_SHARED_SECRET)
zr.PDP_EVALUATE_URL, zr.EVALUATE_SHARED_SECRET = None, None
reset()
r = zr.check_risk("hana@test.com", "KR", "/dev")
check("Lambda 주소/비밀키 설정이 없으면 차단(fail-closed), 호출 시도 없음", r["allow"] is False and r["error"] is True and len(calls) == 0)
zr.PDP_EVALUATE_URL, zr.EVALUATE_SHARED_SECRET = saved

print()
print("실패 수:", fails)
sys.exit(1 if fails else 0)
