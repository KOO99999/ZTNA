"""
portal_app.py의 B 계층(check_risk 캐시, 게이트, 응답 형식)을 실제 AWS/네트워크 없이 검증.
Lambda 호출(requests.post)은 가짜로 대체하고, 호출 횟수와 보낸 내용을 기록해서 확인한다.
"""
import os
import sys
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

os.environ["PDP_EVALUATE_URL"] = "https://pdp.test/evaluate"
os.environ["EVALUATE_SHARED_SECRET"] = "test-secret-local-only"
os.environ["AUTH_DOMAIN"] = "auth.xmcda.store"
sys.modules['boto3'] = MagicMock()
sys.path.insert(0, '.')
import portal_app as pa

KST = timezone(timedelta(hours=9))
fails = 0

def check(name, cond, detail=""):
    global fails
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f"\n    -> {detail}" if detail else ""))
    if not cond:
        fails += 1

# ---- Lambda 가짜 응답 ----
calls = []
next_response = {"allow": True, "action": "allow", "score": 0, "resource_threshold": 40, "resource_tier": "confidential"}
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

def reset(resp=None, status=200, error=False):
    global next_response, next_status, raise_error
    calls.clear()
    pa._cache.clear()
    next_response = resp or {"allow": True, "action": "allow", "score": 0, "resource_threshold": 40, "resource_tier": "confidential"}
    next_status = status
    raise_error = error

def at_kst(h, m=0, s=0):
    return datetime(2026, 10, 6, h, m, s, tzinfo=KST).timestamp()

pa.requests.post = fake_post
client = pa.app.test_client()
H = {"Cf-Access-Authenticated-User-Email": "hana@test.com", "CF-IPCountry": "KR"}

# ---------- 1. 야간 경계 계산 ----------
def sub(h, m=0, s=0):
    return pa.seconds_until_night_boundary(datetime.fromtimestamp(at_kst(h, m, s), timezone.utc))

check("경계: 21:58 KST -> 22:00까지 120초", abs(sub(21, 58) - 120) < 1, sub(21, 58))
check("경계: 05:59:30 KST -> 06:00까지 30초", abs(sub(5, 59, 30) - 30) < 1, sub(5, 59, 30))
check("경계: 06:00:00 정각 -> 다음은 22:00 (16시간)", abs(sub(6, 0, 0) - 16 * 3600) < 1, sub(6, 0, 0))
check("경계: 22:00:00 정각 -> 다음은 06:00 (8시간)", abs(sub(22, 0, 0) - 8 * 3600) < 1, sub(22, 0, 0))
check("경계: 14:00 KST -> 22:00까지 8시간", abs(sub(14) - 8 * 3600) < 1, sub(14))
check("경계: 00:00 KST -> 06:00까지 6시간", abs(sub(0) - 6 * 3600) < 1, sub(0))

# ---------- 2. 캐시 ----------
with patch.object(pa.time, "time", return_value=at_kst(14, 0, 0)):
    reset()
    pa.check_risk("hana@test.com", "KR", "/dev")
    r2 = pa.check_risk("hana@test.com", "KR", "/dev")
    check("기밀: 같은 사용자/자원/국가 재요청은 캐시 사용 (Lambda 1회)", len(calls) == 1 and r2["from_cache"] is True, f"calls={len(calls)}")

    reset()
    pa.check_risk("hana@test.com", "KR", "/dev")
    pa.check_risk("hana@test.com", "KR", "/hr")
    check("자원이 다르면 캐시를 공유하지 않음", len(calls) == 2, f"calls={len(calls)}")

    reset()
    pa.check_risk("hana@test.com", "KR", "/dev")
    pa.check_risk("kim@test.com", "KR", "/dev")
    check("사용자가 다르면 캐시를 공유하지 않음", len(calls) == 2, f"calls={len(calls)}")

    reset()
    pa.check_risk("hana@test.com", "KR", "/dev")
    pa.check_risk("hana@test.com", "US", "/dev")
    check("국가가 바뀌면 캐시 시간 안이어도 즉시 재평가", len(calls) == 2 and calls[1]["json"]["geo_country"] == "US", f"calls={len(calls)}")

    reset()
    pa.check_risk("hana@test.com", None, "/dev")
    pa.check_risk("hana@test.com", "KR", "/dev")
    check("국가 값이 없다가 생겨도 재평가", len(calls) == 2, f"calls={len(calls)}")

    reset(resp={"allow": True, "action": "allow", "score": 0, "resource_threshold": 20, "resource_tier": "top_secret"})
    pa.check_risk("hana@test.com", "KR", "/admin")
    pa.check_risk("hana@test.com", "KR", "/admin")
    pa.check_risk("hana@test.com", "KR", "/admin")
    check("최고기밀(관리자): 캐시 없이 매 요청 Lambda 호출", len(calls) == 3, f"calls={len(calls)}")

    reset(resp={"allow": False, "action": "step_up_mfa_required", "score": 60, "resource_threshold": 40, "resource_tier": "confidential"})
    pa.check_risk("hana@test.com", "KR", "/dev")
    pa.check_risk("hana@test.com", "KR", "/dev")
    check("step-up 필요 결과는 캐시하지 않음 (재인증 후 바로 풀려야 함)", len(calls) == 2, f"calls={len(calls)}")

    reset(resp={"allow": False, "action": "block", "score": 100, "resource_threshold": 40, "resource_tier": "confidential"})
    pa.check_risk("hana@test.com", "KR", "/dev")
    pa.check_risk("hana@test.com", "KR", "/dev")
    check("차단 결과는 캐시하지 않음", len(calls) == 2, f"calls={len(calls)}")

    reset(resp={"allow": True, "action": "step_up_mfa_verified", "score": 60, "resource_threshold": 40, "resource_tier": "confidential"})
    pa.check_risk("hana@test.com", "KR", "/dev")
    r = pa.check_risk("hana@test.com", "KR", "/dev")
    check("step-up 재인증 후 통과(allow=True)는 캐시 대상", len(calls) == 1 and r["from_cache"], f"calls={len(calls)}")

    reset(error=True)
    r = pa.check_risk("hana@test.com", "KR", "/dev")
    pa.check_risk("hana@test.com", "KR", "/dev")
    check("Lambda 호출 실패 -> fail-closed, 실패는 캐시하지 않음", r["allow"] is False and r["error"] is True and len(calls) == 2, f"calls={len(calls)} result={r}")

    reset(status=500)
    r = pa.check_risk("hana@test.com", "KR", "/dev")
    check("Lambda가 200이 아니면 fail-closed", r["allow"] is False and r["error"] is True)

    reset(resp={"allow": True, "action": "allow", "score": 0, "resource_threshold": 40, "resource_tier": None})
    pa.check_risk("hana@test.com", "KR", "/mystery")
    pa.check_risk("hana@test.com", "KR", "/mystery")
    check("등급을 모르는 자원은 캐시하지 않음", len(calls) == 2, f"calls={len(calls)}")

    reset(resp={"allow": "true", "action": "allow"})
    r = pa.check_risk("hana@test.com", "KR", "/dev")
    check("allow가 정확히 True가 아니면(문자열 등) 허용으로 보지 않음", r["allow"] is False, f"allow={r['allow']}")

# 시간 경과에 따른 만료
reset()
with patch.object(pa.time, "time", return_value=at_kst(14, 0, 0)):
    pa.check_risk("hana@test.com", "KR", "/dev")
with patch.object(pa.time, "time", return_value=at_kst(14, 1, 0)):   # 60초 후 (TTL 90초 이내)
    pa.check_risk("hana@test.com", "KR", "/dev")
check("기밀 TTL(90초) 이내(60초 후)는 캐시 사용", len(calls) == 1, f"calls={len(calls)}")
with patch.object(pa.time, "time", return_value=at_kst(14, 1, 31)):  # 91초 후
    pa.check_risk("hana@test.com", "KR", "/dev")
check("기밀 TTL(90초) 지나면(91초 후) 재평가", len(calls) == 2, f"calls={len(calls)}")

reset(resp={"allow": True, "action": "allow", "score": 0, "resource_threshold": 60, "resource_tier": "internal"})
with patch.object(pa.time, "time", return_value=at_kst(14, 0, 0)):
    pa.check_risk("hana@test.com", "KR", "/marketing")
with patch.object(pa.time, "time", return_value=at_kst(14, 4, 59)):
    pa.check_risk("hana@test.com", "KR", "/marketing")
check("내부 TTL(300초) 이내(299초 후)는 캐시 사용", len(calls) == 1, f"calls={len(calls)}")
with patch.object(pa.time, "time", return_value=at_kst(14, 5, 1)):
    pa.check_risk("hana@test.com", "KR", "/marketing")
check("내부 TTL(300초) 지나면 재평가", len(calls) == 2, f"calls={len(calls)}")

# 야간 경계에서 끊기
reset(resp={"allow": True, "action": "allow", "score": 0, "resource_threshold": 60, "resource_tier": "internal"})
with patch.object(pa.time, "time", return_value=at_kst(21, 58, 0)):   # 22:00까지 120초, TTL은 300초
    pa.check_risk("hana@test.com", "KR", "/marketing")
with patch.object(pa.time, "time", return_value=at_kst(21, 59, 30)):  # 경계 전: 캐시 사용
    pa.check_risk("hana@test.com", "KR", "/marketing")
check("21:58에 만든 캐시는 22:00 전(21:59:30)에는 사용", len(calls) == 1, f"calls={len(calls)}")
with patch.object(pa.time, "time", return_value=at_kst(22, 0, 1)):    # 경계 직후: TTL(300초)은 남았지만 끊겨야 함
    pa.check_risk("hana@test.com", "KR", "/marketing")
check("21:58에 만든 캐시는 TTL이 남았어도 22:00 이후(22:00:01)에는 재평가", len(calls) == 2, f"calls={len(calls)}")

reset(resp={"allow": True, "action": "allow", "score": 0, "resource_threshold": 60, "resource_tier": "internal"})
with patch.object(pa.time, "time", return_value=at_kst(5, 59, 0)):
    pa.check_risk("hana@test.com", "KR", "/marketing")
with patch.object(pa.time, "time", return_value=at_kst(6, 0, 1)):
    pa.check_risk("hana@test.com", "KR", "/marketing")
check("05:59에 만든 캐시도 06:00 이후에는 재평가(야간 종료 경계)", len(calls) == 2, f"calls={len(calls)}")

# 캐시 크기 상한
reset()
with patch.object(pa.time, "time", return_value=at_kst(14, 0, 0)):
    for i in range(pa._CACHE_MAX_ENTRIES + 50):
        pa.check_risk(f"u{i}@test.com", "KR", "/dev")
check("캐시 항목 수가 상한을 넘지 않음", len(pa._cache) <= pa._CACHE_MAX_ENTRIES, f"size={len(pa._cache)}")

# ---------- 3. Lambda로 보내는 내용 ----------
reset()
client.get("/dev", headers=H)
sent = calls[0]
check("Lambda 호출에 비밀키 헤더 포함", sent["headers"].get("X-Evaluate-Secret") == "test-secret-local-only")
check("Lambda 호출 본문: identity/geo_country/resource_path/source", 
      sent["json"]["identity"] == "hana@test.com" and sent["json"]["geo_country"] == "KR"
      and sent["json"]["resource_path"] == "/dev" and sent["json"]["source"] == "B", sent["json"])
check("Lambda 호출 본문에 UTC ISO8601 request_timestamp 포함",
      sent["json"]["request_timestamp"].endswith("+00:00"), sent["json"]["request_timestamp"])
check("Lambda 호출 timeout 설정됨", sent["timeout"] == pa.PDP_TIMEOUT_SECONDS)

# ---------- 4. 게이트: 자원 매핑 ----------
reset()
client.get("/", headers={**H, "Host": "admin.xmcda.store"})
check("admin 서브도메인 / -> resource_path=/admin", calls[0]["json"]["resource_path"] == "/admin", calls[0]["json"]["resource_path"])
reset()
client.get("/api/db-data?type=admin_logs", headers={**H, "Host": "admin.xmcda.store"})
check("admin 서브도메인 /api/db-data -> resource_path=/api/db-data", calls[0]["json"]["resource_path"] == "/api/db-data")
reset()
client.get("/", headers={**H, "Host": "xmcda.store"})
check("포털 홈 -> resource_path=/", calls[0]["json"]["resource_path"] == "/")
reset()
r = client.get("/no-such-page", headers=H)
check("등록되지 않은 경로는 404, Lambda 호출 없음", r.status_code == 404 and len(calls) == 0, f"status={r.status_code} calls={len(calls)}")

# ---------- 5. 게이트: 응답 형식 ----------
reset()
r = client.get("/dev", headers={"CF-IPCountry": "KR"})
check("인증 헤더 없음 -> 403, Lambda 호출 없음", r.status_code == 403 and len(calls) == 0, f"status={r.status_code}")
reset()
r = client.get("/api/db-data?type=admin_logs", headers={"CF-IPCountry": "KR", "Host": "admin.xmcda.store"})
check("인증 헤더 없음(API) -> 403 JSON", r.status_code == 403 and r.get_json()["status"] == "Denied", r.get_json())

reset(resp={"allow": False, "action": "step_up_mfa_required", "score": 60, "resource_threshold": 40, "resource_tier": "confidential"})
r = client.get("/hr?x=1", headers={**H, "Host": "xmcda.store"})
loc = r.headers.get("Location", "")
check("step-up 필요(페이지) -> 302 로 /stepup", r.status_code == 302 and loc.startswith("https://auth.xmcda.store/stepup?return_url="), loc)
check("step-up 리다이렉트의 return_url이 원래 주소(쿼리 포함)", "return_url=https%3A%2F%2Fxmcda.store%2Fhr%3Fx%3D1" in loc, loc)

reset(resp={"allow": False, "action": "step_up_mfa_required", "score": 40, "resource_threshold": 20, "resource_tier": "top_secret"})
r = client.get("/api/db-data?type=admin_logs", headers={**H, "Host": "admin.xmcda.store"})
body = r.get_json()
check("step-up 필요(API) -> 403 JSON, status=StepUpRequired", r.status_code == 403 and body["status"] == "StepUpRequired", body)
check("API step-up의 return_url은 API 주소가 아니라 관리자 페이지", "return_url=https%3A%2F%2Fadmin.xmcda.store%2F" in body["stepup_url"] and "api" not in body["stepup_url"].split("return_url=")[1], body["stepup_url"])

reset(resp={"allow": False, "action": "block", "score": 100, "resource_threshold": 40, "resource_tier": "confidential"})
r = client.get("/dev", headers=H)
text = r.get_data(as_text=True)
check("차단(페이지) -> 403, 점수/사유 노출 없음", r.status_code == 403 and "100" not in text and "confidential" not in text, f"status={r.status_code}")
r = client.get("/api/db-data?type=admin_logs", headers={**H, "Host": "admin.xmcda.store"})
check("차단(API) -> 403 JSON Denied", r.status_code == 403 and r.get_json()["status"] == "Denied")

reset(resp={"allow": False, "action": "block_until_mfa", "score": 94, "resource_threshold": 40, "resource_tier": "confidential"})
r = client.get("/dev", headers=H)
check("block_until_mfa도 step-up 안내가 아니라 차단", r.status_code == 403, f"status={r.status_code}")

reset(error=True)
r = client.get("/dev", headers=H)
check("Lambda 장애(페이지) -> 503 (fail-closed)", r.status_code == 503, f"status={r.status_code}")
r = client.get("/api/db-data?type=admin_logs", headers={**H, "Host": "admin.xmcda.store"})
check("Lambda 장애(API) -> 503 JSON", r.status_code == 503 and r.get_json()["status"] == "Error")

# ---------- 6. 통과 시 화면 ----------
reset(resp={"allow": True, "action": "allow", "score": 0, "resource_threshold": 40, "resource_tier": "confidential"})
r = client.get("/hr", headers=H)
text = r.get_data(as_text=True)
check("통과: /hr 화면에 Lambda가 적용한 임계값(40점) 표시", r.status_code == 200 and "40점" in text, f"status={r.status_code}")
reset(resp={"allow": True, "action": "allow", "score": 0, "resource_threshold": 20, "resource_tier": "top_secret"})
r = client.get("/", headers={**H, "Host": "admin.xmcda.store"})
text = r.get_data(as_text=True)
check("통과: 관리자 콘솔에 20점 표시, 옛 문구('신뢰 점수') 없음", "20점" in text and "신뢰 점수" not in text and "StepUpRequired" in text)
reset(resp={"allow": True, "action": "allow", "score": 0, "resource_threshold": 60, "resource_tier": "internal"})
r = client.get("/", headers={**H, "Host": "xmcda.store"})
check("통과: 포털 홈에 60점 표시", "60점" in r.get_data(as_text=True))

# ---------- 7. 디버그 라우트는 기본으로 꺼져 있음 ----------
reset()
r = client.get("/debug-headers", headers=H)
check("ZT_DEBUG_HEADERS 미설정이면 /debug-headers 없음(404)", r.status_code == 404, f"status={r.status_code}")

print()
print("실패 수:", fails)
sys.exit(1 if fails else 0)
