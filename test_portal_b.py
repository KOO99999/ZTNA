"""
portal_app.py(앱), zt_jwt.py(JWT 검증), zt_risk.py(위험도 확인)의 B 계층(check_risk 캐시, 게이트, 응답 형식)을 실제 AWS/네트워크 없이 검증.
Lambda 호출(requests.post)은 가짜로 대체하고, 호출 횟수와 보낸 내용을 기록해서 확인한다.
"""
import os
import sys
import json
import time as _time
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

os.environ["PDP_EVALUATE_URL"] = "https://pdp.test/evaluate"
os.environ["EVALUATE_SHARED_SECRET"] = "test-secret-local-only"
os.environ["AUTH_DOMAIN"] = "auth.xmcda.store"
os.environ["CF_TEAM_DOMAIN"] = "team-test.cloudflareaccess.com"
os.environ["CF_ACCESS_AUDS"] = "aud-portal,aud-admin"
sys.modules['boto3'] = MagicMock()
sys.path.insert(0, '.')
import portal_app as pa
import zt_jwt as zj
import zt_risk as zr

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
    zr._cache.clear()
    next_response = resp or {"allow": True, "action": "allow", "score": 0, "resource_threshold": 40, "resource_tier": "confidential"}
    next_status = status
    raise_error = error

def at_kst(h, m=0, s=0):
    return datetime(2026, 10, 6, h, m, s, tzinfo=KST).timestamp()

zr.requests.post = fake_post
client = pa.app.test_client()

# ---- Cloudflare JWT 가짜 발급 환경: 테스트용 RSA 키 2개(정상 키 / 위조자 키) ----
GOOD_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EVIL_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ISS = "https://team-test.cloudflareaccess.com"
jwks_fetches = []

def fake_fetch_jwks():
    jwks_fetches.append(1)
    return {"kid-good": GOOD_KEY.public_key()}

zj._fetch_jwks = fake_fetch_jwks

def make_token(email="hana@test.com", key=None, kid="kid-good", alg="RS256", iss=ISS,
               aud=("aud-portal",), exp_delta=300, drop=(), extra=None):
    now = int(_time.time())
    claims = {"email": email, "iss": iss, "aud": list(aud), "iat": now, "exp": now + exp_delta}
    if extra:
        claims.update(extra)
    for d in drop:
        claims.pop(d, None)
    return pyjwt.encode(claims, key or GOOD_KEY, algorithm=alg, headers={"kid": kid})

def hdr(email="hana@test.com", country="KR", **kw):
    return {"Cf-Access-Jwt-Assertion": make_token(email, **kw), "CF-IPCountry": country}

H = hdr()

# ---------- 1. 야간 경계 계산 ----------
def sub(h, m=0, s=0):
    return zr.seconds_until_night_boundary(datetime.fromtimestamp(at_kst(h, m, s), timezone.utc))

check("경계: 21:58 KST -> 22:00까지 120초", abs(sub(21, 58) - 120) < 1, sub(21, 58))
check("경계: 05:59:30 KST -> 06:00까지 30초", abs(sub(5, 59, 30) - 30) < 1, sub(5, 59, 30))
check("경계: 06:00:00 정각 -> 다음은 22:00 (16시간)", abs(sub(6, 0, 0) - 16 * 3600) < 1, sub(6, 0, 0))
check("경계: 22:00:00 정각 -> 다음은 06:00 (8시간)", abs(sub(22, 0, 0) - 8 * 3600) < 1, sub(22, 0, 0))
check("경계: 14:00 KST -> 22:00까지 8시간", abs(sub(14) - 8 * 3600) < 1, sub(14))
check("경계: 00:00 KST -> 06:00까지 6시간", abs(sub(0) - 6 * 3600) < 1, sub(0))

# ---------- 2. 캐시 ----------
with patch.object(zr.time, "time", return_value=at_kst(14, 0, 0)):
    reset()
    zr.check_risk("hana@test.com", "KR", "/dev")
    r2 = zr.check_risk("hana@test.com", "KR", "/dev")
    check("기밀: 같은 사용자/자원/국가 재요청은 캐시 사용 (Lambda 1회)", len(calls) == 1 and r2["from_cache"] is True, f"calls={len(calls)}")

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

    reset(resp={"allow": True, "action": "allow", "score": 0, "resource_threshold": 20, "resource_tier": "top_secret"})
    zr.check_risk("hana@test.com", "KR", "/admin")
    zr.check_risk("hana@test.com", "KR", "/admin")
    zr.check_risk("hana@test.com", "KR", "/admin")
    check("최고기밀(관리자): 캐시 없이 매 요청 Lambda 호출", len(calls) == 3, f"calls={len(calls)}")

    reset(resp={"allow": False, "action": "step_up_mfa_required", "score": 60, "resource_threshold": 40, "resource_tier": "confidential"})
    zr.check_risk("hana@test.com", "KR", "/dev")
    zr.check_risk("hana@test.com", "KR", "/dev")
    check("step-up 필요 결과는 캐시하지 않음 (재인증 후 바로 풀려야 함)", len(calls) == 2, f"calls={len(calls)}")

    reset(resp={"allow": False, "action": "block", "score": 100, "resource_threshold": 40, "resource_tier": "confidential"})
    zr.check_risk("hana@test.com", "KR", "/dev")
    zr.check_risk("hana@test.com", "KR", "/dev")
    check("차단 결과는 캐시하지 않음", len(calls) == 2, f"calls={len(calls)}")

    reset(resp={"allow": True, "action": "step_up_mfa_verified", "score": 60, "resource_threshold": 40, "resource_tier": "confidential"})
    zr.check_risk("hana@test.com", "KR", "/dev")
    r = zr.check_risk("hana@test.com", "KR", "/dev")
    check("step-up 재인증 후 통과(allow=True)는 캐시 대상", len(calls) == 1 and r["from_cache"], f"calls={len(calls)}")

    reset(error=True)
    r = zr.check_risk("hana@test.com", "KR", "/dev")
    zr.check_risk("hana@test.com", "KR", "/dev")
    check("Lambda 호출 실패 -> fail-closed, 실패는 캐시하지 않음", r["allow"] is False and r["error"] is True and len(calls) == 2, f"calls={len(calls)} result={r}")

    reset(status=500)
    r = zr.check_risk("hana@test.com", "KR", "/dev")
    check("Lambda가 200이 아니면 fail-closed", r["allow"] is False and r["error"] is True)

    reset(resp={"allow": True, "action": "allow", "score": 0, "resource_threshold": 40, "resource_tier": None})
    zr.check_risk("hana@test.com", "KR", "/mystery")
    zr.check_risk("hana@test.com", "KR", "/mystery")
    check("등급을 모르는 자원은 캐시하지 않음", len(calls) == 2, f"calls={len(calls)}")

    reset(resp={"allow": "true", "action": "allow"})
    r = zr.check_risk("hana@test.com", "KR", "/dev")
    check("allow가 정확히 True가 아니면(문자열 등) 허용으로 보지 않음", r["allow"] is False, f"allow={r['allow']}")

# 시간 경과에 따른 만료
reset()
with patch.object(zr.time, "time", return_value=at_kst(14, 0, 0)):
    zr.check_risk("hana@test.com", "KR", "/dev")
with patch.object(zr.time, "time", return_value=at_kst(14, 1, 0)):   # 60초 후 (TTL 90초 이내)
    zr.check_risk("hana@test.com", "KR", "/dev")
check("기밀 TTL(90초) 이내(60초 후)는 캐시 사용", len(calls) == 1, f"calls={len(calls)}")
with patch.object(zr.time, "time", return_value=at_kst(14, 1, 31)):  # 91초 후
    zr.check_risk("hana@test.com", "KR", "/dev")
check("기밀 TTL(90초) 지나면(91초 후) 재평가", len(calls) == 2, f"calls={len(calls)}")

reset(resp={"allow": True, "action": "allow", "score": 0, "resource_threshold": 60, "resource_tier": "internal"})
with patch.object(zr.time, "time", return_value=at_kst(14, 0, 0)):
    zr.check_risk("hana@test.com", "KR", "/marketing")
with patch.object(zr.time, "time", return_value=at_kst(14, 4, 59)):
    zr.check_risk("hana@test.com", "KR", "/marketing")
check("내부 TTL(300초) 이내(299초 후)는 캐시 사용", len(calls) == 1, f"calls={len(calls)}")
with patch.object(zr.time, "time", return_value=at_kst(14, 5, 1)):
    zr.check_risk("hana@test.com", "KR", "/marketing")
check("내부 TTL(300초) 지나면 재평가", len(calls) == 2, f"calls={len(calls)}")

# 야간 경계에서 끊기
reset(resp={"allow": True, "action": "allow", "score": 0, "resource_threshold": 60, "resource_tier": "internal"})
with patch.object(zr.time, "time", return_value=at_kst(21, 58, 0)):   # 22:00까지 120초, TTL은 300초
    zr.check_risk("hana@test.com", "KR", "/marketing")
with patch.object(zr.time, "time", return_value=at_kst(21, 59, 30)):  # 경계 전: 캐시 사용
    zr.check_risk("hana@test.com", "KR", "/marketing")
check("21:58에 만든 캐시는 22:00 전(21:59:30)에는 사용", len(calls) == 1, f"calls={len(calls)}")
with patch.object(zr.time, "time", return_value=at_kst(22, 0, 1)):    # 경계 직후: TTL(300초)은 남았지만 끊겨야 함
    zr.check_risk("hana@test.com", "KR", "/marketing")
check("21:58에 만든 캐시는 TTL이 남았어도 22:00 이후(22:00:01)에는 재평가", len(calls) == 2, f"calls={len(calls)}")

reset(resp={"allow": True, "action": "allow", "score": 0, "resource_threshold": 60, "resource_tier": "internal"})
with patch.object(zr.time, "time", return_value=at_kst(5, 59, 0)):
    zr.check_risk("hana@test.com", "KR", "/marketing")
with patch.object(zr.time, "time", return_value=at_kst(6, 0, 1)):
    zr.check_risk("hana@test.com", "KR", "/marketing")
check("05:59에 만든 캐시도 06:00 이후에는 재평가(야간 종료 경계)", len(calls) == 2, f"calls={len(calls)}")

# 캐시 크기 상한
reset()
with patch.object(zr.time, "time", return_value=at_kst(14, 0, 0)):
    for i in range(zr._CACHE_MAX_ENTRIES + 50):
        zr.check_risk(f"u{i}@test.com", "KR", "/dev")
check("캐시 항목 수가 상한을 넘지 않음", len(zr._cache) <= zr._CACHE_MAX_ENTRIES, f"size={len(zr._cache)}")

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
check("Lambda 호출 timeout 설정됨", sent["timeout"] == zr.PDP_TIMEOUT_SECONDS)

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

# ---------- 7. Cloudflare JWT 서명 검증 (검증 실패 = 기록 + 즉시 차단) ----------
import io, contextlib

def blocked_with_log(headers, path="/dev", host="xmcda.store"):
    """요청을 보내고 (상태코드, 응답, 출력된 로그, Lambda 호출 수)를 돌려준다."""
    reset()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = client.get(path, headers={**headers, "Host": host})
    return r, buf.getvalue(), len(calls)

r, log, n = blocked_with_log({"CF-IPCountry": "KR"})
check("JWT 없음 -> 403, Lambda 호출 없음, 실패 기록(token_missing)",
      r.status_code == 403 and n == 0 and "[JWT_VERIFY_FAILED] reason=token_missing" in log, f"{r.status_code} {log!r}")

r, log, n = blocked_with_log({"Cf-Access-Authenticated-User-Email": "hana@test.com", "CF-IPCountry": "KR"})
check("평문 이메일 헤더만 있고 JWT 없음(위조 시나리오) -> 차단", r.status_code == 403 and n == 0 and "token_missing" in log)

r, log, n = blocked_with_log({**hdr(), "Cf-Access-Authenticated-User-Email": "admin@test.com"})
check("JWT는 hana인데 평문 헤더만 admin으로 바꿔도 신원은 hana(JWT)로 Lambda에 전달",
      r.status_code == 200 and calls[0]["json"]["identity"] == "hana@test.com", calls[0]["json"] if calls else "no call")

r, log, n = blocked_with_log({"Cf-Access-Jwt-Assertion": "not.a.jwt", "CF-IPCountry": "KR"})
check("형식이 깨진 토큰 -> 차단 + 기록(malformed)", r.status_code == 403 and n == 0 and "reason=malformed" in log, log)

r, log, n = blocked_with_log(hdr(key=EVIL_KEY))
check("위조 서명(다른 개인키로 서명, kid만 정상) -> 차단 + 기록(bad_signature)",
      r.status_code == 403 and n == 0 and "reason=bad_signature" in log, log)

r, log, n = blocked_with_log(hdr(kid="kid-unknown"))
check("모르는 kid -> 차단 + 기록(unknown_kid)", r.status_code == 403 and n == 0 and "reason=unknown_kid" in log, log)

r, log, n = blocked_with_log(hdr(exp_delta=-10))
check("만료된 토큰 -> 차단 + 기록(expired)", r.status_code == 403 and n == 0 and "reason=expired" in log, log)

r, log, n = blocked_with_log(hdr(aud=("aud-other",)))
check("다른 앱의 aud -> 차단 + 기록(bad_aud)", r.status_code == 403 and n == 0 and "reason=bad_aud" in log, log)

r, log, n = blocked_with_log(hdr(iss="https://evil.cloudflareaccess.com"))
check("다른 발급자(iss) -> 차단 + 기록(bad_iss)", r.status_code == 403 and n == 0 and "reason=bad_iss" in log, log)

r, log, n = blocked_with_log(hdr(drop=("exp",)))
check("exp 없는 토큰 -> 차단(영구 토큰 방지)", r.status_code == 403 and n == 0 and "reason=missing_claim" in log, log)

r, log, n = blocked_with_log(hdr(drop=("email",)))
check("email 클레임 없는 토큰(서비스 토큰 등) -> 차단 + 기록(no_email_claim)",
      r.status_code == 403 and n == 0 and "reason=no_email_claim" in log, log)

none_token = pyjwt.encode({"email": "hana@test.com", "iss": ISS, "aud": ["aud-portal"], "iat": int(_time.time()), "exp": int(_time.time()) + 300},
                          key=None, algorithm="none", headers={"kid": "kid-good"})
r, log, n = blocked_with_log({"Cf-Access-Jwt-Assertion": none_token, "CF-IPCountry": "KR"})
check("alg=none 토큰 -> 차단", r.status_code == 403 and n == 0 and "reason=bad_alg_or_kid" in log, log)

import hmac as _hmac, hashlib as _hashlib, base64 as _b64
def b64(b): return _b64.urlsafe_b64encode(b).rstrip(b"=")
pub_pem = GOOD_KEY.public_key().public_bytes(
    __import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).Encoding.PEM,
    __import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).PublicFormat.SubjectPublicKeyInfo)
hs_head = b64(json.dumps({"alg": "HS256", "kid": "kid-good", "typ": "JWT"}).encode())
hs_body = b64(json.dumps({"email": "hana@test.com", "iss": ISS, "aud": ["aud-portal"], "iat": int(_time.time()), "exp": int(_time.time()) + 300}).encode())
hs_sig = b64(_hmac.new(pub_pem, hs_head + b"." + hs_body, _hashlib.sha256).digest())
r, log, n = blocked_with_log({"Cf-Access-Jwt-Assertion": (hs_head + b"." + hs_body + b"." + hs_sig).decode(), "CF-IPCountry": "KR"})
check("HS256 혼동 공격(공개키를 HMAC 비밀로 사용) -> 차단", r.status_code == 403 and n == 0 and "reason=bad_alg_or_kid" in log, log)

r, log, n = blocked_with_log({**hdr(key=EVIL_KEY)}, path="/api/db-data?type=admin_logs", host="admin.xmcda.store")
check("JWT 검증 실패(API) -> 403 JSON Denied, Lambda 호출 없음", r.status_code == 403 and r.get_json()["status"] == "Denied" and n == 0)

r, log, n = blocked_with_log(hdr(key=EVIL_KEY))
check("검증 실패 로그에 토큰 원문이 없음", make_token()[:20] not in log and "eyJ" not in log, log)

# 정상 토큰
r, log, n = blocked_with_log(hdr(aud=("aud-admin",)), path="/dev")
check("정상 토큰(두 번째 허용 aud) -> 통과, 로그에 실패 기록 없음", r.status_code == 200 and "JWT_VERIFY_FAILED" not in log, f"{r.status_code} {log!r}")

r, log, n = blocked_with_log(hdr(aud=("aud-other", "aud-portal")))
check("aud 목록 중 하나라도 허용 목록에 있으면 통과", r.status_code == 200, r.status_code)

reset()
pa.table = MagicMock()
pa.table.scan.return_value = {"Items": []}
r = client.get("/api/db-data?type=admin_logs", headers={**hdr(), "Host": "admin.xmcda.store"})
check("정상 토큰: /api/db-data 응답의 identity가 JWT의 email", r.status_code == 200 and r.get_json()["identity"] == "hana@test.com", r.get_data(as_text=True))

reset()
r = client.get("/dev", headers={**hdr(email="kim@test.com")})
check("Lambda에 보내는 identity는 JWT의 email", calls[0]["json"]["identity"] == "kim@test.com", calls[0]["json"])

r = client.get("/hr", headers=hdr(email="kim@test.com"))
check("화면에 표시되는 계정도 JWT의 email", "kim@test.com" in r.get_data(as_text=True))

# 설정 누락 -> fail-closed
saved = (zj.CF_ISSUER, zj.CF_ACCESS_AUDS)
zj.CF_ISSUER, zj.CF_ACCESS_AUDS = None, []
r, log, n = blocked_with_log(hdr())
check("팀 도메인/AUD 설정이 없으면 모두 차단(fail-closed) + 기록(config_missing)",
      r.status_code == 403 and n == 0 and "reason=config_missing" in log, log)
zj.CF_ISSUER, zj.CF_ACCESS_AUDS = saved

# 공개키 가져오기: 캐시 / 실패 / 키 교체
zj._jwks.update({"keys": {}, "fetched_at": 0.0})
jwks_fetches.clear()
client.get("/dev", headers=hdr()); client.get("/dev", headers=hdr()); client.get("/dev", headers=hdr())
check("공개키 목록은 캐시되어 요청마다 받지 않음(1회)", len(jwks_fetches) == 1, len(jwks_fetches))

def failing_fetch():
    raise RuntimeError("cloudflare unreachable")
orig_fetch = zj._fetch_jwks
zj._jwks.update({"keys": {}, "fetched_at": 0.0})
zj._fetch_jwks = failing_fetch
r, log, n = blocked_with_log(hdr())
check("공개키를 못 받고 아는 키도 없으면 차단 + 기록(jwks_unavailable)",
      r.status_code == 403 and n == 0 and "reason=jwks_unavailable" in log, log)
zj._fetch_jwks = orig_fetch

zj._jwks.update({"keys": {"kid-good": GOOD_KEY.public_key()}, "fetched_at": _time.time() - zj.JWKS_CACHE_SECONDS - 5})
zj._fetch_jwks = failing_fetch
r, log, n = blocked_with_log(hdr())
check("캐시가 오래됐고 새로 못 받아도, 이미 아는 키로는 계속 검증(Cloudflare 일시 장애 대응)", r.status_code == 200, f"{r.status_code} {log!r}")
zj._fetch_jwks = orig_fetch

zj._jwks.update({"keys": {"kid-good": GOOD_KEY.public_key()}, "fetched_at": _time.time()})
jwks_fetches.clear()
for _ in range(5):
    client.get("/dev", headers=hdr(kid="kid-unknown"))
check("모르는 kid가 반복돼도 공개키 재요청 폭주 없음(1분 최소 간격)", len(jwks_fetches) == 0, len(jwks_fetches))

# 키 교체: 캐시에 없는 새 kid가 나타나면(1분 이상 지났을 때) 다시 받아서 통과
NEW_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
def rotated_fetch():
    return {"kid-good": GOOD_KEY.public_key(), "kid-new": NEW_KEY.public_key()}
zj._fetch_jwks = rotated_fetch
zj._jwks.update({"keys": {"kid-good": GOOD_KEY.public_key()}, "fetched_at": _time.time() - 120})
reset()
r = client.get("/dev", headers=hdr(key=NEW_KEY, kid="kid-new"))
check("Cloudflare 키 교체: 새 kid가 나오면 공개키를 다시 받아 통과", r.status_code == 200, r.status_code)
zj._fetch_jwks = orig_fetch

# ---------- 8. 디버그 라우트는 기본으로 꺼져 있음 ----------
reset()
r = client.get("/debug-headers", headers=H)
check("ZT_DEBUG_HEADERS 미설정이면 /debug-headers 없음(404)", r.status_code == 404, f"status={r.status_code}")

print()
print("실패 수:", fails)
sys.exit(1 if fails else 0)
