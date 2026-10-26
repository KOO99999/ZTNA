"""
main.tf가 참조하는 risk_score_engine.py를 실제 AWS 없이 로컬에서 검증하는 스크립트.
v10: 전체 배점 2배 재설정 반영 (RISK_THRESHOLD=40, STEP_UP_MARGIN=20).
v12: 자원 등급(tier) 도입, /dev 임계값 60 -> 40.
"""
import os
import sys
import time
import json
from unittest.mock import MagicMock

# risk_score_engine.py가 import 시점에 os.environ에서 읽으므로 import보다 먼저 세팅해야 함
os.environ["EVALUATE_SHARED_SECRET"] = "test-secret-local-only"

sys.modules['boto3'] = MagicMock()
import boto3
mock_table = MagicMock()       # risk_score_log
mock_user_risk = MagicMock()    # [User Risk] 기본은 걸려 있는 신호 없음
mock_mfa_table = MagicMock()   # [step-up] mfa_verified - 별도 mock, 기본은 기록 없음(get_item 결과 없음)으로 둠
mock_decision = MagicMock()    # [마지막 판단] access_decision
mock_device_state = MagicMock()   # [기기 순찰] device_state, 기본은 기록 없음
mock_device_state.query.return_value = {"Items": []}

def _table_side_effect(name):
    if name == 'user_risk':
        return mock_user_risk
    if name == 'access_decision':
        return mock_decision
    if name == 'device_state':
        return mock_device_state
    return mock_mfa_table if name == 'mfa_verified' else mock_table

boto3.resource.return_value.Table.side_effect = _table_side_effect

sys.path.insert(0, '.')
import risk_score_engine as engine

TEST_HEADERS = {"x-evaluate-secret": "test-secret-local-only"}

def run_case(name, body, expect_allow=None, expect_action=None, mfa_record=None):
    mock_table.reset_mock()
    mock_mfa_table.reset_mock()
    mock_user_risk.reset_mock()
    mock_user_risk.query.return_value = {"Items": []}
    # 기본값: mfa_verified 기록 없음. mfa_record를 넘기면 그 내용으로 get_item이 응답하게 함
    # (예: {"identity": "...", "expires_at": now+600} 처럼 이미 저장돼있던 상황을 흉내)
    mock_mfa_table.get_item.return_value = {"Item": mfa_record} if mfa_record else {}
    result_raw = engine.lambda_handler({"headers": TEST_HEADERS, "body": json.dumps(body)}, None)
    result = json.loads(result_raw["body"])
    ok_allow = (expect_allow is None) or (result["allow"] == expect_allow)
    ok_action = (expect_action is None) or (result["action"] == expect_action)
    status = "PASS" if (ok_allow and ok_action) else "FAIL"
    print(f"[{status}] {name}")
    print(f"    -> risk_score={result['score']} allow={result['allow']} action={result['action']} reasons={result['reasons']}")
    if status == "FAIL":
        print(f"    !! 기대값: allow={expect_allow}, action={expect_action}")
    called = mock_table.put_item.called
    print(f"    -> DynamoDB put_item 호출됨: {called}")
    print()

now = int(time.time())

# RISK_MATRIX(v10): night_access=20, unknown_location=40, brute_force=58(resettable),
# threat_intel_match=86, waf_sqli=94, device_fingerprint_mismatch=76
# RISK_THRESHOLD=40 (이하 허용), STEP_UP_MARGIN=20 (40~60 구간이 경계)

run_case(
    "정상 접속 (신호 없음)",
    {"session_id": "s1", "identity": "hana@test.com"},
    expect_allow=True, expect_action="allow"
)

run_case(
    "야간 접속만 (behavioral, 경계 밖)",
    {"session_id": "s2", "identity": "hana@test.com", "night_access": True},
    expect_allow=True, expect_action="allow"
)

run_case(
    "WAF SQLi 탐지 (security, MFA 미통과)",
    {"session_id": "s3", "identity": "attacker@test.com", "waf_sqli": True},
    expect_allow=False, expect_action="block_until_mfa"
)

run_case(
    "WAF SQLi 이후 MFA 재인증 통과 (94점, resettable 아님 -> 여전히 차단)",
    {"session_id": "s3", "identity": "attacker@test.com", "waf_sqli": True, "security_mfa_passed": True},
    expect_allow=False, expect_action="block"
)

run_case(
    "단말 지문 불일치 단독 (security, +76)",
    {"session_id": "s4", "identity": "hana@test.com", "device_fingerprint_mismatch": True},
    expect_allow=False, expect_action="block_until_mfa"
)

run_case(
    "조합규칙: 위치이상+WAF SQLi (40+94+30=164)",
    {"session_id": "s5", "identity": "attacker@test.com", "unknown_location": True, "waf_sqli": True},
    expect_allow=False, expect_action="block_until_mfa"
)

run_case(
    "조합규칙: 브루트포스+위협인텔 (58+86+20=164)",
    {"session_id": "s6", "identity": "attacker@test.com", "brute_force": True, "threat_intel_match": True},
    expect_allow=False, expect_action="block_until_mfa"
)

run_case(
    "정확히 임계값(40)과 동일 -> 통과",
    {"session_id": "s7", "identity": "hana@test.com", "unknown_location": True},
    expect_allow=True, expect_action="allow"
)

run_case(
    "behavioral 조합 60(20+40) -> 경계구간(40,60], Step-up MFA",
    {"session_id": "s8", "identity": "hana@test.com", "night_access": True, "unknown_location": True},
    expect_allow=False, expect_action="step_up_mfa_required"
)

run_case(
    "security 위험 상태에서 History Decay 미적용 확인",
    {"session_id": "s9", "identity": "attacker@test.com", "waf_sqli": True,
     "last_activity_timestamp": now - 7200},
    expect_allow=False, expect_action="block_until_mfa"
)
print(">>> reasons에 'history_decay'가 없어야 정상 (security 위험 중엔 decay 스킵)")
print()

run_case(
    "brute_force 단독, MFA 미통과 -> +58 반영 확인",
    {"session_id": "s12", "identity": "hana@test.com", "brute_force": True},
    expect_allow=False, expect_action="block_until_mfa"
)

run_case(
    "brute_force + MFA 통과 -> resettable, 위험도 리셋되어 통과",
    {"session_id": "s12", "identity": "hana@test.com", "brute_force": True, "security_mfa_passed": True},
    expect_allow=True, expect_action="allow"
)
print(">>> risk_score가 0이어야 정상 (brute_force가 리셋으로 사라짐)")
print()

run_case(
    "waf_sqli + MFA 통과 -> resettable 아님, 위험도(94) 그대로 유지",
    {"session_id": "s13", "identity": "attacker@test.com", "waf_sqli": True, "security_mfa_passed": True},
    expect_allow=False, expect_action="block"
)
print(">>> risk_score가 94여야 정상")
print()

run_case(
    "조합규칙: brute_force(리셋됨)+threat_intel_match, MFA 통과 -> 86만 남음",
    {"session_id": "s14", "identity": "attacker@test.com", "brute_force": True,
     "threat_intel_match": True, "security_mfa_passed": True},
    expect_allow=False, expect_action="block"
)
print(">>> risk_score가 86이어야 정상 (조합 보너스 +20은 적용 안 됨)")
print()

# night_access(20)+decay(3시간*10=30)=50 -> (40,60] 경계구간
run_case(
    "behavioral+decay=50 -> Step-up MFA 트리거 확인",
    {"session_id": "s10", "identity": "hana@test.com", "night_access": True,
     "last_activity_timestamp": now - 3 * 3600},
    expect_allow=False, expect_action="step_up_mfa_required"
)

# device_fingerprint_mismatch(76)가 MFA 통과해도 경계+마진(60)을 안전하게 초과하는지 확인
run_case(
    "[v10] device_fingerprint_mismatch + MFA 통과 -> 76 > 60, 여전히 확실히 차단",
    {"session_id": "s15", "identity": "attacker@test.com", "device_fingerprint_mismatch": True,
     "security_mfa_passed": True},
    expect_allow=False, expect_action="block"
)

# --- [v11] RESOURCE_THRESHOLDS 테스트 ---
# [v12] 등급: top_secret=20(/admin)  confidential=40(/hr,/dev)  internal=60(/marketing,/)
# (등급을 못 찾으면 DEFAULT_THRESHOLD=40)

run_case(
    "[RESOURCE_THRESHOLDS] resource_path 없음 -> 기존과 동일하게 DEFAULT_THRESHOLD(40) 적용 (회귀 확인)",
    {"session_id": "r1", "identity": "hana@test.com", "unknown_location": True},
    expect_allow=True, expect_action="allow"
)
print(">>> 위 s7 케이스(정확히 임계값과 동일)와 동일한 결과여야 정상 - resource_path 없어도 기존 동작 안 깨짐")
print()

run_case(
    "[RESOURCE_THRESHOLDS] 목록에 없는 resource_path -> DEFAULT_THRESHOLD(40)로 안전 처리",
    {"session_id": "r2", "identity": "hana@test.com", "unknown_location": True, "resource_path": "unknown.xmcda.store/"},
    expect_allow=True, expect_action="allow"
)

run_case(
    "[RESOURCE_THRESHOLDS] /admin(임계값20): unknown_location(40점) 단독 -> 기본(40)이면 통과지만 admin은 Step-up",
    {"session_id": "r3", "identity": "hana@test.com", "unknown_location": True, "resource_path": "admin.xmcda.store/"},
    expect_allow=False, expect_action="step_up_mfa_required"
)
print(">>> 같은 신호(unknown_location)라도 자원이 /admin이면 위 r1과 다르게 걸려야 정상")
print()

run_case(
    "[RESOURCE_THRESHOLDS] /admin 하위 경로(/admin/users)도 접두어 매칭으로 동일 임계값(20) 적용",
    {"session_id": "r4", "identity": "hana@test.com", "unknown_location": True, "resource_path": "admin.xmcda.store/users"},
    expect_allow=False, expect_action="step_up_mfa_required"
)

run_case(
    "[RESOURCE_THRESHOLDS] /dev(기밀, 임계값40): night_access+unknown_location(60점) -> 경계구간이라 Step-up",
    {"session_id": "r5", "identity": "hana@test.com", "night_access": True, "unknown_location": True, "resource_path": "dev.xmcda.store/"},
    expect_allow=False, expect_action="step_up_mfa_required"
)
print(">>> [v12] /dev가 60->40으로 바뀌어 s8과 같은 결과여야 정상 (v11까지는 통과였음)")
print()

run_case(
    "[v12] /hr(기밀, 임계값40): 같은 신호 조합 -> /dev와 동일하게 Step-up",
    {"session_id": "r5b", "identity": "hana@test.com", "night_access": True, "unknown_location": True, "resource_path": "hr.xmcda.store/"},
    expect_allow=False, expect_action="step_up_mfa_required"
)

run_case(
    "[v12] /marketing(내부, 임계값60): night_access+unknown_location(60점) -> 통과",
    {"session_id": "r5c", "identity": "hana@test.com", "night_access": True, "unknown_location": True, "resource_path": "marketing.xmcda.store/"},
    expect_allow=True, expect_action="allow"
)
print(">>> 내부 등급만 가장 관대해야 정상")
print()

run_case(
    "[RESOURCE_THRESHOLDS] /admin(임계값20)에 쿼리스트링이 붙어도 정상 매칭",
    {"session_id": "r6", "identity": "hana@test.com", "unknown_location": True, "resource_path": "admin.xmcda.store/?type=admin_logs"},
    expect_allow=False, expect_action="step_up_mfa_required"
)

run_case(
    "[RESOURCE_THRESHOLDS] security 위험(waf_sqli)은 resource_path와 무관하게 여전히 MFA 전까지 무조건 차단",
    {"session_id": "r7", "identity": "attacker@test.com", "waf_sqli": True, "resource_path": "dev.xmcda.store/"},
    expect_allow=False, expect_action="block_until_mfa"
)
print(">>> /dev는 임계값이 관대해도, security 신호는 §4 로직이 threshold보다 먼저 적용되어야 정상")
print()

# --- [step-up 재인증] mfa_verified 기록 관련 테스트 ---

mock_table.reset_mock()
mock_mfa_table.reset_mock()
_mfa_reauth_result = json.loads(engine.lambda_handler(
    {"headers": TEST_HEADERS, "body": json.dumps({"identity": "hana@test.com", "mfa_reauth": True})}, None
)["body"])
print(f"[{'PASS' if _mfa_reauth_result.get('recorded') is True else 'FAIL'}] [step-up] mfa_reauth 응답에 recorded:true 포함")
print(f"    -> {_mfa_reauth_result}")
print(f"    -> mfa_verified put_item 호출됨: {mock_mfa_table.put_item.called}")
print()

run_case(
    "[step-up] 경계구간인데 mfa_verified 기록 없음 -> 기존과 동일하게 step_up_mfa_required (회귀 확인)",
    {"session_id": "m1", "identity": "hana@test.com", "night_access": True, "unknown_location": True},
    expect_allow=False, expect_action="step_up_mfa_required"
)
print(">>> 위 s8 케이스와 동일한 결과여야 정상 - mfa_verified 기록이 없으면 기존 동작 그대로")
print()

run_case(
    "[step-up] 경계구간 + 5분 전 mfa_verified 기록(유효) -> step_up_mfa_verified로 통과",
    {"session_id": "m2", "identity": "hana@test.com", "night_access": True, "unknown_location": True},
    expect_allow=True, expect_action="step_up_mfa_verified",
    mfa_record={"identity": "hana@test.com", "verified_at": now - 300, "expires_at": now + 300}
)
print(">>> reasons에 recent_mfa_reauth_verified가 있어야 정상")
print()

run_case(
    "[step-up] 경계구간 + 15분 전 mfa_verified 기록(10분 초과, 만료) -> 다시 step_up_mfa_required",
    {"session_id": "m3", "identity": "hana@test.com", "night_access": True, "unknown_location": True},
    expect_allow=False, expect_action="step_up_mfa_required",
    mfa_record={"identity": "hana@test.com", "verified_at": now - 900, "expires_at": now - 300}
)
print(">>> expires_at이 지난 기록은 무시되고 다시 막혀야 정상")
print()

run_case(
    "[step-up] 차단 구간(임계값+마진 초과)은 mfa_verified 기록이 있어도 그대로 차단",
    {"session_id": "m4", "identity": "attacker@test.com", "unknown_location": True, "waf_sqli": True},
    expect_allow=False, expect_action="block_until_mfa",
    mfa_record={"identity": "attacker@test.com", "verified_at": now - 60, "expires_at": now + 540}
)
print(">>> step-up 재인증은 경계구간에만 적용됨 - security 신호로 인한 차단은 무관하게 그대로여야 정상")
print()


# --- [v12] 등급(tier) 표 검증 ---
def check_tier(name, path, expect_tier, expect_threshold):
    tier = engine.get_resource_tier(path)
    th = engine.get_resource_threshold(path)
    ok = (tier == expect_tier and th == expect_threshold)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    print(f"    -> path={path} tier={tier} threshold={th}")
    if not ok:
        print(f"    !! 기대값: tier={expect_tier}, threshold={expect_threshold}")
    print()

check_tier("[v12] /admin -> top_secret(20)", "admin.xmcda.store/", "top_secret", 20)
check_tier("[v12] /admin?type=x -> top_secret(20)", "admin.xmcda.store/?type=x", "top_secret", 20)
check_tier("[v12] /hr -> confidential(40)", "hr.xmcda.store/", "confidential", 40)
check_tier("[v12] /dev -> confidential(40), /hr과 같은 등급", "dev.xmcda.store/", "confidential", 40)
check_tier("[v12] /dev/sub 접두어 매칭 -> confidential(40)", "dev.xmcda.store/sub", "confidential", 40)
check_tier("[v12] /marketing -> internal(60)", "marketing.xmcda.store/", "internal", 60)
check_tier("[v12] / -> internal(60)", "xmcda.store/", "internal", 60)
check_tier("[v12] 목록에 없는 경로 -> 등급 없음, DEFAULT_THRESHOLD(40)", "unknown.xmcda.store/", None, 40)
check_tier("[v12] resource_path 없음 -> 등급 없음, DEFAULT_THRESHOLD(40)", None, None, 40)
# [서브도메인 분리] 자원 식별자 = 호스트+경로. 키는 호스트, 경로 경계("/")에서만 일치
check_tier("[서브도메인] 호스트 대문자/끝 슬래시 정규화 -> HR.xmcda.store// = confidential", "HR.xmcda.store//", "confidential", 40)
check_tier("[서브도메인] 호스트만(경로 없음)도 매칭 -> admin.xmcda.store", "admin.xmcda.store", "top_secret", 20)
check_tier("[서브도메인] 비슷한 다른 호스트(dev.xmcda.store.evil.com)는 불일치", "dev.xmcda.store.evil.com/", None, 40)
check_tier("[서브도메인] 접두어만 같은 호스트(devx.xmcda.store)는 불일치", "devx.xmcda.store/", None, 40)
check_tier("[서브도메인] 옛 형식(/admin)은 등급 없음 -> DEFAULT(40)", "/admin", None, 40)
check_tier("[서브도메인] 로그인 서버 평가(auth.xmcda.store/authorize) -> 등급 없음, DEFAULT(40)", "auth.xmcda.store/authorize", None, 40)

_r = json.loads(engine.lambda_handler(
    {"headers": TEST_HEADERS, "body": json.dumps({"session_id": "t1", "identity": "hana@test.com", "resource_path": "dev.xmcda.store/"})}, None
)["body"])
print(f"[{'PASS' if _r.get('resource_tier') == 'confidential' else 'FAIL'}] [v12] 응답에 resource_tier 포함")
print(f"    -> resource_tier={_r.get('resource_tier')}")
print()

mock_table.reset_mock()
engine.lambda_handler(
    {"headers": TEST_HEADERS, "body": json.dumps({"session_id": "t2", "identity": "hana@test.com", "source": "B"})}, None
)
_logged = mock_table.put_item.call_args.kwargs["Item"]
print(f"[{'PASS' if _logged.get('source') == 'B' else 'FAIL'}] [v12] source=B 가 DynamoDB 로그에 기록됨")
engine.lambda_handler(
    {"headers": TEST_HEADERS, "body": json.dumps({"session_id": "t3", "identity": "hana@test.com"})}, None
)
_logged_default = mock_table.put_item.call_args.kwargs["Item"]
print(f"[{'PASS' if _logged_default.get('source') == 'A' else 'FAIL'}] [v12] source 미지정 시 기본값 A")
print()


def run_auth_case(name, headers):
    mock_table.reset_mock()
    result_raw = engine.lambda_handler(
        {"headers": headers, "body": json.dumps({"session_id": "auth1", "identity": "x@test.com"})},
        None
    )
    status = "PASS" if result_raw["statusCode"] == 401 else "FAIL"
    print(f"[{status}] {name}")
    print(f"    -> statusCode={result_raw['statusCode']}")
    if status == "FAIL":
        print("    !! 기대값: statusCode=401")
    print()

run_auth_case("헤더 없이 호출 -> 401 unauthorized", {})
run_auth_case("틀린 비밀키로 호출 -> 401 unauthorized", {"x-evaluate-secret": "wrong-value"})


# ==========================================================================
# [캐시 유효기간] Lambda가 정해서 응답(cache_ttl_seconds)으로 돌려준다.
# 호출한 쪽(zt_risk.py)은 이 값을 그대로 따르므로, 등급표/야간 경계/MFA 만료 계산은 여기서만 검증한다.
# ==========================================================================
import io
import contextlib
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

_KST = timezone(timedelta(hours=9))

def _kst(h, m=0, s=0):
    return datetime(2026, 10, 6, h, m, s, tzinfo=_KST).timestamp()

def t(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")
    if detail or not cond:
        print(f"    -> {detail}")
    print()

for label, (h, m, s), expect in [
    ("21:58 KST -> 22:00까지 120초", (21, 58, 0), 120),
    ("05:59:30 KST -> 06:00까지 30초", (5, 59, 30), 30),
    ("06:00:00 정각 -> 다음은 22:00 (16시간)", (6, 0, 0), 16 * 3600),
    ("22:00:00 정각 -> 다음은 06:00 (8시간)", (22, 0, 0), 8 * 3600),
    ("14:00 KST -> 22:00까지 8시간", (14, 0, 0), 8 * 3600),
    ("00:00 KST -> 06:00까지 6시간", (0, 0, 0), 6 * 3600),
]:
    got = engine.seconds_until_night_boundary(_kst(h, m, s))
    t(f"[캐시TTL] 야간 경계: {label}", abs(got - expect) < 1, f"got={got}")

noon = _kst(14)
t("[캐시TTL] 기밀(confidential) 허용 -> 90초", engine.compute_cache_ttl("confidential", True, noon) == 90)
t("[캐시TTL] 내부(internal) 허용 -> 300초", engine.compute_cache_ttl("internal", True, noon) == 300)
t("[캐시TTL] 최고기밀(top_secret) -> 0 (캐시 안 함)", engine.compute_cache_ttl("top_secret", True, noon) == 0)
t("[캐시TTL] 등급을 모르는 자원(None) -> 0", engine.compute_cache_ttl(None, True, noon) == 0)
t("[캐시TTL] 허용이 아니면 등급과 무관하게 0", engine.compute_cache_ttl("internal", False, noon) == 0)
t("[캐시TTL] 21:58의 내부 자원 -> 22:00 경계까지 120초로 끊김",
  engine.compute_cache_ttl("internal", True, _kst(21, 58)) == 120, engine.compute_cache_ttl("internal", True, _kst(21, 58)))
t("[캐시TTL] 05:59:30의 기밀 자원 -> 06:00 경계까지 30초로 끊김",
  engine.compute_cache_ttl("confidential", True, _kst(5, 59, 30)) == 30)
t("[캐시TTL] MFA 재인증 기록이 30초 남았으면 기밀 TTL(90)보다 짧은 30초",
  engine.compute_cache_ttl("confidential", True, noon, mfa_expires_at=int(noon) + 30) == 30)
t("[캐시TTL] MFA 기록이 이미 만료됐으면(음수) 0 이하로 내려가지 않음",
  engine.compute_cache_ttl("confidential", True, noon, mfa_expires_at=int(noon) - 5) == 0)

def _call(body, mfa_record=None):
    mock_table.reset_mock()
    mock_mfa_table.reset_mock()
    mock_user_risk.reset_mock()
    mock_user_risk.query.return_value = {"Items": []}
    mock_mfa_table.get_item.return_value = {"Item": mfa_record} if mfa_record else {}
    raw = engine.lambda_handler({"headers": TEST_HEADERS, "body": json.dumps(body)}, None)
    return json.loads(raw["body"])

with patch.object(engine.time, "time", return_value=_kst(14)):
    now14 = int(_kst(14))
    r = _call({"session_id": "c1", "identity": "hana@test.com", "resource_path": "dev.xmcda.store/"})
    t("[캐시TTL] 응답: /dev 허용 -> cache_ttl_seconds=90", r["allow"] and r.get("cache_ttl_seconds") == 90, r.get("cache_ttl_seconds"))
    r = _call({"session_id": "c2", "identity": "hana@test.com", "resource_path": "marketing.xmcda.store/"})
    t("[캐시TTL] 응답: /marketing 허용 -> 300", r.get("cache_ttl_seconds") == 300, r.get("cache_ttl_seconds"))
    r = _call({"session_id": "c3", "identity": "hana@test.com", "resource_path": "admin.xmcda.store/"})
    t("[캐시TTL] 응답: /admin 허용 -> 0 (매 요청 검사)", r["allow"] and r.get("cache_ttl_seconds") == 0, r.get("cache_ttl_seconds"))
    r = _call({"session_id": "c4", "identity": "hana@test.com", "resource_path": "unknown.xmcda.store/"})
    t("[캐시TTL] 응답: 목록에 없는 자원 -> 0", r.get("cache_ttl_seconds") == 0, r.get("cache_ttl_seconds"))
    r = _call({"session_id": "c5", "identity": "x@test.com", "resource_path": "dev.xmcda.store/", "waf_sqli": True})
    t("[캐시TTL] 응답: 차단 -> 0", (not r["allow"]) and r.get("cache_ttl_seconds") == 0, r.get("cache_ttl_seconds"))
    r = _call({"session_id": "c6", "identity": "hana@test.com", "resource_path": "dev.xmcda.store/", "night_access": True, "unknown_location": True})
    t("[캐시TTL] 응답: step-up 필요 -> 0", r["action"] == "step_up_mfa_required" and r.get("cache_ttl_seconds") == 0, r)
    r = _call({"session_id": "c7", "identity": "hana@test.com", "resource_path": "dev.xmcda.store/", "night_access": True, "unknown_location": True},
              mfa_record={"identity": "hana@test.com", "expires_at": now14 + 30})
    t("[캐시TTL] 응답: step-up 재인증 통과 -> MFA 남은 시간(30초)을 넘지 않음",
      r["action"] == "step_up_mfa_verified" and r.get("cache_ttl_seconds") == 30, r)

with patch.object(engine.time, "time", return_value=_kst(21, 58)):
    r = _call({"session_id": "c8", "identity": "hana@test.com", "resource_path": "marketing.xmcda.store/"})
    t("[캐시TTL] 응답: 21:58의 /marketing -> 야간 경계(120초)로 끊김", r.get("cache_ttl_seconds") == 120, r.get("cache_ttl_seconds"))

# 비밀키 유출 방지: event 원문을 로그로 찍지 않는다 (예전에는 print(event)로 x-evaluate-secret이 CloudWatch에 남았음)
_buf = io.StringIO()
with contextlib.redirect_stdout(_buf):
    engine.lambda_handler({"headers": TEST_HEADERS, "body": json.dumps({"session_id": "leak", "identity": "hana@test.com"})}, None)
    engine.lambda_handler({"headers": TEST_HEADERS, "body": json.dumps({"session_id": "leak2", "identity": "hana@test.com", "mfa_reauth": True})}, None)
    engine.lambda_handler({"headers": {"x-evaluate-secret": "wrong-value-xyz"}, "body": "{}"}, None)
t("[보안] 정상 호출 로그에 공유비밀키가 찍히지 않음", "test-secret-local-only" not in _buf.getvalue(), _buf.getvalue()[:200])
t("[보안] 틀린 비밀키로 거부된 호출의 로그에도 입력값이 찍히지 않음", "wrong-value-xyz" not in _buf.getvalue())


# ==========================================================================
# [User Risk] 해제 불가 신호를 인증된 신원에 저장하고, 이후 판단에 반영하고, 조회 실패는 차단
# ==========================================================================
def _flag(identity, signal, status="active"):
    return {"identity": identity, "signal": signal, "status": status, "set_at": now}

t("[UserRisk] STICKY_SIGNALS는 resettable=False인 security 신호 3개",
  sorted(engine.STICKY_SIGNALS) == ["device_fingerprint_mismatch", "threat_intel_match", "waf_sqli"], engine.STICKY_SIGNALS)

# 1) persist_risk=true + 감지 -> 저장
r = _call({"session_id": "u1", "identity": "kim@test.com", "waf_sqli": True, "persist_risk": True, "source": "B"})
calls = mock_user_risk.update_item.call_args_list
t("[UserRisk] persist_risk=true: 감지된 waf_sqli를 user_risk에 active로 저장", len(calls) == 1
  and calls[0].kwargs["Key"] == {"identity": "kim@test.com", "signal": "waf_sqli"}
  and calls[0].kwargs["ExpressionAttributeValues"][":active"] == "active"
  and calls[0].kwargs["ExpressionAttributeValues"][":src"] == "B", calls)
t("[UserRisk] 해제된(released) 항목은 같은 조건식으로 다시 active가 될 수 있음(재감지)",
  "<> :active" in calls[0].kwargs["ConditionExpression"])

# 2) persist_risk 없음 -> 저장 안 함 (로그인 폼 등 인증 전 입력으로 남의 계정을 잠그는 공격 방지)
r = _call({"session_id": "u2", "identity": "victim@test.com", "waf_sqli": True})
t("[UserRisk] persist_risk가 없으면 저장하지 않음(남의 이메일을 적어 잠그는 공격 방지)", mock_user_risk.update_item.call_count == 0)
t("[UserRisk] 저장하지 않아도 그 요청 자체는 차단", (not r["allow"]) and r["action"] == "block_until_mfa", r)

# 3) 저장 대상이 아닌 신호는 저장 안 함
r = _call({"session_id": "u3", "identity": "kim@test.com", "night_access": True, "brute_force": True, "persist_risk": True})
t("[UserRisk] night_access/brute_force 같은 해제 가능 신호는 저장하지 않음", mock_user_risk.update_item.call_count == 0)

# 4) identity 없음/unknown -> 조회·저장 모두 안 함
r = _call({"session_id": "u4", "waf_sqli": True, "persist_risk": True})
t("[UserRisk] identity가 없으면 조회/저장하지 않음", mock_user_risk.query.call_count == 0 and mock_user_risk.update_item.call_count == 0)
r = _call({"session_id": "u4b", "identity": "unknown", "waf_sqli": True, "persist_risk": True})
t("[UserRisk] identity가 'unknown'이어도 저장하지 않음", mock_user_risk.update_item.call_count == 0)

# 5) 이미 걸려 있는 신호 -> 다른 신호 없이도 차단, 이유에 표시
def _call_flagged(body, items):
    mock_table.reset_mock(); mock_mfa_table.reset_mock(); mock_user_risk.reset_mock()
    mock_mfa_table.get_item.return_value = {}
    mock_user_risk.query.return_value = {"Items": items}
    raw = engine.lambda_handler({"headers": TEST_HEADERS, "body": json.dumps(body)}, None)
    return raw["statusCode"], json.loads(raw["body"])

code, r = _call_flagged({"session_id": "u5", "identity": "kim@test.com", "resource_path": "dev.xmcda.store/"},
                        [_flag("kim@test.com", "threat_intel_match")])
t("[UserRisk] active 신호가 있으면 아무 신호 없이 와도 차단", code == 200 and (not r["allow"]) and r["action"] == "block_until_mfa", r)
t("[UserRisk] 차단 이유에 user_risk_active가 표시됨", "user_risk_active:threat_intel_match" in r["reasons"], r["reasons"])
t("[UserRisk] 차단이면 캐시 유효시간 0", r.get("cache_ttl_seconds") == 0)

code, r = _call_flagged({"session_id": "u6", "identity": "kim@test.com", "resource_path": "dev.xmcda.store/", "security_mfa_passed": True},
                        [_flag("kim@test.com", "waf_sqli")])
t("[UserRisk] MFA를 통과해도 걸린 신호는 풀리지 않음(resettable=False)", not r["allow"], r)

code, r = _call_flagged({"session_id": "u7", "identity": "kim@test.com", "resource_path": "dev.xmcda.store/"},
                        [_flag("kim@test.com", "waf_sqli", status="released")])
t("[UserRisk] released(해제된) 항목은 판단에 반영되지 않음", code == 200 and r["allow"], r)

code, r = _call_flagged({"session_id": "u8", "identity": "kim@test.com", "resource_path": "dev.xmcda.store/"},
                        [_flag("kim@test.com", "night_access")])
t("[UserRisk] sticky 대상이 아닌 신호 이름이 저장돼 있어도 무시", code == 200 and r["allow"], r)

# 6) 같은 신호가 이미 active인 상태에서 또 감지 -> 새로 만들지 않고 last_seen만 갱신
class _CondFail(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"}}
mock_user_risk.reset_mock()
mock_user_risk.query.return_value = {"Items": [_flag("kim@test.com", "waf_sqli")]}
mock_user_risk.update_item.side_effect = [_CondFail("x"), {}]
mock_mfa_table.get_item.return_value = {}
engine.lambda_handler({"headers": TEST_HEADERS, "body": json.dumps(
    {"session_id": "u9", "identity": "kim@test.com", "waf_sqli": True, "persist_risk": True})}, None)
t("[UserRisk] 이미 active인 신호가 또 감지되면 last_seen만 갱신",
  mock_user_risk.update_item.call_count == 2 and "last_seen" in mock_user_risk.update_item.call_args_list[1].kwargs["UpdateExpression"]
  and "#st" not in mock_user_risk.update_item.call_args_list[1].kwargs["UpdateExpression"])
mock_user_risk.update_item.side_effect = None

# 7) 조회 실패 -> fail-closed (500, 호출자는 차단 처리)
mock_table.reset_mock()
mock_user_risk.reset_mock()
mock_user_risk.query.side_effect = RuntimeError("dynamodb down")
_b = io.StringIO()
with contextlib.redirect_stdout(_b):
    raw = engine.lambda_handler({"headers": TEST_HEADERS, "body": json.dumps(
        {"session_id": "u10", "identity": "kim@test.com", "resource_path": "dev.xmcda.store/"})}, None)
t("[UserRisk] 조회 실패는 통과시키지 않고 500(fail-closed)", raw["statusCode"] == 500 and json.loads(raw["body"]).get("error") == "user_risk_unavailable", raw)
t("[UserRisk] 조회 실패 시 판정 로그(put_item)도 남기지 않음(판단하지 않았으므로)", mock_table.put_item.call_count == 0)
mock_user_risk.query.side_effect = None

# 8) 쿼리가 key 기반(Query)이고 예약어를 이름 치환으로 쓴다
mock_user_risk.reset_mock(); mock_user_risk.query.return_value = {"Items": []}
engine.lambda_handler({"headers": TEST_HEADERS, "body": json.dumps({"session_id": "u11", "identity": "kim@test.com"})}, None)
qk = mock_user_risk.query.call_args.kwargs
t("[UserRisk] Scan이 아니라 identity 키로 Query하고, 예약어는 이름 치환 사용",
  qk.get("KeyConditionExpression") == "#i = :i" and qk["ExpressionAttributeNames"] == {"#i": "identity"}
  and mock_user_risk.scan.call_count == 0)

# ==========================================================================
# [기기 신뢰] WARP 기기 검사 결과(devicePosture)와 기기 주인(Cloudflare API) -> 신호
#   관리 안 됨/남의 기기 45점, 검사 실패 25점. 기기 신호로 경계구간에 들어오면 재인증 대신 차단(block_device)
# ==========================================================================
from unittest.mock import patch
print()
FW_OK = [{"type": "firewall", "rule": "ZT - Windows Firewall On", "success": True},
         {"type": "warp", "rule": "WARP", "success": True}]
FW_FAIL = [{"type": "firewall", "rule": "ZT - Windows Firewall On", "success": False}]
DEV_ID = "01a16dae-7040-1d67-aca9-b05dc71233c1"
engine.CF_ACCOUNT_ID, engine.CF_DEVICE_API_TOKEN = "acct", "tok"
api_calls = []

class _Resp:
    def __init__(self, email): self.email = email
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self):
        return json.dumps({"success": True, "result": {"id": DEV_ID, "last_seen_user": {"email": self.email}}}).encode()

def owner_is(email):
    def fake(req, timeout=None):
        api_calls.append((req.full_url, req.headers.get("Authorization"), timeout))
        return _Resp(email)
    return fake

def dev_case(name, extra, owner, expect_allow, expect_action, resource="dev.xmcda.store/", identity="kim@xmcda.store"):
    api_calls.clear()
    with patch.object(engine.urllib.request, "urlopen", owner_is(owner)):
        run_case(name, {"session_id": "d", "identity": identity, "resource_path": resource, **extra},
                 expect_allow=expect_allow, expect_action=expect_action)

dev_case("[기기] 등록 기기 + 방화벽 통과 + 본인 기기 -> 기밀(dev) 통과",
         {"device_context": True, "device_id": DEV_ID, "device_posture": FW_OK}, "kim@xmcda.store", True, "allow")
t("[기기] 기기 주인 조회: physical-devices API, Bearer 토큰, 짧은 timeout",
  api_calls and api_calls[0][0].endswith(f"/accounts/acct/devices/physical-devices/{DEV_ID}")
  and api_calls[0][1] == "Bearer tok" and api_calls[0][2] == 2, api_calls)
dev_case("[기기] WARP 없는 기기(device_id 없음) -> 기밀(dev)은 재인증 없이 차단(block_device)",
         {"device_context": True, "device_id": None, "device_posture": []}, None, False, "block_device")
t("[기기] 기기 정보가 없으면 주인 조회 API를 부르지 않음", not api_calls, api_calls)
dev_case("[기기] WARP 없는 기기 -> 내부(포털)는 통과",
         {"device_context": True}, None, True, "allow", resource="xmcda.store/")
dev_case("[기기] WARP 없는 기기 -> 최고기밀(admin)은 차단",
         {"device_context": True}, None, False, "block", resource="admin.xmcda.store/")
dev_case("[기기] 방화벽 꺼짐(25) -> 기밀(dev 40)은 통과",
         {"device_context": True, "device_id": DEV_ID, "device_posture": FW_FAIL}, "kim@xmcda.store", True, "allow")
dev_case("[기기] 방화벽 꺼짐(25) -> 최고기밀(admin 20)은 경계구간이지만 기기 신호라 차단(block_device)",
         {"device_context": True, "device_id": DEV_ID, "device_posture": FW_FAIL}, "kim@xmcda.store", False, "block_device",
         resource="admin.xmcda.store/")
dev_case("[기기] 방화벽 꺼짐(25) -> 포털(60) 통과",
         {"device_context": True, "device_id": DEV_ID, "device_posture": FW_FAIL}, "kim@xmcda.store", True, "allow",
         resource="xmcda.store/")
dev_case("[기기] 필수 검사 결과 없음(만료 등) -> 검사 실패로 처리(admin 차단)",
         {"device_context": True, "device_id": DEV_ID, "device_posture": [{"type": "warp", "rule": "WARP", "success": True}]},
         "kim@xmcda.store", False, "block_device", resource="admin.xmcda.store/")
dev_case("[기기] 남의 기기(등록자 admin != 로그인 kim) -> 기밀(dev) 재인증 없이 차단(block_device)",
         {"device_context": True, "device_id": DEV_ID, "device_posture": FW_OK}, "admin@xmcda.store", False, "block_device")
dev_case("[기기] 기기 주인 비교는 대소문자 무시",
         {"device_context": True, "device_id": DEV_ID, "device_posture": FW_OK}, "KIM@XMCDA.STORE", True, "allow")
dev_case("[기기] 해외(40) + 남의 기기(45) + 조합 규칙(20) = 105 -> 포털(60)에서도 차단",
         {"device_context": True, "device_id": DEV_ID, "device_posture": FW_OK, "geo_country": "US"},
         "admin@xmcda.store", False, "block", resource="xmcda.store/")
mock_mfa_table.get_item.return_value = {"Item": {"identity": "kim@xmcda.store", "expires_at": int(time.time()) + 600}}
api_calls.clear()
_r = json.loads(engine.lambda_handler({"headers": TEST_HEADERS, "body": json.dumps(
    {"session_id": "d2", "identity": "kim@xmcda.store", "resource_path": "dev.xmcda.store/", "device_context": True})}, None)["body"])
t("[기기] 최근 재인증 기록이 있어도 WARP 없는 기기 -> 기밀(dev) 차단(재인증으로 풀리지 않음)",
  _r["allow"] is False and _r["action"] == "block_device" and _r["device_reasons"] == ["device_unmanaged"]
  and _r["cache_ttl_seconds"] == 0, _r)
mock_mfa_table.get_item.return_value = {}

def failing_urlopen(req, timeout=None):
    raise OSError("cloudflare api down")
with patch.object(engine.urllib.request, "urlopen", failing_urlopen):
    run_case("[기기] 주인 조회 실패 -> 주인 신호 없이 판단(조회 장애로 전원 차단 방지), 상태 신호는 정상 판단",
             {"session_id": "d3", "identity": "kim@xmcda.store", "resource_path": "dev.xmcda.store/",
              "device_context": True, "device_id": DEV_ID, "device_posture": FW_OK}, expect_allow=True, expect_action="allow")
for bad in ("../../etc", "01a16dae/../x", "x" * 100):
    api_calls.clear()
    with patch.object(engine.urllib.request, "urlopen", owner_is("admin@xmcda.store")):
        engine.lookup_device_owner(bad)
    t(f"[기기] 이상한 device_id({bad[:15]!r})는 API 주소에 넣지 않음", not api_calls, api_calls)
run_case("[기기] device_context 없는 호출(로그인 서버/웹 서버 앞단)은 기기 신호를 만들지 않음",
         {"session_id": "d4", "identity": "kim@xmcda.store", "resource_path": "dev.xmcda.store/"}, expect_allow=True, expect_action="allow")

# [기기 신호 스위치] report: 로그에만 남기고 점수 반영 안 함 / off: 계산도 안 함 / 알 수 없는 값: enforce
def mode_case(mode, owner):
    engine.DEVICE_SIGNAL_MODE = mode
    api_calls.clear()
    mock_mfa_table.get_item.return_value = {}
    mock_user_risk.query.return_value = {"Items": []}
    with patch.object(engine.urllib.request, "urlopen", owner_is(owner)):
        r = json.loads(engine.lambda_handler({"headers": TEST_HEADERS, "body": json.dumps(
            {"session_id": "m", "identity": "kim@xmcda.store", "resource_path": "admin.xmcda.store/",
             "device_context": True, "device_id": DEV_ID, "device_posture": FW_FAIL})}, None)["body"])
    return r
r = mode_case("report", "admin@xmcda.store")
t("[기기 스위치] report: 방화벽 실패+남의 기기여도 점수 0 -> 최고기밀(admin)도 통과",
  r["allow"] is True and r["score"] == 0, r)
t("[기기 스위치] report: 감지한 신호는 reasons에 report-only로 남음",
  "device_posture_failed (report-only, +0)" in r["reasons"] and "device_owner_mismatch (report-only, +0)" in r["reasons"], r["reasons"])
r = mode_case("off", "admin@xmcda.store")
t("[기기 스위치] off: 기기 신호 없음 + 주인 조회 API 호출 안 함",
  r["allow"] is True and not any("device_" in x for x in r["reasons"]) and not api_calls, (r, api_calls))
r = mode_case("enforce", "admin@xmcda.store")
t("[기기 스위치] enforce: 점수 반영 -> 최고기밀(admin) 차단", r["allow"] is False, r)
import os as _os, subprocess as _sp
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_probe = ("import sys; from unittest.mock import MagicMock; sys.modules['boto3']=MagicMock(); "
          "sys.path.insert(0, sys.argv[1]); import risk_score_engine as e; print(e.DEVICE_SIGNAL_MODE)")
for raw, expect in (("REPORT ", "report"), ("off", "off"), ("bogus", "enforce"), (None, "enforce")):
    _env = {k: v for k, v in _os.environ.items() if k != "DEVICE_SIGNAL_MODE"}
    if raw is not None:
        _env["DEVICE_SIGNAL_MODE"] = raw
    _out = _sp.run([sys.executable, "-c", _probe, _HERE], env=_env, capture_output=True, text=True).stdout.strip()
    t(f"[기기 스위치] 환경변수 {raw!r} -> {expect} (엔진을 새로 불러와 확인)", _out == expect, _out)
engine.DEVICE_SIGNAL_MODE = "enforce"

# ==========================================================================
# [마지막 판단] access_decision: 판단할 때마다 사용자+앱별로 저장, /stepup이 조회해 화면을 고른다
# ==========================================================================
print()
def handler(body):
    return json.loads(engine.lambda_handler({"headers": TEST_HEADERS, "body": json.dumps(body)}, None)["body"])

mock_decision.reset_mock(); mock_mfa_table.get_item.return_value = {}
with patch.object(engine.urllib.request, "urlopen", owner_is("admin@xmcda.store")):
    _r = handler({"session_id": "x1", "identity": "Kim@Xmcda.Store", "resource_path": "DEV.xmcda.store/a?x=1",
                  "device_context": True, "device_id": DEV_ID, "device_posture": FW_OK})
_item = mock_decision.put_item.call_args.kwargs["Item"] if mock_decision.put_item.called else {}
t("[판단 기록] 판단마다 저장: 신원 소문자, 앱 호스트만, 결과, 기기 사유, 10분 만료",
  _item.get("identity") == "kim@xmcda.store" and _item.get("resource_host") == "dev.xmcda.store"
  and _item.get("action") == "block_device" and _item.get("device_reasons") == ["device_owner_mismatch"]
  and _item.get("expires_at") - _item.get("decided_at") == 600, _item)
t("[판단 기록] 응답에도 device_reasons 포함", _r.get("device_reasons") == ["device_owner_mismatch"], _r)

mock_decision.reset_mock()
handler({"session_id": "x2", "identity": "kim@xmcda.store", "resource_path": "auth.xmcda.store/authorize", "source": "login"})
t("[판단 기록] 로그인 서버 자체 평가(source=login)는 저장하지 않음", not mock_decision.put_item.called)
handler({"session_id": "x3", "identity": "kim@xmcda.store", "resource_path": "dev.xmcda.store/", "source": "B"})
t("[판단 기록] 웹 서버 앞단(B) 평가도 저장(/stepup이 B의 재인증 요청도 구분)",
  mock_decision.put_item.called and mock_decision.put_item.call_args.kwargs["Item"]["action"] == "allow")
mock_decision.reset_mock()
handler({"session_id": "x4", "resource_path": "dev.xmcda.store/"})
t("[판단 기록] 신원이 없으면 저장하지 않음", not mock_decision.put_item.called)
mock_decision.put_item.side_effect = Exception("ddb down")
_r = handler({"session_id": "x5", "identity": "kim@xmcda.store", "resource_path": "dev.xmcda.store/"})
t("[판단 기록] 저장 실패해도 판단 결과는 그대로", _r["allow"] is True and _r["action"] == "allow", _r)
mock_decision.put_item.side_effect = None

# 기기 신호가 없는 경계구간은 기존처럼 재인증
run_case("[기기 규칙] 기기 신호 없이 해외(40)만 -> 포털(60)은 통과, 규칙 영향 없음",
         {"session_id": "x6", "identity": "kim@xmcda.store", "resource_path": "xmcda.store/", "geo_country": "US"},
         expect_allow=True, expect_action="allow")
run_case("[기기 규칙] 기기 신호 없이 해외(40) -> 관리자(20) 경계구간은 기존처럼 재인증(규칙은 기기 신호에만)",
         {"session_id": "x7", "identity": "kim@xmcda.store", "resource_path": "admin.xmcda.store/",
          "geo_country": "US"}, expect_allow=False, expect_action="step_up_mfa_required")
with patch.object(engine.urllib.request, "urlopen", owner_is("admin@xmcda.store")):
    _r = handler({"session_id": "x8", "identity": "kim@xmcda.store", "resource_path": "xmcda.store/", "geo_country": "US",
                  "device_context": True, "device_id": DEV_ID, "device_posture": FW_OK})
t("[기기 규칙] 경계구간을 넘는 차단(105)은 action=block 그대로, 기기 사유는 같이 전달(화면에 기기 안내)",
  _r["action"] == "block" and _r["device_reasons"] == ["device_owner_mismatch"], _r)
engine.DEVICE_SIGNAL_MODE = "report"
_r = handler({"session_id": "x9", "identity": "kim@xmcda.store", "resource_path": "dev.xmcda.store/", "device_context": True})
t("[기기 규칙] report 모드에서는 기기 차단 규칙도 적용 안 됨(점수 0, 통과)",
  _r["allow"] is True and _r["device_reasons"] == [], _r)
engine.DEVICE_SIGNAL_MODE = "enforce"

# 조회(decision_lookup)
now_ = int(time.time())
mock_decision.reset_mock()
mock_decision.get_item.return_value = {"Item": {"identity": "kim@xmcda.store", "resource_host": "dev.xmcda.store",
                                                "action": "block_device", "device_reasons": ["device_unmanaged", "evil"],
                                                "expires_at": now_ + 300}}
_r = handler({"decision_lookup": True, "identity": "KIM@xmcda.store", "resource_host": "Dev.Xmcda.Store"})
t("[판단 조회] 저장된 판단을 돌려줌(키는 소문자 신원+호스트, 모르는 사유 이름은 버림)",
  _r == {"found": True, "action": "block_device", "device_reasons": ["device_unmanaged"]}
  and mock_decision.get_item.call_args.kwargs["Key"] == {"identity": "kim@xmcda.store", "resource_host": "dev.xmcda.store"}, _r)
t("[판단 조회] 점수 계산/판정 로그 없음", not mock_decision.put_item.called)
mock_decision.get_item.return_value = {"Item": {"action": "block", "expires_at": now_ - 1}}
t("[판단 조회] 만료된 기록 -> found=False", handler({"decision_lookup": True, "identity": "k@x", "resource_host": "dev.xmcda.store"}) == {"found": False})
mock_decision.get_item.return_value = {}
t("[판단 조회] 기록 없음 -> found=False", handler({"decision_lookup": True, "identity": "k@x", "resource_host": "dev.xmcda.store"}) == {"found": False})
for bad in ({"identity": "", "resource_host": "dev.xmcda.store"}, {"identity": "k@x"}, {"identity": ["x"], "resource_host": "d"}):
    t(f"[판단 조회] 잘못된 입력 {bad} -> found=False", handler({"decision_lookup": True, **bad}) == {"found": False})
mock_decision.get_item.side_effect = Exception("ddb down")
t("[판단 조회] 조회 실패 -> found=False", handler({"decision_lookup": True, "identity": "k@x", "resource_host": "dev.xmcda.store"}) == {"found": False})
mock_decision.get_item.side_effect = None
_r = engine.lambda_handler({"headers": {"x-evaluate-secret": "wrong"}, "body": json.dumps({"decision_lookup": True, "identity": "k@x", "resource_host": "d"})}, None)
t("[판단 조회] 공유 비밀키가 틀리면 401(조회도 같은 인증)", _r["statusCode"] == 401, _r)

# ==========================================================================
# [기기 순찰] 사용 중 기기만 1분마다 Fleet Status 조회 -> 정상에서 나쁨으로 바뀌면 그 기기로 들어온 사용자 세션 끊기
# ==========================================================================
print()
import urllib.error, io
t("[순찰] 상태 정보 없음 -> no_data", engine.classify_fleet_status({}) == "no_data" and engine.classify_fleet_status(None) == "no_data")
t("[순찰] WARP 연결 끊김 -> disconnected", engine.classify_fleet_status({"status": "disconnected", "platform": "windows", "firewallEnabled": True}) == "disconnected")
t("[순찰] Windows인데 firewallEnabled 없음(꺼지면 빠짐, 실측) -> firewall_off",
  engine.classify_fleet_status({"status": "connected", "platform": "windows"}) == "firewall_off")
t("[순찰] Windows + 연결 + 방화벽 True -> 정상", engine.classify_fleet_status({"status": "connected", "platform": "windows", "firewallEnabled": True}) is None)
t("[순찰] Windows가 아니면 방화벽 항목은 보지 않음(방화벽 검사 규칙이 Windows 전용)",
  engine.classify_fleet_status({"status": "connected", "platform": "mac"}) is None)

class _J:
    def __init__(self, obj): self.obj = obj
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self): return json.dumps(self.obj).encode()

def router(fleet, revoke_ok=True):
    calls = []
    def fake(req, timeout=None):
        url = req.full_url
        calls.append((req.get_method(), url, req.headers.get("Authorization"), req.data))
        if "/fleet-status/live" in url:
            dev = url.split("/dex/devices/")[1].split("/")[0]
            v = fleet.get(dev)
            if isinstance(v, int):
                raise urllib.error.HTTPError(url, v, "x", {}, io.BytesIO(b""))
            return _J({"success": True, "result": v})
        if url.endswith("/access/organizations/revoke_user"):
            return _J({"success": revoke_ok, "result": revoke_ok})
        raise AssertionError(url)
    return fake, calls

D1 = "11111111-2222-3333-4444-555555555555"
OK = {"status": "connected", "platform": "windows", "firewallEnabled": True}
FW_OFF = {"status": "connected", "platform": "windows"}
NOW = 1_800_000_000
engine.CF_ACCESS_REVOKE_TOKEN = "revoke-tok"

def rec(identity="kim@xmcda.store", device=D1, **kw):
    return {"device_id": device, "identity": identity, "active_until": NOW + 600, **kw}

def sweep(records, fleet, scan_error=None, **kw):
    mock_device_state.reset_mock(); mock_table.reset_mock()
    if scan_error:
        mock_device_state.scan.side_effect = scan_error
    else:
        mock_device_state.scan.side_effect = None
        mock_device_state.scan.return_value = {"Items": records}
    fake, calls = router(fleet, **kw)
    with patch.object(engine.urllib.request, "urlopen", fake):
        summary = engine.device_sweep(now=NOW)
    ups = [c.kwargs for c in mock_device_state.update_item.call_args_list]
    logs = [c.kwargs["Item"] for c in mock_table.put_item.call_args_list]
    return summary, calls, ups, logs

revokes = lambda calls: [c for c in calls if c[1].endswith("revoke_user")]
vals = lambda u: u["ExpressionAttributeValues"]

summary, calls, ups, logs = sweep([rec()], {D1: FW_OFF})
sk = mock_device_state.scan.call_args.kwargs
t("[순찰] 대상은 '사용 중' 기록만(active_until > 지금), Cloudflare 기기 목록은 조회하지 않음",
  sk["FilterExpression"] == "#a > :n" and sk["ExpressionAttributeValues"] == {":n": NOW}
  and not any("physical-devices" in c[1] for c in calls), (sk, calls))
t("[순찰] 기기 상태 조회: Fleet Status(최근 10분), 읽기 토큰",
  calls[0][1] == f"https://api.cloudflare.com/client/v4/accounts/acct/dex/devices/{D1}/fleet-status/live?since_minutes=10"
  and calls[0][2] == "Bearer tok", calls[0])
t("[순찰] 정상(기록 없음) -> 방화벽 꺼짐: 그 기기로 들어온 사용자 세션 끊기 1회(POST, 끊기 전용 토큰)",
  len(revokes(calls)) == 1 and revokes(calls)[0][0] == "POST" and revokes(calls)[0][2] == "Bearer revoke-tok"
  and json.loads(revokes(calls)[0][3]) == {"email": "kim@xmcda.store"} and summary["revoked"] == ["kim@xmcda.store"], (calls, summary))
t("[순찰] 순찰 결과만 갱신(UpdateItem, active_until은 건드리지 않음): 나쁨/firewall_off/끊음/시각",
  ups and ups[0]["Key"] == {"device_id": D1, "identity": "kim@xmcda.store"}
  and vals(ups[0]) == {":s": "bad", ":r": "firewall_off", ":c": NOW, ":v": True}
  and "active_until" not in ups[0]["ExpressionAttributeNames"].values(), ups)
t("[순찰] 판정 로그에 남김(source=sweep, action=device_session_revoked)",
  logs and logs[0]["action"] == "device_session_revoked" and logs[0]["source"] == "sweep"
  and logs[0]["reasons"] == ["device_sweep:firewall_off"] and logs[0]["identity"] == "kim@xmcda.store", logs)

summary, calls, ups, logs = sweep([rec("a@x"), rec("b@x")], {D1: FW_OFF})
t("[순찰] 한 기기를 두 사람이 쓰면: 상태 조회 1번, 두 사람 모두 끊기",
  len([c for c in calls if "fleet-status" in c[1]]) == 1 and sorted(summary["revoked"]) == ["a@x", "b@x"], calls)
summary, calls, ups, logs = sweep([rec(sweep_state="bad", reason="firewall_off", revoked=True)], {D1: FW_OFF})
t("[순찰] 이미 끊은 나쁜 상태가 계속되면 다시 끊지 않음(포털은 계속 쓸 수 있게)",
  not revokes(calls) and vals(ups[0])[":v"] is True and not logs, (calls, ups))
summary, calls, ups, logs = sweep([rec(sweep_state="bad", reason="firewall_off", revoked=False)], {D1: FW_OFF})
t("[순찰] 지난번 끊기에 실패했으면 이번에 다시 끊음", len(revokes(calls)) == 1, calls)
summary, calls, ups, logs = sweep([rec(sweep_state="bad", reason="firewall_off", revoked=True)], {D1: OK})
t("[순찰] 나쁨 -> 정상으로 돌아오면 끊지 않고 정상으로, 끊은 기록 초기화(다시 나빠지면 또 끊음)",
  not revokes(calls) and vals(ups[0])[":s"] == "ok" and vals(ups[0])[":v"] is False, ups)
summary, calls, ups, logs = sweep([rec()], {D1: OK})
t("[순찰] 정상 -> 정상: 끊지 않음", not revokes(calls) and vals(ups[0])[":s"] == "ok", ups)
summary, calls, ups, logs = sweep([rec()], {D1: 404})
t("[순찰] 사용 중인데 상태 정보 없음(404, WARP 끄기/숨김) -> 나쁨(no_data)으로 끊음",
  vals(ups[0])[":r"] == "no_data" and len(revokes(calls)) == 1, ups)
for code in (429, 500):
    summary, calls, ups, logs = sweep([rec()], {D1: code})
    t(f"[순찰] 상태 API 오류({code}) -> '모름': 끊지 않고 상태도 바꾸지 않음",
      not revokes(calls) and not ups and summary["unknown"] == 1, (calls, ups))
summary, calls, ups, logs = sweep([rec()], {D1: FW_OFF}, scan_error=Exception("ddb down"))
t("[순찰] 사용 중 기록 조회 실패 -> 아무것도 하지 않음", not calls and not ups and summary["unknown"] == -1, calls)
mock_device_state.scan.side_effect = None
summary, calls, ups, logs = sweep([rec(device="../evil"), rec(identity="")], {})
t("[순찰] 이상한 기기 ID, 사용자 없는 기록은 조회하지 않음", not calls, calls)
mock_device_state.reset_mock()
pages = [{"Items": [rec("a@x")], "LastEvaluatedKey": {"k": 1}}, {"Items": [rec("b@x")]}]
mock_device_state.scan.side_effect = pages
fake, calls = router({D1: OK})
with patch.object(engine.urllib.request, "urlopen", fake):
    summary = engine.device_sweep(now=NOW)
t("[순찰] 기록이 많으면 이어서 읽음(LastEvaluatedKey)",
  summary["active"] == 2 and mock_device_state.scan.call_args_list[1].kwargs.get("ExclusiveStartKey") == {"k": 1}, summary)
mock_device_state.scan.side_effect = None
summary, calls, ups, logs = sweep([rec()], {D1: FW_OFF}, revoke_ok=False)
t("[순찰] 끊기 실패 -> revoked=False로 기록(다음 순찰에서 재시도), action=device_session_revoke_failed",
  vals(ups[0])[":v"] is False and logs[0]["action"] == "device_session_revoke_failed", (ups, logs))
engine.CF_ACCESS_REVOKE_TOKEN = ""
summary, calls, ups, logs = sweep([rec()], {D1: FW_OFF})
t("[순찰] 끊기 토큰이 없으면 끊기 요청을 안 보냄(상태만 기록)", not revokes(calls) and vals(ups[0])[":v"] is False, calls)
engine.CF_ACCESS_REVOKE_TOKEN = "revoke-tok"
engine.DEVICE_SIGNAL_MODE = "report"
summary, calls, ups, logs = sweep([rec()], {D1: FW_OFF})
t("[순찰] report 모드: 끊지 않고 '끊었을 것'만 한 번 기록",
  not revokes(calls) and logs[0]["action"] == "device_session_revoke_report_only" and vals(ups[0])[":v"] is True
  and summary["revoked"] == [], (calls, logs))
engine.DEVICE_SIGNAL_MODE = "off"
summary, calls, ups, logs = sweep([rec()], {D1: FW_OFF})
t("[순찰] off 모드: 조회도 안 함", not calls and not mock_device_state.scan.called, calls)
engine.DEVICE_SIGNAL_MODE = "enforce"

# 정문 판단 때 사용 중 기록 + 순찰 결과 반영
mock_device_state.reset_mock()
mock_device_state.query.return_value = {"Items": []}
with patch.object(engine.urllib.request, "urlopen", owner_is("kim@xmcda.store")):
    run_case("[사용 중 기록] 정문 판단(기기 정보 있음) 때 기록",
             {"session_id": "a1", "identity": "Kim@Xmcda.Store", "resource_path": "dev.xmcda.store/",
              "device_context": True, "device_id": DEV_ID, "device_posture": FW_OK}, expect_allow=True)
_u = mock_device_state.update_item.call_args.kwargs if mock_device_state.update_item.called else {}
t("[사용 중 기록] (기기, 사용자 소문자) 키로 active_until=지금+30분만 갱신(순찰 결과는 건드리지 않음)",
  _u.get("Key") == {"device_id": DEV_ID, "identity": "kim@xmcda.store"}
  and set(_u["ExpressionAttributeNames"].values()) == {"active_until", "expires_at"}
  and _u["ExpressionAttributeValues"][":a"] - int(time.time()) in range(1795, 1801), _u)
mock_device_state.reset_mock()
run_case("[사용 중 기록] 기기 정보 없는 판단(웹 서버 B, 로그인 서버)은 기록 안 함",
         {"session_id": "a2", "identity": "kim@xmcda.store", "resource_path": "dev.xmcda.store/", "source": "B"})
t("[사용 중 기록] B 판단은 device_state를 쓰지 않음", not mock_device_state.update_item.called)
run_case("[사용 중 기록] WARP 없는 기기(device_id 없음)는 기록 안 함",
         {"session_id": "a3", "identity": "kim@xmcda.store", "resource_path": "xmcda.store/", "device_context": True})
t("[사용 중 기록] device_id 없으면 기록 없음", not mock_device_state.update_item.called)

now_ = int(time.time())
def q(items):
    mock_device_state.query.side_effect = None
    mock_device_state.query.return_value = {"Items": items}
q([{"device_id": DEV_ID, "identity": "a", "sweep_state": "bad", "reason": "firewall_off", "checked_at": now_ - 60}])
t("[순찰 반영] 최근 나쁨(firewall_off) -> device_posture_failed", engine.sweep_signal_for(DEV_ID) == "device_posture_failed")
t("[순찰 반영] 기기 ID로 Query(이름 치환)",
  mock_device_state.query.call_args.kwargs["KeyConditionExpression"] == "#d = :d"
  and mock_device_state.query.call_args.kwargs["ExpressionAttributeValues"] == {":d": DEV_ID})
q([{"sweep_state": "bad", "reason": "disconnected", "checked_at": now_ - 60}])
t("[순찰 반영] 최근 나쁨(disconnected) -> device_unmanaged", engine.sweep_signal_for(DEV_ID) == "device_unmanaged")
q([{"sweep_state": "bad", "reason": "firewall_off", "checked_at": now_ - 601}])
t("[순찰 반영] 10분 넘은 순찰 결과는 믿지 않음(순찰이 멈췄을 때 옛 결과로 막지 않게)", engine.sweep_signal_for(DEV_ID) is None)
q([{"sweep_state": "bad", "reason": "firewall_off", "checked_at": now_ - 120}, {"sweep_state": "ok", "checked_at": now_ - 30}])
t("[순찰 반영] 여러 사용자 기록이면 가장 최근 순찰 결과(정상)를 따름", engine.sweep_signal_for(DEV_ID) is None)
q([{"identity": "a", "active_until": now_ + 100}])
t("[순찰 반영] 아직 순찰 전(사용 기록만) -> 신호 없음", engine.sweep_signal_for(DEV_ID) is None)
mock_device_state.query.side_effect = Exception("ddb down")
t("[순찰 반영] 조회 실패 -> 신호 없음(Access 검사 결과로만 판단)", engine.sweep_signal_for(DEV_ID) is None)
mock_device_state.query.side_effect = None
t("[순찰 반영] 이상한 기기 ID는 조회하지 않음", engine.sweep_signal_for("../x") is None)

q([{"sweep_state": "bad", "reason": "firewall_off", "checked_at": int(time.time())}])
dev_case("[순찰 반영] Access 검사 결과는 통과(5분 주기라 아직 옛 값)지만 순찰은 꺼짐 -> 관리자 콘솔 차단",
         {"device_context": True, "device_id": DEV_ID, "device_posture": FW_OK}, "kim@xmcda.store", False, "block_device",
         resource="admin.xmcda.store/")
q([])

# 순찰 배포 설정(Terraform)
_here = os.path.dirname(os.path.abspath(__file__))
_sw = open(os.path.join(_here, "device_sweep.tf"), encoding="utf-8").read()
_main = open(os.path.join(_here, "main.tf"), encoding="utf-8").read()
_pdp = _main.split('resource "aws_lambda_function" "pdp_engine"')[1].split("\n}\n")[0]
t("[순찰 배포] 세션 끊기 토큰은 순찰 함수에만(인터넷에 열린 판단 함수에는 없음)",
  "CF_ACCESS_REVOKE_TOKEN = var.cloudflare_access_revoke_token" in _sw and "revoke" not in _pdp.lower())
t("[순찰 배포] 1분 일정, 진입점 device_sweep_handler, 실행 제한 50초(1분보다 짧게)",
  'schedule_expression = "rate(1 minute)"' in _sw and 'handler          = "risk_score_engine.device_sweep_handler"' in _sw
  and "timeout = 50" in _sw)
t("[순찰 배포] 순찰 역할: device_state Scan/UpdateItem + 판정 로그 쓰기만",
  '["dynamodb:Scan", "dynamodb:UpdateItem"]' in _sw and "aws_dynamodb_table.device_state.arn" in _sw and "dynamodb:*" not in _sw)
t("[순찰 배포] 판단 함수는 device_state UpdateItem(사용 기록)/Query(순찰 결과)만",
  'Action   = ["dynamodb:UpdateItem", "dynamodb:Query"]\n      Resource = [aws_dynamodb_table.device_state.arn]' in _sw)
t("[순찰 배포] device_state 키 = 기기 ID + 사용자", 'hash_key     = "device_id"\n  range_key    = "identity"' in _sw)
t("[순찰 배포] EventBridge만 순찰 함수를 부를 수 있음(source_arn 제한)",
  'principal     = "events.amazonaws.com"' in _sw and "source_arn    = aws_cloudwatch_event_rule.device_sweep.arn" in _sw)
engine.CF_ACCOUNT_ID, engine.CF_DEVICE_API_TOKEN = "", ""
