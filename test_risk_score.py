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
mock_mfa_table = MagicMock()   # [step-up] mfa_verified - 별도 mock, 기본은 기록 없음(get_item 결과 없음)으로 둠

def _table_side_effect(name):
    return mock_mfa_table if name == 'mfa_verified' else mock_table

boto3.resource.return_value.Table.side_effect = _table_side_effect

sys.path.insert(0, '.')
import risk_score_engine as engine

TEST_HEADERS = {"x-evaluate-secret": "test-secret-local-only"}

def run_case(name, body, expect_allow=None, expect_action=None, mfa_record=None):
    mock_table.reset_mock()
    mock_mfa_table.reset_mock()
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
# [v12] 등급: top_secret=20(/admin,/api/db-data)  confidential=40(/hr,/dev)  internal=60(/marketing,/)
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
    {"session_id": "r2", "identity": "hana@test.com", "unknown_location": True, "resource_path": "/no-such-page"},
    expect_allow=True, expect_action="allow"
)

run_case(
    "[RESOURCE_THRESHOLDS] /admin(임계값20): unknown_location(40점) 단독 -> 기본(40)이면 통과지만 admin은 Step-up",
    {"session_id": "r3", "identity": "hana@test.com", "unknown_location": True, "resource_path": "/admin"},
    expect_allow=False, expect_action="step_up_mfa_required"
)
print(">>> 같은 신호(unknown_location)라도 자원이 /admin이면 위 r1과 다르게 걸려야 정상")
print()

run_case(
    "[RESOURCE_THRESHOLDS] /admin 하위 경로(/admin/users)도 접두어 매칭으로 동일 임계값(20) 적용",
    {"session_id": "r4", "identity": "hana@test.com", "unknown_location": True, "resource_path": "/admin/users"},
    expect_allow=False, expect_action="step_up_mfa_required"
)

run_case(
    "[RESOURCE_THRESHOLDS] /dev(기밀, 임계값40): night_access+unknown_location(60점) -> 경계구간이라 Step-up",
    {"session_id": "r5", "identity": "hana@test.com", "night_access": True, "unknown_location": True, "resource_path": "/dev"},
    expect_allow=False, expect_action="step_up_mfa_required"
)
print(">>> [v12] /dev가 60->40으로 바뀌어 s8과 같은 결과여야 정상 (v11까지는 통과였음)")
print()

run_case(
    "[v12] /hr(기밀, 임계값40): 같은 신호 조합 -> /dev와 동일하게 Step-up",
    {"session_id": "r5b", "identity": "hana@test.com", "night_access": True, "unknown_location": True, "resource_path": "/hr"},
    expect_allow=False, expect_action="step_up_mfa_required"
)

run_case(
    "[v12] /marketing(내부, 임계값60): night_access+unknown_location(60점) -> 통과",
    {"session_id": "r5c", "identity": "hana@test.com", "night_access": True, "unknown_location": True, "resource_path": "/marketing"},
    expect_allow=True, expect_action="allow"
)
print(">>> 내부 등급만 가장 관대해야 정상")
print()

run_case(
    "[RESOURCE_THRESHOLDS] /api/db-data(임계값20)에 쿼리스트링이 붙어도 정상 매칭",
    {"session_id": "r6", "identity": "hana@test.com", "unknown_location": True, "resource_path": "/api/db-data?type=admin_logs"},
    expect_allow=False, expect_action="step_up_mfa_required"
)

run_case(
    "[RESOURCE_THRESHOLDS] security 위험(waf_sqli)은 resource_path와 무관하게 여전히 MFA 전까지 무조건 차단",
    {"session_id": "r7", "identity": "attacker@test.com", "waf_sqli": True, "resource_path": "/dev"},
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

check_tier("[v12] /admin -> top_secret(20)", "/admin", "top_secret", 20)
check_tier("[v12] /api/db-data?type=x -> top_secret(20)", "/api/db-data?type=x", "top_secret", 20)
check_tier("[v12] /hr -> confidential(40)", "/hr", "confidential", 40)
check_tier("[v12] /dev -> confidential(40), /hr과 같은 등급", "/dev", "confidential", 40)
check_tier("[v12] /dev/sub 접두어 매칭 -> confidential(40)", "/dev/sub", "confidential", 40)
check_tier("[v12] /marketing -> internal(60)", "/marketing", "internal", 60)
check_tier("[v12] / -> internal(60)", "/", "internal", 60)
check_tier("[v12] 목록에 없는 경로 -> 등급 없음, DEFAULT_THRESHOLD(40)", "/no-such-page", None, 40)
check_tier("[v12] resource_path 없음 -> 등급 없음, DEFAULT_THRESHOLD(40)", None, None, 40)

_r = json.loads(engine.lambda_handler(
    {"headers": TEST_HEADERS, "body": json.dumps({"session_id": "t1", "identity": "hana@test.com", "resource_path": "/dev"})}, None
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
