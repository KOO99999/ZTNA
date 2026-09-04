"""
main.tf가 참조하는 risk_score_engine.py를 실제 AWS 없이 로컬에서 검증하는 스크립트.
v10: 전체 배점 2배 재설정 반영 (RISK_THRESHOLD=40, STEP_UP_MARGIN=20).
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
mock_table = MagicMock()
boto3.resource.return_value.Table.return_value = mock_table

sys.path.insert(0, '.')
import risk_score_engine as engine

TEST_HEADERS = {"x-evaluate-secret": "test-secret-local-only"}

def run_case(name, body, expect_allow=None, expect_action=None):
    mock_table.reset_mock()
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

# --- 공유 비밀키 검증 자체 테스트 (헤더 없이/틀린 값으로 호출 시 401) ---
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
