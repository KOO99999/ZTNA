"""
main.tf 안의 trust_score_engine.py를 실제 AWS 없이 로컬에서 검증하는 스크립트.
boto3.resource('dynamodb')를 mock으로 치환해서 put_item 호출만 가로채고,
lambda_handler를 시나리오별로 직접 호출해 반환값을 확인한다.
"""
import sys
import time
import json
from unittest.mock import MagicMock

# boto3를 실제로 임포트하기 전에 mock으로 치환 (AWS 자격증명/네트워크 불필요)
sys.modules['boto3'] = MagicMock()
import boto3
mock_table = MagicMock()
boto3.resource.return_value.Table.return_value = mock_table

sys.path.insert(0, '.')
import trust_score_engine as engine

def run_case(name, body, expect_allow=None, expect_action=None):
    mock_table.reset_mock()
    result_raw = engine.lambda_handler({"body": json.dumps(body)}, None)
    result = json.loads(result_raw["body"])
    ok_allow = (expect_allow is None) or (result["allow"] == expect_allow)
    ok_action = (expect_action is None) or (result["action"] == expect_action)
    status = "PASS" if (ok_allow and ok_action) else "FAIL"
    print(f"[{status}] {name}")
    print(f"    -> score={result['score']} allow={result['allow']} action={result['action']} reasons={result['reasons']}")
    if status == "FAIL":
        print(f"    !! 기대값: allow={expect_allow}, action={expect_action}")
    # DynamoDB put_item이 실제로 호출됐는지도 확인
    called = mock_table.put_item.called
    print(f"    -> DynamoDB put_item 호출됨: {called}")
    print()

now = int(time.time())

# 케이스 1: 아무 위협 신호 없음 -> 100점, 그냥 통과
run_case(
    "정상 접속 (신호 없음)",
    {"session_id": "s1", "identity": "hana@test.com"},
    expect_allow=True, expect_action="allow"
)

# 케이스 2: behavioral 감점만 (night_access -10) -> 90점, 통과
run_case(
    "야간 접속만 (behavioral, 경계 밖)",
    {"session_id": "s2", "identity": "hana@test.com", "night_access": True},
    expect_allow=True, expect_action="allow"
)

# 케이스 3: security 감점 걸림 (waf_sqli -50) -> MFA 재인증 전까지 무조건 차단
run_case(
    "WAF SQLi 탐지 (security, MFA 미통과)",
    {"session_id": "s3", "identity": "attacker@test.com", "waf_sqli": True},
    expect_allow=False, expect_action="block_until_mfa"
)

# 케이스 4: security 감점 + MFA 통과 플래그 -> decay 적용됨, 점수에 따라 재평가
run_case(
    "WAF SQLi 이후 MFA 재인증 통과",
    {"session_id": "s3", "identity": "attacker@test.com", "waf_sqli": True, "security_mfa_passed": True},
    expect_allow=False, expect_action="block"  # 50점 감점이라 여전히 80점 미만
)

# 케이스 5: 신규 신호 device_fingerprint_mismatch 단독 -> -40점, security 그룹 -> block_until_mfa
run_case(
    "단말 지문 불일치 (신규 신호, security)",
    {"session_id": "s4", "identity": "hana@test.com", "device_fingerprint_mismatch": True},
    expect_allow=False, expect_action="block_until_mfa"
)

# 케이스 6: 조합규칙1 (unknown_location + waf_sqli) -> -20-50-15=85점 감점 -> 15점, block_until_mfa
run_case(
    "조합규칙: 위치이상+WAF SQLi",
    {"session_id": "s5", "identity": "attacker@test.com", "unknown_location": True, "waf_sqli": True},
    expect_allow=False, expect_action="block_until_mfa"
)

# 케이스 7: 조합규칙2 (brute_force + threat_intel_match) 신규 추가 규칙 확인 -15-40-10=65점 감점 -> 35점
run_case(
    "조합규칙(신규): 브루트포스+위협인텔",
    {"session_id": "s6", "identity": "attacker@test.com", "brute_force": True, "threat_intel_match": True},
    expect_allow=False, expect_action="block_until_mfa"
)

# 케이스 8: 경계구간 (78~82) -> unknown_location(-20) 만으로는 80점이라 경계 밖이지만,
# night_access(-10)+unknown_location(-20)=100-30=70점은 경계 밖(차단).
# 정확히 78~82 사이를 만들려면 감점 조합을 인위적으로 맞춰야 하므로,
# unknown_location(-20) 단독 -> 80점 정확히 (REQUIRED_SCORE와 동일, 경계 조건 elif는 '< REQUIRED_SCORE'라 80은 통과 처리됨)
run_case(
    "정확히 80점 (임계값과 동일 -> 통과)",
    {"session_id": "s7", "identity": "hana@test.com", "unknown_location": True},
    expect_allow=True, expect_action="allow"
)

# 케이스 9: night_access + unknown_location = -30 -> 70점, 경계(78~82) 밖이라 그냥 block
run_case(
    "70점 (경계 밖, 그냥 차단)",
    {"session_id": "s8", "identity": "hana@test.com", "night_access": True, "unknown_location": True},
    expect_allow=False, expect_action="block"
)

# 케이스 10: History Decay가 security 감점에는 안 걸리는지 확인
# waf_sqli(-50) + last_activity 2시간 전(-10 decay 예상) 이지만 MFA 미통과라 decay 자체가 스킵되어야 함
run_case(
    "security 감점 상태에서 History Decay 미적용 확인",
    {"session_id": "s9", "identity": "attacker@test.com", "waf_sqli": True,
     "last_activity_timestamp": now - 7200},  # 2시간 전
    expect_allow=False, expect_action="block_until_mfa"
)
print(">>> reasons에 'history_decay'가 없어야 정상 (security 감점 중엔 decay 스킵)")
print()

# 케이스 11 (v6.1): 마진 5로 넓힌 뒤 75점 조합이 실제로 step_up_mfa_required를 트리거하는지 확인
# brute_force는 security 그룹이라 우선 block_until_mfa 분기가 먼저 걸리므로 여기선 쓸 수 없음.
# behavioral 신호(night_access -10)만으로는 90점이라, decay(-15, 3시간 방치)를 더해 정확히 75점을 만든다.
run_case(
    "[v6.1] 75점 조합(behavioral+decay) -> Step-up MFA 실제 트리거 확인",
    {"session_id": "s10", "identity": "hana@test.com", "night_access": True,
     "last_activity_timestamp": now - 3 * 3600},
    expect_allow=False, expect_action="step_up_mfa_required"
)
