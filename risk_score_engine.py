import json
import os
import time
import uuid
import boto3

dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-2')
table = dynamodb.Table('risk_score_log')

# /evaluate가 인증 없이 URL만 알면 호출되는 문제 보완용.
# Terraform(main.tf)이 random_password로 생성해 Lambda 환경변수로 주입한 값과 대조한다.
SHARED_SECRET = os.environ.get("EVALUATE_SHARED_SECRET")

# v10: 전체 배점 2배 확대 (임계값·마진·조합보너스·시간감쇠 포함 일관 적용)
#   - v9까지: night_access=10 ~ waf_sqli=47, 임계값 20, 마진 10 (재인증 구간 20~30)
#   - v10: 재인증 구간이 좁아 보인다는 팀 판단에 따라 전 항목을 2배로 재설정.
#     주의: 이 2배 확대는 "신호들 사이의 상대적 비율·판정 로직을 그대로 유지한 채
#     눈금만 두 배로 늘린 것"으로, 각 상황이 통과/재인증/차단 중 어디로 분류되는지는
#     v9과 완전히 동일함(수학적으로 동치) — 표기상의 재설정이며 새로운 근거를 추가한 것은
#     아님을 보고서에 명시할 것. resettable=False 신호(threat_intel_match/waf_sqli/
#     device_fingerprint_mismatch, 최소값 76)는 여전히 임계값+마진(60)을 안전하게 초과해
#     "MFA 통과 후에도 확실히 차단" 원칙이 유지됨
RISK_MATRIX = {
    # --- behavioral: 시간 경과로 자동 회복 가능. 데이터셋(rba-dataset) 검증 완료(v9) ---
    "night_access": {"risk": 20, "group": "behavioral"},
    "unknown_location": {"risk": 40, "group": "behavioral"},

    # --- security: 자동 회복 불가, security_mfa_passed=True + resettable=True 인 경우만 리셋.
    #     배점은 OWASP Risk Rating Methodology(가능성×영향도) 기반(v9)에 2배 재설정(v10) ---
    "brute_force": {"risk": 58, "group": "security", "resettable": True},
    "threat_intel_match": {"risk": 86, "group": "security", "resettable": False},
    "waf_sqli": {"risk": 94, "group": "security", "resettable": False},
    "device_fingerprint_mismatch": {"risk": 76, "group": "security", "resettable": False},
}

COMBINATION_RULES = [
    (("unknown_location", "waf_sqli"), 30, "interaction_location_waf"),
    (("brute_force", "threat_intel_match"), 20, "interaction_bruteforce_threatintel"),
]

RISK_THRESHOLD = 40            # 이 값 이하면 허용
STEP_UP_MARGIN = 20            # RISK_THRESHOLD ~ +MARGIN 구간을 "경계구간"(Step-up MFA)으로 간주

# 장애 시 정책 참고표 (실제 적용은 PEP/Cloudflare Worker에서 이 값을 조회해 구현)
FAIL_POLICY = {
    "general": "fail_open",
    "admin": "fail_closed",
}

def lambda_handler(event, context):
    print("Received event:", json.dumps(event))

    # API Gateway(HTTP API v2)는 헤더 키를 소문자로 정규화해서 넘겨줌
    headers = event.get("headers", {}) or {}
    provided_secret = headers.get("x-evaluate-secret")
    if not SHARED_SECRET or provided_secret != SHARED_SECRET:
        return {
            "statusCode": 401,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "unauthorized"})
        }

    body = {}
    if "body" in event and event["body"]:
        try:
            body = json.loads(event["body"])
        except Exception:
            body = {}
    elif isinstance(event, dict):
        body = event

    risk_score = 0             # 0(완전 안전)에서 시작, 위험할수록 더함. 상한 없음
    reasons = []
    penalized_signals = []     # 실제로 위험도가 반영된 신호만 (조합규칙 판단용)
    security_penalty_applied = False
    current_time = int(time.time())
    security_mfa_passed = bool(body.get("security_mfa_passed"))

    # 1. 위협 인덱스 가산 (behavioral/security 구분 + resettable 처리)
    for factor, rule in RISK_MATRIX.items():
        if body.get(factor):
            if rule["group"] == "security":
                security_penalty_applied = True
                if security_mfa_passed and rule.get("resettable"):
                    reasons.append(f"{factor} (resettable, MFA 통과로 리셋됨)")
                    continue
            risk_score += rule["risk"]
            reasons.append(f"{factor} (+{rule['risk']})")
            penalized_signals.append(factor)

    # 2. 조합 규칙 가산 — 실제로 위험도가 반영된 신호끼리만 적용 (리셋된 신호는 조합에서도 제외)
    for signals, bonus, label in COMBINATION_RULES:
        if all(s in penalized_signals for s in signals):
            risk_score += bonus
            reasons.append(f"{label} (+{bonus})")

    # 3. History Decay — security 위험이 걸려있고 아직 MFA 재인증 전이면 decay 적용 안 함
    if not security_penalty_applied or security_mfa_passed:
        last_activity = body.get("last_activity_timestamp")
        if last_activity:
            try:
                inactivity_hours = int((current_time - int(last_activity)) / 3600)
                if inactivity_hours > 0:
                    decay_penalty = inactivity_hours * 10   # v10: 시간당 5 -> 10 (2배 일관 적용)
                    risk_score += decay_penalty
                    reasons.append(f"history_decay_{inactivity_hours}h (+{decay_penalty})")
            except Exception as e:
                print("History decay calculation error:", str(e))

    session_id = body.get("session_id", str(uuid.uuid4()))

    # 4. 보안 위험이 걸린 세션은 MFA 재인증 전까지 무조건 차단
    if security_penalty_applied and not security_mfa_passed:
        allow_access = False
        action = "block_until_mfa"
    # 5. 경계구간(RISK_THRESHOLD ~ +STEP_UP_MARGIN)은 즉시 차단 대신 Adaptive MFA 요구
    elif RISK_THRESHOLD < risk_score <= RISK_THRESHOLD + STEP_UP_MARGIN:
        allow_access = False
        action = "step_up_mfa_required"
        print(f"[SOC_ALERT] identity={body.get('identity','unknown')} risk_score={risk_score} action={action}")
    else:
        allow_access = (risk_score <= RISK_THRESHOLD)
        action = "allow" if allow_access else "block"

    try:
        table.put_item(
            Item={
                'session_id': session_id,
                'timestamp': current_time,
                'risk_score': risk_score,
                'reasons': reasons,
                'allow': allow_access,
                'action': action,
                'identity': body.get('identity', 'unknown')
            }
        )
    except Exception as e:
        print("DynamoDB logging failed:", str(e))

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "success": allow_access,
            "allow": allow_access,
            "score": risk_score,
            "action": action,
            "reasons": reasons,
            "session_id": session_id
        })
    }
