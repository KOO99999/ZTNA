import json
import os
import time
import uuid
import boto3
from datetime import datetime, timedelta

dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-2')
table = dynamodb.Table('risk_score_log')

# /evaluate가 인증 없이 URL만 알면 호출되는 문제 보완용.
# Terraform(main.tf)이 random_password로 생성해 Lambda 환경변수로 주입한 값과 대조한다.
SHARED_SECRET = os.environ.get("EVALUATE_SHARED_SECRET")

# 이 시스템의 "본거지" 국가. unknown_location 판정 기준값.
HOME_COUNTRY = "KR"

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

# [v11] 자원 민감도별 임계값(RESOURCE_THRESHOLDS)
#   그동안 RISK_THRESHOLD(40) 하나를 모든 자원(/admin, /dev 등)에 동일하게 적용해왔음.
#   NIST SP 800-207의 "자원 민감도에 따라 판정 기준선을 차등화해야 한다"는 원칙에 따라,
#   자원별로 임계값을 다르게 적용하도록 확장. 숫자(20/40/60) 자체는 상대적 위계(관리자
#   자원이 가장 엄격, 일반 자원이 가장 느슨)만 반영한 팀 판단이며 절대적 근거는 없음 —
#   이 분야(제로트러스트 임계값 결정) 자체가 학계에서도 "표준화된 도출 방법이 없다"고
#   인정하는 공백 지점이라는 점을 보고서에 명시할 것.
#   STEP_UP_MARGIN은 자원별로 따로 두지 않고 "임계값+20" 규칙 하나로 통일 (고정폭 유지 결정).
RESOURCE_THRESHOLDS = {
    "/admin": 20,
    "/api/db-data": 20,
    "/hr": 40,
    "/dev": 60,
    "/marketing": 60,
    "/": 60,
}
DEFAULT_THRESHOLD = 40         # resource_path가 없거나(구버전 호출 등) 목록에 없는 자원 -> 기존 RISK_THRESHOLD와 동일값으로 안전 처리

STEP_UP_MARGIN = 20            # 임계값 ~ +MARGIN 구간을 "경계구간"(Step-up MFA)으로 간주 (자원 무관 고정폭)


def get_resource_threshold(resource_path):
    """resource_path(예: '/admin', '/api/db-data?type=x')에 맞는 임계값을 조회.
    - 정확히 일치하면 그 값을 사용
    - 하위 경로(예: '/admin/users')는 가장 긴 접두어가 일치하는 항목을 사용
    - 둘 다 없으면 DEFAULT_THRESHOLD로 안전 처리 (기존 동작과 동일)
    """
    if not resource_path:
        return DEFAULT_THRESHOLD

    normalized = resource_path.split("?")[0].rstrip("/") or "/"

    if normalized in RESOURCE_THRESHOLDS:
        return RESOURCE_THRESHOLDS[normalized]

    for path in sorted(RESOURCE_THRESHOLDS.keys(), key=len, reverse=True):
        if path != "/" and normalized.startswith(path):
            return RESOURCE_THRESHOLDS[path]

    return DEFAULT_THRESHOLD

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

    # --- 0. 원본 신호(request_timestamp, geo_country) 판정 ---
    # Worker(index.js)는 판단 없이 원본 데이터만 전달하고, "야간인지/위치가
    # 이상한지"에 대한 실제 판정은 여기(PDP)에서 전담한다. 판정 결과를
    # body에 boolean으로 채워넣으면, 아래 §1의 RISK_MATRIX 루프가
    # body.get(factor) 형태로 그대로 읽어간다.

    # night_access: 요청 시각(KST) 기준 22시~06시 사이면 야간 접속으로 판단.
    # 1단계 구현: 전 직원 공통 고정 기준(전 직원 동일 적용).
    # 추후 role별 가정값 -> 실측 이력 기반 개인화로 단계적 고도화 예정.
    request_timestamp = body.get("request_timestamp")
    if request_timestamp:
        try:
            dt_utc = datetime.fromisoformat(request_timestamp.replace("Z", "+00:00"))
            kst_hour = (dt_utc + timedelta(hours=9)).hour
            if kst_hour >= 22 or kst_hour < 6:
                body["night_access"] = True
        except Exception as e:
            print("night_access 판정 중 시각 파싱 오류:", str(e))

    # unknown_location: Cloudflare Access가 제공하는 geo.country가 HOME_COUNTRY(KR)와
    # 다르면 위치 이상으로 판단. geo_country가 없는 경우(누락/알 수 없음)는 오탐 방지를
    # 위해 위험으로 간주하지 않음.
    geo_country = body.get("geo_country")
    if geo_country is not None and geo_country != HOME_COUNTRY:
        body["unknown_location"] = True

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

    # resource_path: Worker(index.js)가 Access JWT의 request_url을 가공 없이 그대로 전달.
    # 판단(어떤 임계값을 적용할지)은 여기(PDP)에서 전담 — Worker/PEP는 원본만 넘긴다는
    # 기존 원칙(night_access/unknown_location과 동일)을 그대로 따름.
    resource_path = body.get("resource_path")
    resource_threshold = get_resource_threshold(resource_path)

    # 4. 보안 위험이 걸린 세션은 MFA 재인증 전까지 무조건 차단
    if security_penalty_applied and not security_mfa_passed:
        allow_access = False
        action = "block_until_mfa"
    # 5. 경계구간(자원별 임계값 ~ +STEP_UP_MARGIN)은 즉시 차단 대신 Adaptive MFA 요구
    elif resource_threshold < risk_score <= resource_threshold + STEP_UP_MARGIN:
        allow_access = False
        action = "step_up_mfa_required"
        print(f"[SOC_ALERT] identity={body.get('identity','unknown')} risk_score={risk_score} resource_path={resource_path} threshold={resource_threshold} action={action}")
    else:
        allow_access = (risk_score <= resource_threshold)
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
                'identity': body.get('identity', 'unknown'),
                'resource_path': resource_path or 'unknown',
                'resource_threshold': resource_threshold
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
            "session_id": session_id,
            "resource_path": resource_path,
            "resource_threshold": resource_threshold
        })
    }
