import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import boto3
from datetime import datetime, timedelta, timezone

dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-2')
table = dynamodb.Table('risk_score_log')
mfa_table = dynamodb.Table('mfa_verified')
decision_table = dynamodb.Table('access_decision')   # 사용자+앱별 마지막 판단(재인증/차단 화면을 고르는 데 씀)
device_state_table = dynamodb.Table('device_state')   # 기기 순찰(device_sweep)이 본 기기별 최신 상태
user_risk_table = dynamodb.Table('user_risk')   # 관리자가 풀어줄 때까지 유지되는 누적 위험 상태(mfa_verified와 별개)

# [step-up 재인증] MFA 재인증 기록의 유효 시간. 팀이 정한 값이며 표준에 정해진 수치는
# 아님(RFC 9470/NIST 800-63B 모두 "얼마나 최근이어야 하는가"의 구체적 숫자는 구현자에게
# 맡김). 로그인 시점 평가만 있는 지금 구조 기준으로 정한 값 - 세션 중 재평가(B 계층)가
# 생기면 그 재평가 주기와 맞춰 다시 조정 필요.
MFA_FRESHNESS_SECONDS = 600

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

    # --- device: 기기 신뢰(WARP 기기 검사, Cloudflare가 검사하고 결과를 Access 신원 정보로 넘겨줌) ---
    #     MFA로 기기 상태가 바뀌지는 않지만, 경계구간에서는 최근 재인증(step-up)으로 통과할 수 있게 behavioral로 둔다
    #     (관리자 해제가 필요한 sticky 신호로 두면 개인 PC/공용 PC를 쓰는 정상 직원이 계속 막힘).
    #     45점 = 내부(60) 통과 / 기밀(40) 재인증 / 최고기밀(20) 차단. 팀 판단 수치(표준 근거 없음) - 보고서에 명시.
    "device_unmanaged": {"risk": 45, "group": "behavioral"},       # WARP 미등록/미연결 기기(기기 정보 없음)
    # 회사 기기인 건 확인됐고 관리 상태(방화벽)가 나쁜 것 -> 공격보다 관리 소홀일 가능성이 커서 낮게 둔다.
    #   25점: 내부(60)/기밀(40) 통과, 최고기밀(20)만 걸림(기기 신호라 재인증 없이 차단 + "방화벽을 켜세요")
    "device_posture_failed": {"risk": 25, "group": "behavioral"},  # 등록 기기지만 필수 기기 검사(방화벽) 실패/결과 없음
    "device_owner_mismatch": {"risk": 45, "group": "behavioral"},  # 기기 등록 사용자 != 로그인한 사람
}

COMBINATION_RULES = [
    (("unknown_location", "waf_sqli"), 30, "interaction_location_waf"),
    # 해외에서 남의 기기로 접속 = 계정 탈취 후 다른 장비 사용 가능성이 높은 조합
    (("unknown_location", "device_owner_mismatch"), 20, "interaction_location_device_owner"),
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
# [v12] 경로마다 숫자를 직접 적는 대신 "등급 이름 -> 임계값" 표와 "경로 -> 등급" 표로 분리.
#   "/hr과 /dev는 같은 기밀 등급"이 코드에 그대로 드러나고, 기준을 바꿀 땐 등급 숫자 하나만 고치면 됨.
#   등급 분류는 "자원이 흔히 다루는 데이터 종류에 대한 가정"(개인정보, 소스코드/서버 접근 = 기밀)에
#   따른 팀 판단이며 실제 데이터 분류 체계에 근거한 것이 아님 - 숫자(20/40/60)와 함께 보고서에 명시할 것.
# 야간 접속 판정 기준(KST 22시~06시). night_access 판정과 아래 캐시 만료 계산이 같은 값을 쓴다.
NIGHT_START_HOUR_KST = 22
NIGHT_END_HOUR_KST = 6

TIER_THRESHOLDS = {
    "top_secret": 20,    # 최고기밀: 관리자 콘솔, 감사 로그 API
    "confidential": 40,  # 기밀: 인사(개인정보), 개발(소스코드/서버 접근)
    "internal": 60,      # 내부: 마케팅, 포털 공통
}

# [서브도메인 분리] 자원 식별자를 경로("/hr")에서 "호스트+경로"("hr.xmcda.store/...")로 바꿨다.
#   앱마다 호스트가 따로라서, 경로만 보면 hr.xmcda.store/와 포털 xmcda.store/가 둘 다 "/"로 구분이 안 된다.
#   키는 호스트(앱 단위)이고, 나중에 특정 경로만 더 엄격하게 하려면 "호스트/경로" 키를 추가하면 된다
#   (가장 긴 키가 우선, 경로 경계("/")에서만 일치). 기준 도메인은 Lambda 환경변수 DOMAIN_NAME(main.tf).
DOMAIN_NAME = os.environ.get("DOMAIN_NAME", "xmcda.store").strip().lower()

RESOURCE_TIERS = {
    f"admin.{DOMAIN_NAME}": "top_secret",
    f"hr.{DOMAIN_NAME}": "confidential",
    f"dev.{DOMAIN_NAME}": "confidential",
    f"marketing.{DOMAIN_NAME}": "internal",
    DOMAIN_NAME: "internal",          # 포털(전사 공통)
}

# 기존 코드/테스트가 쓰는 이름 유지 (자원 -> 임계값). 등급표에서 파생되므로 따로 고칠 곳 없음.
RESOURCE_THRESHOLDS = {path: TIER_THRESHOLDS[tier] for path, tier in RESOURCE_TIERS.items()}
DEFAULT_THRESHOLD = 40         # resource_path가 없거나(구버전 호출 등) 목록에 없는 자원 -> 기존 RISK_THRESHOLD와 동일값으로 안전 처리

STEP_UP_MARGIN = 20            # 임계값 ~ +MARGIN 구간을 "경계구간"(Step-up MFA)으로 간주 (자원 무관 고정폭)


def normalize_resource(resource_path):
    """'HR.xmcda.store/a/?x=1' -> 'hr.xmcda.store/a'. 쿼리 제거, 호스트 소문자, 끝 슬래시 제거."""
    if not resource_path:
        return None
    value = resource_path.split("?")[0].split("#")[0].strip()
    host, slash, path = value.partition("/")
    host = host.lower().rstrip(".")
    if not host:
        return None
    path = path.rstrip("/")
    return f"{host}/{path}" if path else host


# ==========================================================================
# [기기 신뢰] WARP 기기 검사 결과를 신호로 바꾼다.
#   - 검사 자체는 Cloudflare(WARP)가 하고, Access가 신원 정보(devicePosture, device_id)에 담아 Worker로 보낸다.
#     Worker는 판단 없이 그대로 넘기고(device_context=True), 여기(PDP)서 판단한다.
#   - 기기 등록 사용자는 Cloudflare API(physical-devices)의 last_seen_user.email로 확인한다(읽기 전용 토큰).
#   - device_context가 없는 호출(로그인 서버, 웹 서버 앞단)은 기기 정보를 모르므로 기기 신호를 만들지 않는다.
# ==========================================================================
DEVICE_POSTURE_RULE_NAME = os.environ.get("DEVICE_POSTURE_RULE_NAME", "ZT - Windows Firewall On")
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")
CF_DEVICE_API_TOKEN = os.environ.get("CF_DEVICE_API_TOKEN", "")
# [기기 신호 스위치] 다른 신호를 개발/시험하는 동안 기기 신호 때문에 접속이 막히지 않게 켜고 끈다.
#   enforce: 점수에 반영(실제 판단)
#   report : 신호는 계산해서 로그(reasons)에만 "report-only, +0"으로 남기고 점수에는 넣지 않음
#            (Microsoft 조건부 액세스의 "보고 전용(Report-only)" 모드와 같은 개념: 영향을 먼저 관찰한 뒤 켠다)
#   off    : 계산하지 않음(Cloudflare 기기 주인 조회 API도 부르지 않음)
#   알 수 없는 값이면 안전한 쪽(enforce)으로 본다.
DEVICE_SIGNALS = ("device_unmanaged", "device_owner_mismatch", "device_posture_failed")
DEVICE_SIGNAL_MODES = ("enforce", "report", "off")
DEVICE_SIGNAL_MODE = os.environ.get("DEVICE_SIGNAL_MODE", "enforce").strip().lower()
if DEVICE_SIGNAL_MODE not in DEVICE_SIGNAL_MODES:
    DEVICE_SIGNAL_MODE = "enforce"
_DEVICE_ID_RE = re.compile(r"^[0-9a-fA-F-]{8,64}$")


def lookup_device_owner(device_id):
    """기기 ID로 Cloudflare에 등록된 기기 사용자 이메일을 조회. 설정이 없거나 실패하면 None.
    실패 시 주인 불일치 신호를 만들지 않는다(조회 장애로 전 직원이 막히지 않게). 기기 상태 신호는 그대로 판단된다."""
    if not (CF_ACCOUNT_ID and CF_DEVICE_API_TOKEN and _DEVICE_ID_RE.match(device_id or "")):
        return None
    url = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/devices/physical-devices/{device_id}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {CF_DEVICE_API_TOKEN}"})
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode())
        email = ((data.get("result") or {}).get("last_seen_user") or {}).get("email")
        return email.strip().lower() if isinstance(email, str) and email.strip() else None
    except Exception as e:
        print("[DEVICE_OWNER_LOOKUP_FAILED]", type(e).__name__)
        return None


def derive_device_signals(body):
    """Worker가 넘긴 기기 정보로 device_unmanaged / device_posture_failed / device_owner_mismatch를 정한다.
    감지한 신호 이름 목록을 돌려준다. enforce 모드일 때만 body에 신호를 넣어 점수에 반영한다."""
    if DEVICE_SIGNAL_MODE == "off" or body.get("device_context") is not True:
        return []
    detected = []
    device_id = body.get("device_id")
    if not device_id:
        detected.append("device_unmanaged")
    else:
        posture = body.get("device_posture") or []
        required = [p for p in posture if isinstance(p, dict) and p.get("rule") == DEVICE_POSTURE_RULE_NAME]
        if not required or not all(p.get("success") is True for p in required):
            detected.append("device_posture_failed")
        # 기기 순찰(device_sweep)이 본 최신 상태도 같이 본다. Access가 넘기는 검사 결과는 5분 주기라,
        # 순찰이 세션을 끊은 직후 다시 들어오면 아직 "통과"로 남아 있을 수 있다. 둘 중 하나라도 나쁘면 나쁜 것.
        swept = sweep_signal_for(str(device_id))
        if swept and swept not in detected:
            detected.append(swept)
        owner = lookup_device_owner(str(device_id))
        identity = str(body.get("identity") or "").strip().lower()
        if owner and identity and owner != identity:
            detected.append("device_owner_mismatch")
    if DEVICE_SIGNAL_MODE == "enforce":
        for signal in detected:
            body[signal] = True
    return detected


# [마지막 판단] 사용자+앱(호스트)별로 가장 최근 판단만 짧게 보관한다(TTL). 화면 선택용이며 접근 허용에는 쓰지 않는다.
DECISION_TTL_SECONDS = 600


def resource_host(resource_path):
    normalized = normalize_resource(resource_path) if isinstance(resource_path, str) else None
    return normalized.split("/")[0] if normalized else None


def save_decision(identity, resource_path, action, device_reasons, now):
    host = resource_host(resource_path)
    if not host:
        return
    try:
        decision_table.put_item(Item={
            "identity": str(identity).strip().lower(),
            "resource_host": host,
            "action": action,
            "device_reasons": list(device_reasons),
            "decided_at": now,
            "expires_at": now + DECISION_TTL_SECONDS,
        })
    except Exception as e:
        print("access_decision 기록 실패:", str(e))


def lookup_decision(identity, host):
    """{"found": bool, "action": ..., "device_reasons": [...]}. 없거나 만료됐거나 조회 실패면 found=False."""
    if not isinstance(identity, str) or not isinstance(host, str) or not identity.strip() or not host.strip():
        return {"found": False}
    host = resource_host(host)
    if not host:
        return {"found": False}
    try:
        item = decision_table.get_item(Key={"identity": identity.strip().lower(), "resource_host": host}).get("Item")
    except Exception as e:
        print("access_decision 조회 실패:", str(e))
        return {"found": False}
    if not item or int(item.get("expires_at", 0)) <= int(time.time()):
        return {"found": False}
    reasons = [r for r in (item.get("device_reasons") or []) if r in DEVICE_SIGNALS]
    return {"found": True, "action": str(item.get("action", "")), "device_reasons": reasons}


# ==========================================================================
# [기기 순찰] 세션 도중의 기기 상태 변화를 잡는다.
#   왜: Access는 세션을 새로 줄 때만 기기 정보를 넘기고(get-identity도 로그인 시점 값, 실측 확인),
#       세션 중 상태를 실시간으로 받는 Logpush는 Enterprise 기능이다. 그래서 엔진이 1분마다 Cloudflare의
#       기기 상태 API(DEX Fleet Status: status, firewallEnabled, 실측 약 2분 단위 갱신)를 조회한다.
#   어떻게: 정상 -> 나쁨(방화벽 꺼짐 / WARP 연결 끊김 / 상태 정보 없음)으로 "바뀐" 기기를 찾으면 그 사용자의
#       Access 세션을 끊는다(revoke_user). 사용자가 다시 들어오면 Access -> External Evaluation -> 이 엔진이
#       최신 상태(sweep_signal_for)까지 보고 다시 판단한다. 판단은 엔진, Cloudflare는 끊기만 한다.
#       (실무의 "상태가 바뀌면 세션을 끊고 재평가" 방식 - Microsoft CAE, OpenID CAEP와 같은 구조, 수신만 polling)
#   끊기는 바뀐 순간 한 번만: 나쁜 상태가 계속될 때마다 끊으면 포털(통과 대상)도 못 쓰게 된다.
#   API 오류(429/5xx/네트워크)는 "모름"으로 보고 상태를 바꾸지 않는다(장애로 전원 세션이 끊기지 않게).
#   별도 Lambda(device-sweep)로 실행하며, 세션 끊기 토큰은 그 함수에만 있다(인터넷에 열린 판단 함수에는 없음).
# ==========================================================================
SWEEP_LOOKBACK_MINUTES = 60          # 최근 이 시간 안에 보인 기기만 순찰(오래 꺼진 기기는 쓰는 중이 아님)
SWEEP_STATE_FRESH_SECONDS = 600      # 판단 때 순찰 결과를 믿는 시간(순찰이 멈췄으면 옛 결과로 막지 않음)
SWEEP_STATE_TTL_SECONDS = 86400
SWEEP_MAX_PAGES = 10
CF_ACCESS_REVOKE_TOKEN = os.environ.get("CF_ACCESS_REVOKE_TOKEN", "")
SWEEP_REASON_SIGNAL = {"firewall_off": "device_posture_failed",
                       "disconnected": "device_unmanaged", "no_data": "device_unmanaged"}


class CloudflareApiUnavailable(Exception):
    """429/5xx/네트워크 오류: 결과를 모르는 상태(나쁨으로 보지 않는다)."""


def _cf_get(path, token):
    req = urllib.request.Request(f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}{path}",
                                 headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None              # 이 기기의 최근 상태 정보 없음
        raise CloudflareApiUnavailable(f"HTTP {e.code}")
    except Exception as e:
        raise CloudflareApiUnavailable(type(e).__name__)


def list_recent_devices(now):
    """최근 SWEEP_LOOKBACK_MINUTES 안에 보인 활성 기기: [(device_id, email)]"""
    since = datetime.fromtimestamp(now - SWEEP_LOOKBACK_MINUTES * 60, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    devices, cursor = [], ""
    for _ in range(SWEEP_MAX_PAGES):
        query = f"?per_page=50&seen_after={since}" + (f"&cursor={urllib.parse.quote(cursor)}" if cursor else "")
        data = _cf_get(f"/devices/physical-devices{query}", CF_DEVICE_API_TOKEN) or {}
        for d in data.get("result") or []:
            device_id = str(d.get("id") or "")
            email = ((d.get("last_seen_user") or {}).get("email") or "").strip().lower()
            if _DEVICE_ID_RE.match(device_id) and email and not d.get("deleted_at"):
                devices.append((device_id, email))
        cursor = ((data.get("result_info") or {}).get("cursor") or "")
        if not cursor:
            break
    return devices


def classify_fleet_status(result):
    """Fleet Status 응답 -> (나쁨 사유 또는 None). firewallEnabled는 꺼지면 응답에서 빠진다(실측) -> True일 때만 정상."""
    if not isinstance(result, dict) or not result:
        return "no_data"
    if str(result.get("status", "")).lower() != "connected":
        return "disconnected"
    if str(result.get("platform", "")).lower() == "windows" and result.get("firewallEnabled") is not True:
        return "firewall_off"
    return None


def revoke_access_sessions(email):
    """Cloudflare Access: 이 사용자의 모든 앱 세션을 끊는다. 성공하면 True."""
    if not (CF_ACCOUNT_ID and CF_ACCESS_REVOKE_TOKEN):
        return False
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/access/organizations/revoke_user",
        data=json.dumps({"email": email}).encode(), method="POST",
        headers={"Authorization": f"Bearer {CF_ACCESS_REVOKE_TOKEN}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode()).get("success") is True
    except Exception as e:
        print("[DEVICE_SWEEP_REVOKE_FAILED]", type(e).__name__)
        return False


def sweep_signal_for(device_id):
    """판단 때 쓰는 순찰 결과: 최근(SWEEP_STATE_FRESH_SECONDS) 나쁨으로 본 기기면 해당 신호 이름, 아니면 None."""
    if not _DEVICE_ID_RE.match(device_id or ""):
        return None
    try:
        item = device_state_table.get_item(Key={"device_id": device_id}).get("Item")
    except Exception as e:
        print("device_state 조회 실패:", str(e))
        return None
    if not item or item.get("state") != "bad":
        return None
    if int(time.time()) - int(item.get("checked_at", 0)) > SWEEP_STATE_FRESH_SECONDS:
        return None
    return SWEEP_REASON_SIGNAL.get(item.get("reason"))


def device_sweep(now=None):
    """기기 순찰 1회. 바뀐 기기 수/끊은 사용자 등을 돌려준다(로그·테스트용)."""
    now = int(now or time.time())
    summary = {"checked": 0, "bad": 0, "revoked": [], "unknown": 0, "mode": DEVICE_SIGNAL_MODE}
    if DEVICE_SIGNAL_MODE == "off" or not (CF_ACCOUNT_ID and CF_DEVICE_API_TOKEN):
        return summary
    try:
        devices = list_recent_devices(now)
    except CloudflareApiUnavailable as e:
        print("[DEVICE_SWEEP_LIST_FAILED]", str(e))
        summary["unknown"] = -1
        return summary
    for device_id, email in devices:
        try:
            data = _cf_get(f"/dex/devices/{device_id}/fleet-status/live?since_minutes=10", CF_DEVICE_API_TOKEN)
        except CloudflareApiUnavailable as e:
            print("[DEVICE_SWEEP_STATUS_UNKNOWN]", device_id, str(e))
            summary["unknown"] += 1
            continue
        summary["checked"] += 1
        reason = classify_fleet_status((data or {}).get("result"))
        try:
            prev = device_state_table.get_item(Key={"device_id": device_id}).get("Item") or {}
        except Exception as e:
            print("device_state 조회 실패:", str(e))
            continue
        item = {"device_id": device_id, "email": email, "state": "bad" if reason else "ok", "reason": reason or "",
                "checked_at": now, "expires_at": now + SWEEP_STATE_TTL_SECONDS,
                # 이미 끊은 기록은 "나쁨이 이어지는 동안"만 유지한다. 정상으로 돌아오면 지워서, 다시 나빠지면 또 끊는다.
                "revoked": bool(prev.get("revoked")) if (reason and prev.get("state") == "bad") else False}
        if reason:
            summary["bad"] += 1
            # 정상 -> 나쁨으로 바뀌었거나, 지난번 끊기에 실패했으면 이번에 끊는다(나쁜 동안 반복해서 끊지 않음)
            if not item["revoked"]:
                if DEVICE_SIGNAL_MODE == "enforce":
                    item["revoked"] = revoke_access_sessions(email)
                    action = "device_session_revoked" if item["revoked"] else "device_session_revoke_failed"
                else:
                    item["revoked"] = True          # report: 끊지는 않고 "끊었을 것"만 기록
                    action = "device_session_revoke_report_only"
                if item["revoked"] and DEVICE_SIGNAL_MODE == "enforce":
                    summary["revoked"].append(email)
                try:
                    table.put_item(Item={"session_id": str(uuid.uuid4()), "timestamp": now, "risk_score": 0,
                                         "reasons": [f"device_sweep:{reason}"], "allow": False, "action": action,
                                         "identity": email, "resource_path": "all-apps", "resource_threshold": 0,
                                         "source": "sweep"})
                except Exception as e:
                    print("DynamoDB logging failed:", str(e))
                print(f"[DEVICE_SWEEP] identity={email} device={device_id} reason={reason} action={action}")
        try:
            device_state_table.put_item(Item=item)
        except Exception as e:
            print("device_state 기록 실패:", str(e))
    return summary


def device_sweep_handler(event, context):
    """EventBridge(1분 일정)가 부르는 진입점. 인터넷(API Gateway)에서는 부를 수 없다(별도 Lambda)."""
    summary = device_sweep()
    print("[DEVICE_SWEEP_SUMMARY]", json.dumps(summary))
    return summary


def get_resource_tier(resource_path):
    """resource_path(호스트+경로, 예: 'admin.xmcda.store/', 'hr.xmcda.store/a?x=1')에 맞는 등급 이름.
    - 가장 긴 키부터 보고, 키와 정확히 같거나 키 뒤가 '/'로 이어질 때만 일치(경로 경계).
      예: 'dev.xmcda.store'는 'dev.xmcda.store/x'와 일치, 'dev.xmcda.store.evil.com'과는 불일치.
    - 없으면 None (임계값은 DEFAULT_THRESHOLD로 안전 처리). 옛 형식('/admin')이나 로그인 서버의
      평가('auth.xmcda.store/authorize')도 여기에 해당한다.
    """
    normalized = normalize_resource(resource_path)
    if not normalized:
        return None
    for key in sorted(RESOURCE_TIERS, key=len, reverse=True):
        if normalized == key or normalized.startswith(key + "/"):
            return RESOURCE_TIERS[key]
    return None


def get_resource_threshold(resource_path):
    """등급을 찾으면 그 등급의 임계값, 못 찾으면 DEFAULT_THRESHOLD(기존 동작과 동일)."""
    tier = get_resource_tier(resource_path)
    return TIER_THRESHOLDS[tier] if tier else DEFAULT_THRESHOLD

# [캐시 유효기간] "통과" 판정을 호출한 쪽(nginx 앞단 판단 서비스, zt_risk.py)이 몇 초 동안 다시
# 묻지 않고 재사용해도 되는지를 PDP(여기)가 정해서 응답(cache_ttl_seconds)에 실어 보낸다.
# 호출한 쪽은 이 값을 그대로 따르고 자기만의 등급표를 갖지 않는다 - 판정 기준과 같은 곳에서
# 관리하면 등급을 바꿀 때 한 군데만 고치면 된다. 숫자는 팀이 정한 값이며 표준에 근거가 있는 것이
# 아니다. 0이면 캐시하지 않고 매 요청마다 묻는다. 등급을 모르는 자원도 0(캐시 안 함).
TIER_CACHE_TTL_SECONDS = {
    "top_secret": 0,       # 관리자 콘솔, 감사 로그 API: 매 요청 검사
    "confidential": 90,    # 인사, 개발
    "internal": 300,       # 마케팅, 포털 공통
}


def seconds_until_night_boundary(now_ts):
    """지금(epoch 초)부터 다음 야간 경계(KST 06:00 또는 22:00)까지 남은 초.
    캐시가 이 경계를 넘어 살아 있으면 21:58에 받은 '통과'가 22:00 이후(야간)에도 쓰이는 빈틈이 생긴다."""
    kst = timezone(timedelta(hours=9))
    now_kst = datetime.fromtimestamp(now_ts, timezone.utc).astimezone(kst)
    boundaries = []
    for hour in (NIGHT_END_HOUR_KST, NIGHT_START_HOUR_KST):
        boundary = now_kst.replace(hour=hour, minute=0, second=0, microsecond=0)
        if boundary <= now_kst:
            boundary += timedelta(days=1)
        boundaries.append(boundary)
    return (min(boundaries) - now_kst).total_seconds()


def compute_cache_ttl(tier, allow_access, now_ts, mfa_expires_at=None):
    """허용 판정을 몇 초간 재사용해도 되는지(초). 허용이 아니면 0.
    min(등급별 캐시 시간, 다음 야간 경계까지 남은 시간, 재인증(MFA) 유효 시간이 남은 만큼)."""
    if not allow_access:
        return 0
    ttl = TIER_CACHE_TTL_SECONDS.get(tier, 0)
    if ttl <= 0:
        return 0
    ttl = min(ttl, seconds_until_night_boundary(now_ts))
    if mfa_expires_at is not None:
        # step-up 재인증 덕에 통과한 경우, 그 재인증 기록이 만료된 뒤까지 통과가 재사용되면 안 됨
        ttl = min(ttl, mfa_expires_at - now_ts)
    return max(0, int(ttl))


# 장애 시 정책 참고표 (Lambda/DynamoDB에 닿지 못해 판단 자체를 할 수 없을 때).
# [현재 동작] 전부 차단(fail_closed). Worker(A 계층, index.js)와 portal_app.py(B 계층) 모두
# 자원 등급과 무관하게, 판단을 못 하면 접근을 막는다. 이 표는 코드가 읽어서 쓰는 값이 아니라
# 현재 정책을 기록해 둔 참고용이다.
# [향후 과제] 등급별 차등(예: 낮은 등급은 fail_open)은 아직 적용하지 않았다. 도입하려면
# Worker와 portal_app.py 양쪽을 함께 바꿔야 하고, 입구(A)가 새 로그인을 막는 이상 효과는
# 이미 로그인된 세션(최대 15분)에 한정된다.
FAIL_POLICY = {
    "general": "fail_closed",
    "admin": "fail_closed",
}

# ==========================================================================
# [User Risk] 관리자가 풀어줄 때까지 유지되는 누적 위험 상태
#   - MFA를 통과해도 풀리지 않는 security 신호(resettable=False)가 "인증된 신원"에 걸리면 user_risk에 active로
#     저장하고, 이후 그 사람의 모든 판단에 같은 신호로 반영한다. 풀어주는 일은 risk_admin.py(전용 Lambda)만 한다.
#   - mfa_verified(짧은 수명의 "방금 MFA했다" 기록)와는 절대 합치지 않는다. 다른 층이다.
#   - 저장은 호출자가 persist_risk=true로 알린 경우에만 한다. 로그인 폼 같은 "아직 인증 전" 입력에서 나온 신호를
#     그 이메일 계정에 저장하면, 남의 이메일을 적어서 그 사람을 잠그는 공격이 가능해지기 때문이다.
# ==========================================================================
STICKY_SIGNALS = tuple(
    name for name, rule in RISK_MATRIX.items()
    if rule["group"] == "security" and rule.get("resettable") is False
)


def load_active_user_risk(identity):
    """이 사람에게 걸려 있는 active 신호 이름 목록. 조회 실패는 예외를 그대로 올린다(호출부가 fail-closed)."""
    resp = user_risk_table.query(
        KeyConditionExpression="#i = :i",
        ExpressionAttributeNames={"#i": "identity"},
        ExpressionAttributeValues={":i": identity},
    )
    return [
        item["signal"] for item in resp.get("Items", [])
        if item.get("status") == "active" and item.get("signal") in STICKY_SIGNALS
    ]


def persist_user_risk(identity, signals, source, now_ts):
    """새로 감지된 sticky 신호를 active로 저장. 이미 active면 last_seen만 갱신, 해제됐던 신호가 다시 감지되면 새로 active."""
    for signal in signals:
        key = {"identity": identity, "signal": signal}
        try:
            user_risk_table.update_item(
                Key=key,
                UpdateExpression="SET #st = :active, set_at = :now, last_seen = :now, #src = :src REMOVE released_by, released_at",
                ConditionExpression="attribute_not_exists(#st) OR #st <> :active",
                ExpressionAttributeNames={"#st": "status", "#src": "source"},
                ExpressionAttributeValues={":active": "active", ":now": now_ts, ":src": source},
            )
        except Exception as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code", "") if hasattr(e, "response") else ""
            if code == "ConditionalCheckFailedException" or "ConditionalCheckFailed" in str(e):
                try:
                    user_risk_table.update_item(
                        Key=key,
                        UpdateExpression="SET last_seen = :now",
                        ExpressionAttributeValues={":now": now_ts},
                    )
                except Exception as e2:
                    print("user_risk last_seen 갱신 실패:", str(e2))
            else:
                print("user_risk 저장 실패:", str(e))


def lambda_handler(event, context):
    # [보안] 예전에는 여기서 event 전체를 print했는데, event.headers에 x-evaluate-secret(공유비밀키)이
    # 그대로 들어 있어 비밀키가 CloudWatch Logs에 평문으로 남았다. event 원문은 절대 기록하지 않는다.
    # (판정 결과는 아래에서 DynamoDB와 [SOC_ALERT] 한 줄 로그로 남기며, 거기에는 비밀키가 없다.)

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

    # [step-up 재인증] 로그인 서버(auth_app.py)의 /stepup이 TOTP 재인증에 성공했을 때
    # 보내는 전용 호출. 위험점수는 계산하지 않고 "이 사용자가 방금 MFA를 통과했다"는
    # 사실만 기록한 뒤 바로 반환한다. User Risk(관리자가 풀어주는 누적 위험 상태)와는
    # 다른 층 - 이건 "인증이 얼마나 최근인가"만 나타내는 짧은 수명의 기록임.
    if body.get("mfa_reauth"):
        identity = body.get("identity", "unknown")
        now_ts = int(time.time())
        try:
            mfa_table.put_item(Item={
                "identity": identity,
                "verified_at": now_ts,
                "expires_at": now_ts + MFA_FRESHNESS_SECONDS,
            })
            recorded = True
        except Exception as e:
            print("mfa_verified 기록 실패:", str(e))
            recorded = False
        return {
            "statusCode": 200 if recorded else 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"recorded": recorded})
        }

    # [마지막 판단 조회] 로그인 서버 /stepup이 어떤 화면을 보여줄지 정할 때 부르는 전용 호출(점수 계산 없음)
    if body.get("decision_lookup"):
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(lookup_decision(body.get("identity"), body.get("resource_host")))
        }

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
            if kst_hour >= NIGHT_START_HOUR_KST or kst_hour < NIGHT_END_HOUR_KST:
                body["night_access"] = True
        except Exception as e:
            print("night_access 판정 중 시각 파싱 오류:", str(e))

    # unknown_location: Cloudflare Access가 제공하는 geo.country가 HOME_COUNTRY(KR)와
    # 다르면 위치 이상으로 판단. geo_country가 없는 경우(누락/알 수 없음)는 오탐 방지를
    # 위해 위험으로 간주하지 않음.
    geo_country = body.get("geo_country")
    if geo_country is not None and geo_country != HOME_COUNTRY:
        body["unknown_location"] = True

    # 기기 신뢰: WARP 기기 검사 결과/기기 주인 -> 신호 (Worker가 기기 정보를 넘긴 경우에만)
    device_detected = derive_device_signals(body)

    # --- User Risk: 이 사람에게 이미 걸려 있는 해제 불가 신호를 읽어 같은 신호로 반영 ---
    # 조회에 실패하면 걸려 있는지 알 수 없으므로 통과시키지 않는다(fail-closed, 500 -> 호출자는 차단 처리).
    risk_identity = body.get("identity")
    has_identity = bool(risk_identity) and risk_identity != "unknown"
    detected_sticky = [s for s in STICKY_SIGNALS if body.get(s)]
    stored_sticky = []
    if has_identity:
        try:
            stored_sticky = load_active_user_risk(risk_identity)
        except Exception as e:
            print("user_risk 조회 실패(fail-closed):", str(e))
            return {
                "statusCode": 500,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "user_risk_unavailable"})
            }
        for signal in stored_sticky:
            body[signal] = True

    risk_score = 0             # 0(완전 안전)에서 시작, 위험할수록 더함. 상한 없음
    reasons = []
    penalized_signals = []     # 실제로 위험도가 반영된 신호만 (조합규칙 판단용)
    security_penalty_applied = False
    current_time = int(time.time())
    security_mfa_passed = bool(body.get("security_mfa_passed"))
    if DEVICE_SIGNAL_MODE == "report":
        reasons.extend(f"{signal} (report-only, +0)" for signal in device_detected)

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
            if factor in stored_sticky and factor not in detected_sticky:
                reasons.append(f"user_risk_active:{factor}")

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

    # resource_path: 자원 식별자(호스트+경로). Worker(index.js)는 Access JWT의 request_url에서,
    # 앞단 판단 서비스(zt_risk.py)는 요청의 Host+경로에서 만들어 보낸다. 로그인 서버는 자기 주소를 보낸다.
    # 판단(어떤 임계값을 적용할지)은 여기(PDP)에서 전담 — Worker/PEP는 원본만 넘긴다는
    # 기존 원칙(night_access/unknown_location과 동일)을 그대로 따름.
    resource_path = body.get("resource_path")
    resource_threshold = get_resource_threshold(resource_path)
    resource_tier = get_resource_tier(resource_path)

    mfa_expires_at = None      # step-up 재인증 기록으로 통과한 경우에만 채움 (캐시 유효기간 계산용)

    # 4. 보안 위험이 걸린 세션은 MFA 재인증 전까지 무조건 차단
    if security_penalty_applied and not security_mfa_passed:
        allow_access = False
        action = "block_until_mfa"
    # 5. 경계구간(자원별 임계값 ~ +STEP_UP_MARGIN)은 즉시 차단 대신 Adaptive MFA 요구.
    #    단, 최근 MFA_FRESHNESS_SECONDS 이내에 /stepup에서 재인증한 기록이 있으면
    #    이미 최근성이 증명된 것으로 보고 통과시킨다.
    elif resource_threshold < risk_score <= resource_threshold + STEP_UP_MARGIN:
        identity = body.get("identity", "unknown")
        mfa_fresh = False
        if identity != "unknown":
            try:
                mfa_item = mfa_table.get_item(Key={"identity": identity}).get("Item")
                if mfa_item and mfa_item.get("expires_at", 0) > current_time:
                    mfa_fresh = True
            except Exception as e:
                print("mfa_verified 조회 실패:", str(e))

        if mfa_fresh:
            mfa_expires_at = int(mfa_item.get("expires_at"))   # DynamoDB는 숫자를 Decimal로 돌려줌
            allow_access = True
            action = "step_up_mfa_verified"
            reasons.append("recent_mfa_reauth_verified")
        else:
            allow_access = False
            action = "step_up_mfa_required"
            print(f"[SOC_ALERT] identity={body.get('identity','unknown')} risk_score={risk_score} resource_path={resource_path} threshold={resource_threshold} action={action}")
    else:
        allow_access = (risk_score <= resource_threshold)
        action = "allow" if allow_access else "block"

    # [기기 신호는 재인증으로 풀어 주지 않는다] TOTP는 "본인인가"를 확인할 뿐 "회사 기기인가"를 바꾸지 못한다.
    # 비밀번호+TOTP를 함께 피싱당하면 공격자 PC에서도 재인증이 통과되므로, 기기 신호 때문에 경계구간에 들어온
    # 경우는 재인증 대신 차단하고, 차단 화면에서 기기 사유와 푸는 방법(기기를 바꾸거나 방화벽을 켜기)을 보여준다.
    device_reasons = [s for s in DEVICE_SIGNALS if s in penalized_signals]
    if device_reasons and action in ("step_up_mfa_required", "step_up_mfa_verified"):
        allow_access = False
        action = "block_device"
        mfa_expires_at = None
        reasons.append("device_not_remediable_by_mfa")

    cache_ttl_seconds = compute_cache_ttl(resource_tier, allow_access, current_time, mfa_expires_at)

    # 마지막 판단 기록: Access가 막으면 사용자는 로그인 서버의 /stepup으로 오는데, 그 페이지는 왜 막혔는지 모른다.
    # 판단은 여기서 했으니, /stepup은 이 기록을 물어보고(decision_lookup) 재인증 화면과 차단 화면 중 하나를 고른다.
    # (예전에는 무조건 재인증 화면이라, 재인증으로 풀리지 않는 차단이면 재인증 -> 다시 차단이 반복됐다)
    if has_identity and body.get("source") != "login":
        save_decision(risk_identity, resource_path, action, device_reasons, current_time)

    # 새로 감지된 해제 불가 신호는 (인증된 신원이고 호출자가 허용한 경우에만) User Risk에 남긴다.
    if has_identity and detected_sticky and body.get("persist_risk") is True:
        persist_user_risk(risk_identity, detected_sticky, body.get("source", "A"), current_time)

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
                'resource_threshold': resource_threshold,
                # 호출 출처 구분(A=Worker/로그인서버, B=portal_app.py 세션 중 재확인) - 로그 조회/검증용
                'source': body.get('source', 'A')
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
            "device_reasons": device_reasons,
            "session_id": session_id,
            "resource_path": resource_path,
            "resource_threshold": resource_threshold,
            "resource_tier": resource_tier,
            "cache_ttl_seconds": cache_ttl_seconds
        })
    }
