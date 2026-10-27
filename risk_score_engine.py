import base64
import ipaddress
import json
import math
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import boto3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-2')
table = dynamodb.Table('risk_score_log')
mfa_table = dynamodb.Table('mfa_verified')
decision_table = dynamodb.Table('access_decision')   # 사용자+앱별 마지막 판단(재인증/차단 화면을 고르는 데 씀)
ip_reputation_table = dynamodb.Table('ip_reputation')   # AbuseIPDB 조회 결과 캐시(IP별 24시간)
device_state_table = dynamodb.Table('device_state')   # 기기 순찰(device_sweep)이 본 기기별 최신 상태
user_risk_table = dynamodb.Table('user_risk')   # 관리자가 풀어줄 때까지 유지되는 누적 위험 상태(mfa_verified와 별개)
ip_geolocation_table = dynamodb.Table('ip_geolocation')   # MaxMind 위치 조회 결과 캐시(IP별 24시간)
user_location_table = dynamodb.Table('user_location')     # 사용자별 마지막으로 '통과된' 접속 위치(이동 속도 비교용)


def log_event(event, **fields):
    """관제(ELK)용 구조화 로그 한 줄: "ZT_EVENT {json}". Lambda의 print는 CloudWatch Logs로 가고,
    Filebeat(aws-cloudwatch 입력)가 가져가 Logstash가 JSON으로 풀어 Elasticsearch에 넣는다.
    사람이 읽는 기존 [TAG] 로그는 그대로 두고, 기계가 읽을 줄을 따로 남긴다(키 이름이 서비스마다 같아야 대시보드/알림이 하나로 됨)."""
    record = {"event": event, "service": "pdp", "ts": int(time.time())}
    record.update({k: v for k, v in fields.items() if v is not None})
    print("ZT_EVENT " + json.dumps(record, ensure_ascii=False, default=str), flush=True)

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
#     아님을 보고서에 명시할 것. resettable=False 신호(threat_intel_match/waf_sqli/waf_attack,
#     최소값 86)는 여전히 임계값+마진(최대 80)을 초과해 "MFA 통과 후에도 확실히 차단" 원칙이 유지됨
RISK_MATRIX = {
    # --- behavioral: 시간 경과로 자동 회복 가능. 데이터셋(rba-dataset) 검증 완료(v9) ---
    "night_access": {"risk": 20, "group": "behavioral"},
    "unknown_location": {"risk": 40, "group": "behavioral"},

    # --- security: 자동 회복 불가, security_mfa_passed=True + resettable=True 인 경우만 리셋.
    #     배점은 OWASP Risk Rating Methodology(가능성×영향도) 기반(v9)에 2배 재설정(v10) ---
    "brute_force": {"risk": 58, "group": "security", "resettable": True},
    "threat_intel_match": {"risk": 86, "group": "security", "resettable": False},
    "waf_sqli": {"risk": 94, "group": "security", "resettable": False},
    # WAF(ModSecurity+CRS)가 막은 SQL 삽입 외 공격(XSS/RCE/LFI/RFI 등). 로그인한 사람이 앱 안에서 공격한 증거라
    # SQL 삽입과 같은 무게로 둔다. MFA로 풀리지 않고 관리자가 해제해야 한다(waf_sqli와 같은 이유).
    "waf_attack": {"risk": 94, "group": "security", "resettable": False},
    # [삭제] device_fingerprint_mismatch(76, 해제 불가): 처음 계획은 "서명된 기기 쿠키/브라우저 지문"을 직접 만드는 것이었으나
    #   WARP 기기 검사(device_unmanaged/device_owner_mismatch/device_posture_failed)로 대체했다. 이 신호를 보내는 곳이
    #   한 군데도 없어 판단에 쓰인 적이 없었고, 이름만 남아 있으면 "기기 지문을 구현했다"로 오해되므로 지웠다.

    # --- device: 기기 신뢰(WARP 기기 검사, Cloudflare가 검사하고 결과를 Access 신원 정보로 넘겨줌) ---
    #     MFA로 기기 상태가 바뀌지는 않지만, 경계구간에서는 최근 재인증(step-up)으로 통과할 수 있게 behavioral로 둔다
    #     (관리자 해제가 필요한 sticky 신호로 두면 개인 PC/공용 PC를 쓰는 정상 직원이 계속 막힘).
    #     45점 = 내부(60) 통과 / 기밀(40) 재인증 / 최고기밀(20) 차단. 팀 판단 수치(표준 근거 없음) - 보고서에 명시.
    "device_unmanaged": {"risk": 45, "group": "behavioral"},       # WARP 미등록/미연결 기기(기기 정보 없음)
    # 회사 기기인 건 확인됐고 관리 상태(방화벽)가 나쁜 것 -> 공격보다 관리 소홀일 가능성이 커서 낮게 둔다.
    #   25점: 내부(60)/기밀(40) 통과, 최고기밀(20)만 걸림(기기 신호라 재인증 없이 차단 + "방화벽을 켜세요")
    "device_posture_failed": {"risk": 25, "group": "behavioral"},  # 등록 기기지만 필수 기기 검사(방화벽) 실패/결과 없음
    "device_owner_mismatch": {"risk": 45, "group": "behavioral"},  # 기기 등록 사용자 != 로그인한 사람

    # --- network: 접속 IP 평판(AbuseIPDB) ---
    # anonymous_network: Tor 출구 IP. 접속 위치를 숨기는 익명 네트워크라 정상 직원이 쓸 이유가 드묾.
    #   Microsoft Entra ID도 "Anonymous IP address"(Tor/익명 VPN)를 로그인 위험으로 보고 기본 정책은 MFA 요구다.
    #   40점 = 내부(60) 통과 / 기밀(40)·최고기밀(20)은 경계구간 -> 재인증(TOTP). 팀 판단 수치.
    #   데이터센터/호스팅 IP는 신호로 쓰지 않는다: WARP를 켜면 접속 IP가 Cloudflare 것으로 바뀌어(실측: IPv4 -> IPv6)
    #   정상 관리 기기가 모두 걸린다.
    "anonymous_network": {"risk": 40, "group": "behavioral"},

    # --- session: 세션(출입증)이 다른 곳으로 옮겨진 흔적 = 쿠키 탈취 의심 ---
    # session_country_change: Access 토큰의 country(로그인한 나라) != 지금 요청 나라(CF-IPCountry).
    #   점수와 상관없이 "다시 로그인"을 요구한다(아래 session_reauth_required). 정상 사용자는 비밀번호+TOTP로 다시 들어오면
    #   새 토큰에 지금 나라가 찍혀 풀리고, 쿠키만 훔친 사람은 다시 로그인할 수 없다(Okta Session protection과 같은 대응).
    "session_country_change": {"risk": 60, "group": "behavioral"},

    # --- 이동 속도(MaxMind GeoLite 위치) ---
    # geo_velocity: 마지막으로 통과된 접속 위치 -> 지금 위치를 비행기보다 빠르게 이동(불가능한 이동) = 같은 계정을 다른 사람이 쓰는 흔적.
    #   Microsoft Entra ID Protection의 "Atypical travel"(로그인 위험, 실시간)과 같은 개념(두 로그인 사이 시간 vs 이동에 걸리는 시간).
    #   GeoIP 오차·VPN 때문에 정상 사용자도 걸릴 수 있어 증거가 아니라 의심으로 보고 behavioral, unknown_location과 같은 40점
    #   (내부·기밀 통과 / 최고기밀 재인증, 해외 신호와 겹치면 80점 -> 기밀 이상 차단·포털 재인증). 재인증에 성공하면 그 위치가 새 기준이 된다.
    "geo_velocity": {"risk": 40, "group": "behavioral"},
}

# [조합 규칙] 신호 두 개가 함께 걸리면 따로 볼 때보다 위험하다고 보고 가산한다.
#   지금 배점에서는 40~45점짜리 behavioral 신호 두 개만 겹쳐도 80점 이상이라 대부분 이미 차단 구간이고,
#   security 신호(86~94점)가 들어간 조합은 단독으로도 차단이다. 그래서 아래 규칙들은 판정(통과/재인증/차단)을 바꾸기보다
#   점수(관제 우선순위)를 올리는 역할이다. 판정을 실제로 바꾸는 조합은 아래 interaction_night_geo_velocity 하나다.
#   검토 후 넣지 않은 조합: geo_velocity + 기기 신호(이미 85점 이상 차단), anonymous_network + 기기 신호(같은 이유),
#   brute_force + waf_sqli(waf_sqli 단독 94점 차단, 두 신호가 로그인 화면/앱 안이라 한 판단에 같이 잡히지 않음).
COMBINATION_RULES = [
    (("unknown_location", "waf_sqli"), 30, "interaction_location_waf"),
    # 해외에서 남의 기기로 접속 = 계정 탈취 후 다른 장비 사용 가능성이 높은 조합
    (("unknown_location", "device_owner_mismatch"), 20, "interaction_location_device_owner"),
    (("brute_force", "threat_intel_match"), 20, "interaction_bruteforce_threatintel"),
    # 야간 + 불가능한 이동: 근무 시간 밖에 "다른 곳에 있는 누군가"가 같은 계정을 쓰는 전형적인 계정 탈취 패턴.
    #   따로 보면 20 + 40 = 60점(기밀 재인증, 포털 통과)이지만, 두 의심이 겹치면 우연일 가능성이 작아진다고 보고 +20 -> 80점
    #   (기밀 차단, 포털 재인증). Microsoft Entra ID Protection도 여러 탐지가 겹치면 위험 수준을 올린다(팀 판단 수치).
    (("night_access", "geo_velocity"), 20, "interaction_night_geo_velocity"),
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
    f"kibana.{DOMAIN_NAME}": "top_secret",   # 관제 콘솔(전 직원 로그인 기록이 모이는 곳이라 관리자 콘솔과 같은 등급)
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

# [세션 바인딩 스위치] 세션 도중 위치/네트워크가 바뀌는 것을 탈취로 볼지(오탐 위험이 있어 상용 제품도 모드를 나눔:
#   Okta Session protection의 Monitoring/Enforced, Microsoft CAE strict location은 소수 시험 후 적용 권고).
#   enforce: 감지하면 다시 로그인 요구 / report: 로그(reasons)에만 report-only로 / off: 계산 안 함. 알 수 없는 값은 enforce.
SESSION_SIGNALS = ("session_country_change",)
SESSION_BINDING_MODE = os.environ.get("SESSION_BINDING_MODE", "enforce").strip().lower()
if SESSION_BINDING_MODE not in ("enforce", "report", "off"):
    SESSION_BINDING_MODE = "enforce"
_COUNTRY_RE = re.compile(r"^[A-Z][A-Z0-9]$")   # ISO 국가 코드 + Cloudflare 특수 코드(T1 = Tor)


def derive_session_signals(body):
    """웹 서버 앞단이 넘긴 session_country(토큰의 로그인 나라)와 geo_country(지금 요청 나라)를 비교한다.
    감지한 신호 목록을 돌려주고, enforce일 때만 body에 넣어 판단에 반영한다.
    XX(알 수 없음)처럼 나라 코드가 아니면 비교하지 않는다. T1(Tor)은 Cloudflare가 쓰는 특수 코드라 비교 대상에 넣는다."""
    if SESSION_BINDING_MODE == "off":
        return []
    login_country = str(body.get("session_country") or "").strip().upper()
    current = str(body.get("geo_country") or "").strip().upper()
    if not _COUNTRY_RE.match(login_country) or not _COUNTRY_RE.match(current) or "XX" in (login_country, current):
        return []
    detected = ["session_country_change"] if login_country != current else []
    if SESSION_BINDING_MODE == "enforce":
        for signal in detected:
            body[signal] = True
    if detected:
        print(f"[SESSION_BINDING] identity={body.get('identity')} login_country={login_country} current={current} mode={SESSION_BINDING_MODE}")
    return detected
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
        # 순찰 대상 등록: 이 기기로 이 사람이 지금 우리 앱을 쓰고 있다(30분 유효, 정문 판단 때마다 갱신)
        mark_device_active(str(device_id), body.get("identity"), int(time.time()))
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
#   무엇을: "지금 우리 앱을 쓰고 있는 기기"만 본다. 정문(A) 판단 때 기기 ID와 사용자를 기록하고(mark_device_active)
#       30분 유효시간을 붙인다. Access 세션은 15분마다 새로 받으므로 계속 쓰는 동안은 갱신되고, 안 쓰면 빠진다.
#       쓰지 않는 기기를 감시하는 것은 기기 관리 도구(MDM)의 일이지 접근 제어의 일이 아니다.
#   어떻게: 정상 -> 나쁨(방화벽 꺼짐 / WARP 연결 끊김 / 상태 정보 없음)으로 "바뀐" 기기를 찾으면, 그 기기로
#       들어온 사용자의 Access 세션을 끊는다(revoke_user). 다시 들어오면 Access -> External Evaluation -> 이 엔진이
#       최신 상태(sweep_signal_for)까지 보고 다시 판단한다. 판단은 엔진, Cloudflare는 끊기만 한다.
#       (실무의 "상태가 바뀌면 세션을 끊고 재평가" 방식 - Microsoft CAE, OpenID CAEP와 같은 구조, 수신만 polling)
#   끊기는 바뀐 순간 한 번만: 나쁜 상태가 계속될 때마다 끊으면 포털(통과 대상)도 못 쓰게 된다.
#   API 오류(429/5xx/네트워크)는 "모름"으로 보고 상태를 바꾸지 않는다(장애로 전원 세션이 끊기지 않게).
#   별도 Lambda(device-sweep)로 실행하며, 세션 끊기 토큰은 그 함수에만 있다(인터넷에 열린 판단 함수에는 없음).
#   한계: 순찰 대상을 테이블 전체 조회(Scan)로 읽는다. 소규모 실증 기준이며, 대규모라면 인덱스(GSI)로 바꾼다.
# ==========================================================================
DEVICE_ACTIVE_SECONDS = 1800         # 정문 판단 후 이 시간 동안 "사용 중 기기"로 순찰(Access 세션 15분의 2배)
SWEEP_STATE_FRESH_SECONDS = 600      # 판단 때 순찰 결과를 믿는 시간(순찰이 멈췄으면 옛 결과로 막지 않음)
SWEEP_RECORD_TTL_SECONDS = 86400     # 사용이 끝난 뒤 기록을 지우기까지(TTL)
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


def mark_device_active(device_id, identity, now):
    """정문 판단 때: 이 기기로 이 사람이 들어왔음을 기록(순찰 대상). 순찰 결과 필드는 건드리지 않는다."""
    identity = str(identity or "").strip().lower()
    if not _DEVICE_ID_RE.match(device_id or "") or not identity or identity == "unknown":
        return
    try:
        device_state_table.update_item(
            Key={"device_id": device_id, "identity": identity},
            UpdateExpression="SET #a = :a, #e = :e",
            ExpressionAttributeNames={"#a": "active_until", "#e": "expires_at"},
            ExpressionAttributeValues={":a": now + DEVICE_ACTIVE_SECONDS,
                                       ":e": now + DEVICE_ACTIVE_SECONDS + SWEEP_RECORD_TTL_SECONDS})
    except Exception as e:
        print("device_state 사용 기록 실패:", str(e))


def list_active_devices(now):
    """사용 중인 (기기, 사용자) 기록: [item, ...]"""
    items, kwargs = [], {"FilterExpression": "#a > :n", "ExpressionAttributeNames": {"#a": "active_until"},
                         "ExpressionAttributeValues": {":n": now}}
    while True:
        resp = device_state_table.scan(**kwargs)
        items.extend(resp.get("Items") or [])
        if not resp.get("LastEvaluatedKey"):
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


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
        items = device_state_table.query(KeyConditionExpression="#d = :d",
                                         ExpressionAttributeNames={"#d": "device_id"},
                                         ExpressionAttributeValues={":d": device_id}).get("Items") or []
    except Exception as e:
        print("device_state 조회 실패:", str(e))
        return None
    now = int(time.time())
    fresh = [i for i in items if i.get("sweep_state") in ("ok", "bad") and now - int(i.get("checked_at", 0)) <= SWEEP_STATE_FRESH_SECONDS]
    if not fresh:
        return None
    latest = max(fresh, key=lambda i: int(i.get("checked_at", 0)))     # 기기 상태는 사용자와 무관 - 가장 최근 결과
    return SWEEP_REASON_SIGNAL.get(latest.get("reason")) if latest.get("sweep_state") == "bad" else None


def device_sweep(now=None):
    """기기 순찰 1회. 확인한 기기 수/끊은 사용자 등을 돌려준다(로그·테스트용)."""
    now = int(now or time.time())
    summary = {"active": 0, "checked": 0, "bad": 0, "revoked": [], "unknown": 0, "mode": DEVICE_SIGNAL_MODE}
    if DEVICE_SIGNAL_MODE == "off" or not (CF_ACCOUNT_ID and CF_DEVICE_API_TOKEN):
        return summary
    try:
        records = list_active_devices(now)
    except Exception as e:
        print("[DEVICE_SWEEP_LIST_FAILED]", str(e))
        summary["unknown"] = -1
        return summary
    summary["active"] = len(records)
    status_cache = {}
    for rec in records:
        device_id, email = str(rec.get("device_id", "")), str(rec.get("identity", ""))
        if not _DEVICE_ID_RE.match(device_id) or not email:
            continue
        if device_id not in status_cache:       # 한 기기를 여러 사람이 쓰면 상태 조회는 한 번만
            try:
                data = _cf_get(f"/dex/devices/{device_id}/fleet-status/live?since_minutes=10", CF_DEVICE_API_TOKEN)
                status_cache[device_id] = classify_fleet_status((data or {}).get("result"))
            except CloudflareApiUnavailable as e:
                print("[DEVICE_SWEEP_STATUS_UNKNOWN]", device_id, str(e))
                status_cache[device_id] = "unknown"
        reason = status_cache[device_id]
        if reason == "unknown":
            summary["unknown"] += 1
            continue
        summary["checked"] += 1
        # 이미 끊은 기록은 "나쁨이 이어지는 동안"만 유지한다. 정상으로 돌아오면 지워서, 다시 나빠지면 또 끊는다.
        revoked = bool(rec.get("revoked")) if (reason and rec.get("sweep_state") == "bad") else False
        if reason:
            summary["bad"] += 1
            # 정상 -> 나쁨으로 바뀌었거나, 지난번 끊기에 실패했으면 이번에 끊는다(나쁜 동안 반복해서 끊지 않음)
            if not revoked:
                if DEVICE_SIGNAL_MODE == "enforce":
                    revoked = revoke_access_sessions(email)
                    action = "device_session_revoked" if revoked else "device_session_revoke_failed"
                    if revoked:
                        summary["revoked"].append(email)
                else:
                    revoked = True          # report: 끊지는 않고 "끊었을 것"만 한 번 기록
                    action = "device_session_revoke_report_only"
                try:
                    table.put_item(Item={"session_id": str(uuid.uuid4()), "timestamp": now, "risk_score": 0,
                                         "reasons": [f"device_sweep:{reason}"], "allow": False, "action": action,
                                         "identity": email, "resource_path": "all-apps", "resource_threshold": 0,
                                         "source": "sweep"})
                except Exception as e:
                    print("DynamoDB logging failed:", str(e))
                print(f"[DEVICE_SWEEP] identity={email} device={device_id} reason={reason} action={action}")
                log_event("device_sweep", identity=email, device_id=device_id, reason=reason, action=action)
        try:
            # 순찰 결과 필드만 갱신(정문 판단이 같은 순간 active_until을 갱신해도 덮어쓰지 않게)
            device_state_table.update_item(
                Key={"device_id": device_id, "identity": email},
                UpdateExpression="SET #s = :s, #r = :r, #c = :c, #v = :v",
                ExpressionAttributeNames={"#s": "sweep_state", "#r": "reason", "#c": "checked_at", "#v": "revoked"},
                ExpressionAttributeValues={":s": "bad" if reason else "ok", ":r": reason or "", ":c": now, ":v": revoked})
        except Exception as e:
            print("device_state 기록 실패:", str(e))
    return summary


def device_sweep_handler(event, context):
    """EventBridge(1분 일정)가 부르는 진입점. 인터넷(API Gateway)에서는 부를 수 없다(별도 Lambda)."""
    summary = device_sweep()
    print("[DEVICE_SWEEP_SUMMARY]", json.dumps(summary))
    return summary


# ==========================================================================
# [위협 IP] AbuseIPDB(전 세계 공격 신고로 만든 공개 IP 평판 DB) 조회 -> threat_intel_match / anonymous_network
#   - 신고가 많아 위험 점수(abuseConfidenceScore, 0~100)가 기준 이상이면 threat_intel_match(86점, security).
#     그 요청(세션)만 막고 사람에게 영구 표시는 하지 않는다(persist_risk를 보내지 않음). IP는 카페 와이파이처럼
#     남이 오염시킨 것일 수 있어서, 관리자 해제 전까지 계속 막으면 정상 직원이 억울하게 막힌다.
#     Microsoft Entra ID도 "Malicious IP address"를 사용자 위험이 아니라 로그인(세션) 위험으로 분류한다.
#   - Tor 출구 IP면 anonymous_network(40점).
#   - 무료 계정은 하루 1,000회 조회 제한 -> IP별 결과를 DynamoDB(ip_reputation)에 24시간 저장해 재사용.
#   - 조회 실패(장애/한도 초과)는 신호 없이 판단(fail-open): 보조 신호라 외부 서비스 장애로 전원을 막지 않는다.
#     실패도 5분간 기억해 장애 중에 요청마다 다시 부르지 않는다.
#   - 사설/루프백/예약 주소는 조회하지 않는다(공개 평판이 없음).
# ==========================================================================
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
THREAT_INTEL_MIN_SCORE = int(os.environ.get("THREAT_INTEL_MIN_SCORE", "50"))
IP_REPUTATION_TTL_SECONDS = 86400
IP_REPUTATION_FAILURE_TTL_SECONDS = 300
ABUSEIPDB_MAX_AGE_DAYS = 90


def normalize_public_ip(value):
    """조회할 만한 공개 IP면 표준 표기 문자열, 아니면 None."""
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return None
    return ip.compressed


def _query_abuseipdb(ip):
    """AbuseIPDB CHECK. 성공하면 {"score": int, "is_tor": bool}, 실패하면 None."""
    url = ("https://api.abuseipdb.com/api/v2/check?" +
           urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": ABUSEIPDB_MAX_AGE_DAYS}))
    req = urllib.request.Request(url, headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode()).get("data") or {}
        score = data.get("abuseConfidenceScore")
        if isinstance(score, bool) or not isinstance(score, int):
            return None
        return {"score": max(0, min(100, score)), "is_tor": data.get("isTor") is True}
    except Exception as e:
        print("[THREAT_INTEL_LOOKUP_FAILED]", type(e).__name__)
        return None


def ip_reputation(ip, now=None):
    """캐시 -> 없으면 AbuseIPDB 조회 후 저장. {"score","is_tor"} 또는 None(모름)."""
    now = int(now or time.time())
    try:
        item = ip_reputation_table.get_item(Key={"ip": ip}).get("Item")
    except Exception as e:
        print("ip_reputation 조회 실패:", str(e))
        item = None
    if item and int(item.get("expires_at", 0)) > now:
        if item.get("status") != "ok":
            return None
        return {"score": int(item.get("score", 0)), "is_tor": bool(item.get("is_tor"))}
    if not ABUSEIPDB_API_KEY:
        return None
    result = _query_abuseipdb(ip)
    record = {"ip": ip, "checked_at": now}
    if result:
        record.update(status="ok", score=result["score"], is_tor=result["is_tor"], expires_at=now + IP_REPUTATION_TTL_SECONDS)
    else:
        record.update(status="unknown", expires_at=now + IP_REPUTATION_FAILURE_TTL_SECONDS)
    try:
        ip_reputation_table.put_item(Item=record)
    except Exception as e:
        print("ip_reputation 저장 실패:", str(e))
    return result


_NOT_LOOKED_UP = object()


def derive_ip_signals(body, rep=_NOT_LOOKED_UP):
    """body["client_ip"] -> threat_intel_match / anonymous_network. 감지한 신호 이름 목록.
    rep: 이미 조회한 평판 결과(lookup_ip_context가 위치 조회와 동시에 조회한 것). 없으면 여기서 조회한다."""
    ip = normalize_public_ip(body.get("client_ip"))
    if not ip:
        return []
    if rep is _NOT_LOOKED_UP:
        rep = ip_reputation(ip)
    if not rep:
        return []
    detected = []
    if rep["score"] >= THREAT_INTEL_MIN_SCORE:
        detected.append("threat_intel_match")
    if rep["is_tor"]:
        detected.append("anonymous_network")
    for signal in detected:
        body[signal] = True
    if detected:
        print(f"[THREAT_INTEL] ip={ip} score={rep['score']} tor={rep['is_tor']} signals={','.join(detected)}")
    return detected


# ==========================================================================
# [이동 속도(geo_velocity)] MaxMind GeoLite 웹 조회(geolite.info)로 IP -> 위도/경도/오차 반경(km)을 얻고,
#   이 사람이 마지막으로 "통과된" 위치와 비교해 비행기보다 빠르게 움직였으면 신호를 만든다.
#   - 웹 조회 방식(B): 무료 계정 하루 1,000회. 같은 IP는 24시간 캐시(ip_geolocation)해서 조회 수를 줄인다.
#     규모가 커지면 GeoLite2 데이터 파일(다운로드, 새 버전 나오면 30일 안에 갱신 의무) 방식으로 전환한다(보고서에 명시).
#   - 거리 = 두 지점의 대권 거리 - 두 위치의 오차 반경 합(GeoIP 오차로 생기는 오탐을 줄임).
#     500km 미만이면 비교하지 않는다(국내 이동/IPv4<->IPv6 전환 등 GeoIP 흔들림). 오차 반경이 500km 넘는 위치(나라 수준)도 비교하지 않는다.
#   - 속도 1,000km/h 초과 = 여객기 순항 속도(약 900km/h)보다 빠름 -> 불가능한 이동.
#   - 위치 기록은 통과(allow)된 판단에서만 갱신한다. 막힌 시도의 위치까지 기록하면 공격자가 해외에서 한 번 시도한 것만으로
#     진짜 주인의 다음 접속이 "불가능한 이동"이 된다. 재인증에 성공하면 통과이므로 그 위치가 새 기준이 된다.
#   - ASN(통신사) 비교는 향후 과제: 무료 웹 조회 응답에 들어 있는지 미확인 + 와이파이<->휴대폰 데이터 전환마다 오탐.
#   스위치(GEO_VELOCITY_MODE): enforce(점수 반영) / report(로그에만 report-only) / off(조회도 안 함). 알 수 없는 값은 enforce.
# ==========================================================================
MAXMIND_ACCOUNT_ID = os.environ.get("MAXMIND_ACCOUNT_ID", "")
MAXMIND_LICENSE_KEY = os.environ.get("MAXMIND_LICENSE_KEY", "")
GEO_VELOCITY_MODE = os.environ.get("GEO_VELOCITY_MODE", "enforce").strip().lower()
if GEO_VELOCITY_MODE not in ("enforce", "report", "off"):
    GEO_VELOCITY_MODE = "enforce"
GEO_SIGNALS = ("geo_velocity",)
GEO_LOOKUP_TTL_SECONDS = 86400
GEO_LOOKUP_FAILURE_TTL_SECONDS = 300
GEO_VELOCITY_MAX_KMH = 1000
GEO_VELOCITY_MIN_DISTANCE_KM = 500
GEO_MAX_ACCURACY_RADIUS_KM = 500
GEO_MIN_ELAPSED_SECONDS = 60          # 1분보다 짧은 간격은 1분으로 계산(0으로 나누기 방지, 같은 순간 두 요청)
EARTH_RADIUS_KM = 6371.0
USER_LOCATION_RETENTION_SECONDS = 30 * 86400


def _query_maxmind(ip):
    """GeoLite City 웹 조회. 성공하면 {"lat","lon","radius","country"}, 위치가 없거나 실패하면 None."""
    url = "https://geolite.info/geoip/v2.1/city/" + urllib.parse.quote(ip, safe="")
    cred = base64.b64encode(f"{MAXMIND_ACCOUNT_ID}:{MAXMIND_LICENSE_KEY}".encode()).decode()
    req = urllib.request.Request(url, headers={"Authorization": "Basic " + cred, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode())
        loc = data.get("location") or {}
        lat, lon, radius = loc.get("latitude"), loc.get("longitude"), loc.get("accuracy_radius")
        if not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in (lat, lon, radius)):
            return None
        if not (-90 <= lat <= 90 and -180 <= lon <= 180 and radius >= 0):
            return None
        country = str((data.get("country") or {}).get("iso_code") or "")
        return {"lat": float(lat), "lon": float(lon), "radius": int(radius), "country": country}
    except Exception as e:
        print("[GEO_LOOKUP_FAILED]", type(e).__name__)
        return None


def ip_geolocation(ip, now=None):
    """캐시 -> 없으면 MaxMind 조회 후 저장. {"lat","lon","radius","country"} 또는 None(모름)."""
    now = int(now or time.time())
    if GEO_VELOCITY_MODE == "off" or not (MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY):
        return None
    try:
        item = ip_geolocation_table.get_item(Key={"ip": ip}).get("Item")
    except Exception as e:
        print("ip_geolocation 조회 실패:", str(e))
        item = None
    if item and int(item.get("expires_at", 0)) > now:
        if item.get("status") != "ok":
            return None
        # DynamoDB는 숫자를 Decimal로 돌려주고 float 저장을 못 하므로 좌표는 문자열로 저장한다
        return {"lat": float(item["lat"]), "lon": float(item["lon"]), "radius": int(item["radius"]),
                "country": item.get("country", "")}
    result = _query_maxmind(ip)
    record = {"ip": ip, "checked_at": now}
    if result:
        record.update(status="ok", lat=f"{result['lat']:.4f}", lon=f"{result['lon']:.4f}", radius=result["radius"],
                      country=result["country"], expires_at=now + GEO_LOOKUP_TTL_SECONDS)
    else:
        record.update(status="unknown", expires_at=now + GEO_LOOKUP_FAILURE_TTL_SECONDS)
    try:
        ip_geolocation_table.put_item(Item=record)
    except Exception as e:
        print("ip_geolocation 저장 실패:", str(e))
    return result


def lookup_ip_context(body):
    """client_ip의 평판(AbuseIPDB)과 위치(MaxMind)를 동시에 조회한다(둘 다 캐시가 없으면 외부 호출 2개를 병렬로:
    호출자 timeout이 3초라 차례로 부르면 최악 4초가 된다). 공개 IP가 아니면 (None, None)."""
    ip = normalize_public_ip(body.get("client_ip"))
    if not ip:
        return None, None
    with ThreadPoolExecutor(max_workers=2) as pool:
        rep_future = pool.submit(ip_reputation, ip)
        geo_future = pool.submit(ip_geolocation, ip)
        return rep_future.result(), geo_future.result()


def distance_km(a, b):
    """두 지점의 대권 거리(haversine, km)."""
    lat1, lon1, lat2, lon2 = map(math.radians, (a["lat"], a["lon"], b["lat"], b["lon"]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(h)))


def load_last_location(identity):
    try:
        item = user_location_table.get_item(Key={"identity": identity}).get("Item")
    except Exception as e:
        print("user_location 조회 실패:", str(e))
        return None
    if not item:
        return None
    try:
        return {"lat": float(item["lat"]), "lon": float(item["lon"]), "radius": int(item["radius"]),
                "seen_at": int(item["seen_at"]), "country": item.get("country", "")}
    except Exception:
        return None


def save_last_location(identity, geo, ip, now):
    try:
        user_location_table.put_item(Item={
            "identity": identity, "lat": f"{geo['lat']:.4f}", "lon": f"{geo['lon']:.4f}", "radius": geo["radius"],
            "country": geo.get("country", ""), "ip": ip, "seen_at": int(now),
            # 위치는 개인정보라 필요한 만큼만 둔다: 30일 지난 기록은 TTL로 지운다(비교 기준이 없으면 신호를 만들지 않음)
            "expires_at": int(now) + USER_LOCATION_RETENTION_SECONDS,
        })
    except Exception as e:
        print("user_location 저장 실패:", str(e))


def derive_geo_signals(body, geo, now=None):
    """마지막 통과 위치와 지금 위치(geo)로 불가능한 이동을 판단. 감지한 신호 목록. enforce일 때만 body에 넣는다."""
    identity = body.get("identity")
    if GEO_VELOCITY_MODE == "off" or not geo or not identity or identity == "unknown":
        return []
    if geo["radius"] > GEO_MAX_ACCURACY_RADIUS_KM:
        return []
    last = load_last_location(identity)
    if not last or last["radius"] > GEO_MAX_ACCURACY_RADIUS_KM:
        return []
    now = int(now or time.time())
    km = distance_km(last, geo) - last["radius"] - geo["radius"]
    if km < GEO_VELOCITY_MIN_DISTANCE_KM:
        return []
    hours = max(now - last["seen_at"], GEO_MIN_ELAPSED_SECONDS) / 3600
    kmh = km / hours
    if kmh <= GEO_VELOCITY_MAX_KMH:
        return []
    if GEO_VELOCITY_MODE == "enforce":
        body["geo_velocity"] = True
    print(f"[GEO_VELOCITY] identity={identity} from={last['country'] or '-'} to={geo['country'] or '-'} "
          f"distance_km={int(km)} elapsed_min={int((now - last['seen_at']) / 60)} speed_kmh={int(kmh)} mode={GEO_VELOCITY_MODE}")
    return ["geo_velocity"]


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

    # 엔진이 직접 계산하고 모드 스위치(enforce/report/off)가 있는 신호는 호출자가 body에 넣어 보내도 버린다.
    # (그대로 두면 report/off 모드에서도 호출자가 보낸 값이 점수에 들어가 스위치가 무력해진다)
    for signal in DEVICE_SIGNALS + SESSION_SIGNALS + GEO_SIGNALS:
        body.pop(signal, None)

    # 기기 신뢰: WARP 기기 검사 결과/기기 주인 -> 신호 (Worker가 기기 정보를 넘긴 경우에만)
    device_detected = derive_device_signals(body)

    # 접속 IP 평판(AbuseIPDB)과 위치(MaxMind): 로그인 서버/웹 서버 앞단이 넘긴 client_ip가 있을 때만(둘을 동시에 조회)
    ip_rep, ip_geo = lookup_ip_context(body)
    derive_ip_signals(body, ip_rep)
    geo_detected = derive_geo_signals(body, ip_geo)

    # 세션 바인딩: 로그인한 나라와 지금 나라 비교(웹 서버 앞단이 Access 토큰의 country를 넘긴 경우만)
    session_detected = derive_session_signals(body)

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
    if SESSION_BINDING_MODE == "report":
        reasons.extend(f"{signal} (report-only, +0)" for signal in session_detected)
    if GEO_VELOCITY_MODE == "report":
        reasons.extend(f"{signal} (report-only, +0)" for signal in geo_detected)

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

    # [세션 바인딩] 출입증이 다른 곳에서 쓰이는 흔적이면 점수와 상관없이 "다시 로그인"을 요구한다.
    # TOTP 재인증은 같은 출입증(같은 country)을 그대로 쓰므로 풀리지 않는다 -> 처음부터 다시 로그인해 새 토큰을 받아야 함.
    if any(s in penalized_signals for s in SESSION_SIGNALS):
        allow_access = False
        action = "session_reauth_required"
        mfa_expires_at = None
        reasons.append("session_reauth_required")

    cache_ttl_seconds = compute_cache_ttl(resource_tier, allow_access, current_time, mfa_expires_at)

    # 마지막 판단 기록: Access가 막으면 사용자는 로그인 서버의 /stepup으로 오는데, 그 페이지는 왜 막혔는지 모른다.
    # 판단은 여기서 했으니, /stepup은 이 기록을 물어보고(decision_lookup) 재인증 화면과 차단 화면 중 하나를 고른다.
    # (예전에는 무조건 재인증 화면이라, 재인증으로 풀리지 않는 차단이면 재인증 -> 다시 차단이 반복됐다)
    if has_identity and body.get("source") != "login":
        save_decision(risk_identity, resource_path, action, device_reasons, current_time)

    # 이동 속도 기준점: 통과된 판단의 위치만 "마지막 위치"로 남긴다(막힌 시도의 위치는 남기지 않음 - 위 geo_velocity 설명)
    if allow_access and has_identity and ip_geo:
        save_last_location(risk_identity, ip_geo, normalize_public_ip(body.get("client_ip")), current_time)

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

    log_event("decision", identity=body.get("identity", "unknown"), action=action, allow=allow_access, score=risk_score,
              signals=penalized_signals, reasons=reasons, resource=resource_path or "unknown", tier=resource_tier,
              threshold=resource_threshold, source=body.get("source", "A"),
              client_ip=normalize_public_ip(body.get("client_ip")), country=body.get("geo_country"), session_id=session_id)

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
