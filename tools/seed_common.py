"""시드 이력 만들기 공통 부분: 계정 칸(slot)과 성향(persona), 출력 형식.

계정 칸은 Terraform이 실제 이메일로 바꿔 넣는다(baseline.tf local.seed_accounts):
  employee01~09 = 직원 이메일 앞부분, admin = 첫 번째 관리자. 비상 관리자는 평소 쓰지 않는 계정이라 시드 없음.
성향:
  night    : 밤 접속이 잦은 사람(야간 배포가 잦은 개발자 등) - 공통 규칙이면 매번 걸리던 사람
  day      : 낮에만 접속하는 사람 - 공통 규칙이면 21시 접속도 통과하던 사람
  traveler : 가끔 해외(출장)에서 접속하는 사람 - 공통 규칙이면 해외 접속마다 걸리던 사람
"""
import json

WINDOW_DAYS = 30
MAX_EVENTS_PER_SLOT = 150

SLOTS = [
    ("employee01", "night"),      # 개발팀: 야간 배포(시연 기본 계정)
    ("employee02", "day"),        # 개발팀
    ("employee03", "day"),        # 개발팀
    ("employee04", "night"),      # 개발팀
    ("employee05", "traveler"),   # 마케팅팀: 출장
    ("employee06", "day"),        # 마케팅팀
    ("employee07", "traveler"),   # 마케팅팀
    ("employee08", "day"),        # 인사팀
    ("employee09", "day"),        # 인사팀
    ("admin", "day"),             # 관리자
]

HOME_COUNTRY = "KR"
# 해외 접속 나라 바꿔 끼우기 순서(그 사람이 두 번째로 많이 쓴 나라 -> JP, 세 번째 -> US ...)
TRAVEL_COUNTRIES = ["JP", "US", "SG", "DE", "GB", "FR", "AU", "VN"]


def downsample(events, limit=MAX_EVENTS_PER_SLOT):
    """시간 순서를 유지한 채 고르게 줄인다(앞부분만 자르면 특정 날짜에 몰림)."""
    if len(events) <= limit:
        return list(events)
    step = len(events) / limit
    return [events[int(i * step)] for i in range(limit)]


def stats(events):
    n = len(events) or 1
    night = sum(1 for _, sec, _ in events if sec // 3600 >= 22 or sec // 3600 < 6) / n
    foreign = sum(1 for _, _, c in events if c != HOME_COUNTRY) / n
    return {"logins": len(events), "night_share": round(night, 3), "foreign_share": round(foreign, 3),
            "countries": sorted({c for _, _, c in events})}


def write_seed(path, origin, slots, meta):
    out = {"origin": origin, "window_days": WINDOW_DAYS, **meta, "slots": slots}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
        f.write("\n")
    return out
