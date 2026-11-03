"""가정 패턴(synthetic) 시드 만들기. RBA 데이터셋에서 뽑기 전까지 쓰는 임시 시드다.

실행: python tools/synthetic_seed.py   (seed/login_seed.json을 덮어씀, origin=synthetic)
  - 같은 결과가 나오도록 난수 시드를 고정한다.
  - 보고서에는 "가정 패턴"이라고 적어야 한다. RBA 데이터셋에서 뽑은 시드(tools/rba_seed_extract.py, origin=rba)로
    바꾸면 이 파일은 더 이상 쓰지 않는다.
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from seed_common import SLOTS, WINDOW_DAYS, HOME_COUNTRY, downsample, stats, write_seed  # noqa: E402

PATTERNS = {
    # (평일 하루 접속 횟수 범위, 시간대 후보(가중치), 주말 접속 확률, 해외 비율, 해외 나라)
    "day": ((2, 5), {8: 2, 9: 5, 10: 4, 11: 3, 13: 4, 14: 4, 15: 3, 16: 3, 17: 2, 18: 1}, 0.05, 0.0, []),
    "night": ((2, 5), {9: 3, 10: 4, 11: 2, 13: 3, 14: 3, 16: 3, 18: 2, 20: 2, 21: 2, 22: 3, 23: 3, 0: 1}, 0.2, 0.0, []),
    "traveler": ((2, 4), {9: 4, 10: 4, 11: 3, 13: 3, 14: 4, 15: 3, 16: 3, 17: 2}, 0.05, 0.15, ["JP", "SG"]),
}


def make_slot(rng, persona):
    per_day, hours, weekend_p, foreign_p, abroad = PATTERNS[persona]
    hour_keys, weights = list(hours), list(hours.values())
    events = []
    trip = set()
    if foreign_p and abroad:
        start = rng.randint(5, WINDOW_DAYS - 8)          # 한 번의 출장(3~5일) + 가끔 해외 접속
        trip = set(range(start, start + rng.randint(3, 5)))
    for day in range(WINDOW_DAYS):
        weekend = day % 7 in (5, 6)
        if weekend and rng.random() > weekend_p:
            continue
        for _ in range(rng.randint(*per_day)):
            h = rng.choices(hour_keys, weights)[0]
            sec = h * 3600 + rng.randint(0, 3599)
            country = abroad[0] if day in trip else (rng.choice(abroad) if abroad and rng.random() < foreign_p / 3 else HOME_COUNTRY)
            events.append((day, sec, country))
    events.sort()
    return downsample(events)


def main(path):
    rng = random.Random(20261103)
    slots = {}
    for slot, persona in SLOTS:
        ev = make_slot(rng, persona)
        slots[slot] = {"persona": persona, "stats": stats(ev), "events": [list(e) for e in ev]}
    write_seed(path, "synthetic", slots, {
        "note": "가정 패턴(팀이 정한 근무 시간대·출장 패턴). 실제 데이터가 아님. RBA 데이터셋 시드로 교체 예정",
        "generator": "tools/synthetic_seed.py", "random_seed": 20261103})
    for slot, d in slots.items():
        print(slot, d["persona"], d["stats"])


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "seed", "login_seed.json"))
