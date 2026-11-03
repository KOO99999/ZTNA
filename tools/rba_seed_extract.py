"""공개 RBA 데이터셋에서 계정별 시드 이력 뽑기.

데이터: Wiefling et al., "Pump Up Password Security! Evaluating and Enhancing Risk-Based Authentication on a
        Real-World Large-Scale Online Service", ACM TOPS 2022. https://github.com/das-group/rba-dataset
        (Zenodo record 6782156, CC BY 4.0 - 보고서에 출처 표기 필수)
        3,300만 건 로그인(2020.2~2021.2, 사용자 330만 명). 이 스크립트가 쓰는 칸: User ID, Login Timestamp,
        Country, Login Successful, Is Attack IP, Is Account Takeover.

실행 예:
  python tools/rba_seed_extract.py rba-dataset.zip            # zip 그대로 또는 압축 푼 rba-dataset.csv
  python tools/rba_seed_extract.py --self-test                 # 작은 가짜 CSV로 동작만 확인
  결과: seed/login_seed.json(origin=rba) - 이 파일만 커밋하면 다음 apply부터 시드가 RBA 패턴으로 바뀐다.

뽑는 방법(보고서에 그대로 적을 수 있게 결과 파일에도 기록됨):
  1) 정상 사용자만: 공격 IP / 계정 탈취 표시가 한 번이라도 있는 사용자는 제외, 성공한 로그인만 사용
  2) 사용자마다 로그인이 가장 많은 연속 30일 구간을 고르고, 그 구간에 25건 이상인 사용자만 후보
  3) 시각: 데이터셋 시각을 UTC로 보고 --local-tz(기본 Europe/Oslo, 노르웨이 서비스)의 현지 시각으로 바꾼 뒤,
     그 "현지 시계"를 그대로 한국 시각으로 옮긴다(오전 9시 출근 패턴 -> 한국 오전 9시)
  4) 나라: 데이터셋은 개인정보 보호를 위해 나라 이름을 무작위로 바꿔 두었으므로 이름 자체는 의미가 없고,
     "그 사람이 가장 많이 쓴 나라 -> KR, 두 번째 -> JP, 세 번째 -> US ..."로 바꿔 끼운다(익숙함의 구조만 유지)
  5) 성향(night/day/traveler)에 맞는 후보를 계정 칸마다 한 명씩(겹치지 않게) 고른다. 고르는 순서는 사용자 ID의
     해시로 정해 매번 같은 결과가 나온다(--salt로 다른 조합 선택 가능)
  6) 한 사람당 최대 150건으로 고르게 줄인다
"""
import argparse
import csv
import hashlib
import io
import os
import random
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from seed_common import SLOTS, WINDOW_DAYS, HOME_COUNTRY, TRAVEL_COUNTRIES, downsample, stats, write_seed  # noqa: E402

COL_USER, COL_TS, COL_COUNTRY = "User ID", "Login Timestamp", "Country"
COL_OK, COL_ATTACK, COL_ATO = "Login Successful", "Is Attack IP", "Is Account Takeover"
MIN_TOTAL = 30          # 1차 후보: 전체 기간 성공 로그인 수
MIN_WINDOW = 25         # 30일 구간 안 최소 로그인 수
MAX_CANDIDATES = 30_000   # 메모리 상한(후보 3만 명이면 충분, 2차에서 이 사람들 줄만 모음)

PERSONA_RULES = {
    "night": lambda s: 0.12 <= s["night_share"] <= 0.5 and s["foreign_share"] <= 0.02,
    "day": lambda s: s["night_share"] <= 0.02 and s["foreign_share"] <= 0.01,
    "traveler": lambda s: 0.05 <= s["foreign_share"] <= 0.35 and s["night_share"] <= 0.05,
}


def _true(v):
    return str(v).strip().lower() in ("true", "1", "yes")


def open_rows(path):
    """CSV 또는 zip(안의 첫 .csv)을 한 줄씩 읽는다(9GB짜리를 메모리에 올리지 않음)."""
    if path.lower().endswith(".zip"):
        zf = zipfile.ZipFile(path)
        name = next(n for n in zf.namelist() if n.lower().endswith(".csv"))
        f = io.TextIOWrapper(zf.open(name), encoding="utf-8", newline="")
    else:
        f = open(path, encoding="utf-8", newline="")
    return csv.DictReader(f)


def parse_ts(value):
    v = value.strip().replace("T", " ").replace("Z", "")
    dt = datetime.fromisoformat(v)
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def pass1_bad_users_and_counts(path, progress):
    counts, bad = Counter(), set()
    for i, r in enumerate(open_rows(path)):
        uid = r[COL_USER]
        if _true(r.get(COL_ATTACK)) or _true(r.get(COL_ATO)):
            bad.add(uid)
        elif _true(r.get(COL_OK)):
            counts[uid] += 1
        if progress and i and i % 2_000_000 == 0:
            print(f"  1차: {i:,}줄", file=sys.stderr)
    return counts, bad


def pass2_collect(path, candidates, progress):
    rows = defaultdict(list)
    for i, r in enumerate(open_rows(path)):
        uid = r[COL_USER]
        if uid in candidates and _true(r.get(COL_OK)):
            rows[uid].append((parse_ts(r[COL_TS]), r[COL_COUNTRY]))
        if progress and i and i % 2_000_000 == 0:
            print(f"  2차: {i:,}줄", file=sys.stderr)
    return rows


def best_window(local_events):
    """시각 순 [(local_dt, country)] -> 로그인이 가장 많은 연속 30일 구간."""
    best, j = (0, 0), 0
    for i in range(len(local_events)):
        while local_events[i][0] - local_events[j][0] >= timedelta(days=WINDOW_DAYS):
            j += 1
        if i - j + 1 > best[1] - best[0]:
            best = (j, i + 1)
    return local_events[best[0]:best[1]]


def to_seed_events(window):
    """현지 시각 구간 -> [(며칠째, 하루 중 초, 바꿔 낀 나라)]"""
    start = window[0][0].date()
    ranked = [c for c, _ in Counter(c for _, c in window).most_common()]
    mapping = {c: (HOME_COUNTRY if k == 0 else TRAVEL_COUNTRIES[min(k - 1, len(TRAVEL_COUNTRIES) - 1)]) for k, c in enumerate(ranked)}
    events = []
    for dt, c in window:
        day = (dt.date() - start).days
        if 0 <= day < WINDOW_DAYS:
            events.append((day, dt.hour * 3600 + dt.minute * 60 + dt.second, mapping[c]))
    return events


def extract(path, local_tz="Europe/Oslo", salt="zt", progress=True):
    try:
        tz = ZoneInfo(local_tz)
    except Exception:
        sys.exit(f"시간대 '{local_tz}'를 찾을 수 없습니다. Windows는 시간대 자료가 없어 먼저 'pip install tzdata'를 실행하세요.")
    counts, bad = pass1_bad_users_and_counts(path, progress)
    cands = [u for u, n in counts.items() if n >= MIN_TOTAL and u not in bad]
    cands.sort(key=lambda u: -counts[u])
    cands = set(cands[:MAX_CANDIDATES])
    rows = pass2_collect(path, cands, progress)
    pool = []
    for uid, evs in rows.items():
        local = sorted((dt.astimezone(tz), c) for dt, c in evs)
        window = best_window(local)
        if len(window) < MIN_WINDOW:
            continue
        seed_events = sorted(to_seed_events(window))
        pool.append((hashlib.sha256((salt + uid).encode()).hexdigest(), uid, seed_events, stats(seed_events)))
    pool.sort()
    used, slots = set(), {}
    for slot, persona in SLOTS:
        pick = next((p for p in pool if p[1] not in used and PERSONA_RULES[persona](p[3])), None)
        if pick is None:
            print(f"[경고] {slot}({persona})에 맞는 사용자가 없어 비워 둠", file=sys.stderr)
            continue
        used.add(pick[1])
        ev = downsample(pick[2])
        slots[slot] = {"persona": persona, "rba_user": hashlib.sha256(pick[1].encode()).hexdigest()[:12],
                       "stats": stats(ev), "events": [list(e) for e in ev]}
    meta = {
        "dataset": "Wiefling et al., RBA login dataset (ACM TOPS 2022), github.com/das-group/rba-dataset, CC BY 4.0",
        "generator": "tools/rba_seed_extract.py",
        "selection": {"exclude": "users with Is Attack IP or Is Account Takeover", "successful_only": True,
                      "window_days": WINDOW_DAYS, "min_logins_in_window": MIN_WINDOW, "salt": salt,
                      "candidates_with_window": len(pool)},
        "transform": {"time": f"dataset timestamp as UTC -> {local_tz} local clock -> same clock in KST",
                      "country": "per user: most used -> KR, then " + ", ".join(TRAVEL_COUNTRIES) + " by frequency rank",
                      "max_events_per_account": 150},
    }
    return slots, meta


def self_test():
    """작은 가짜 CSV(데이터셋과 같은 칸 이름)로 뽑기 과정 전체를 확인한다."""
    rng = random.Random(1)
    tmp = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="", encoding="utf-8")
    w = csv.writer(tmp)
    w.writerow(["index", "Login Timestamp", "User ID", "Round-Trip Time [ms]", "IP Address", "Country", "Region", "City",
                "ASN", "User Agent String", "Browser Name and Version", "OS Name and Version", "Device Type",
                "Login Successful", "Is Attack IP", "Is Account Takeover"])
    base = datetime(2020, 5, 1, tzinfo=timezone.utc)
    idx = 0

    def row(uid, dt, country, ok=True, attack=False, ato=False):
        nonlocal idx
        idx += 1
        w.writerow([idx, dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], uid, 500, "10.0.0.1", country, "-", "-", 1, "ua", "b", "os", "desktop",
                    str(ok), str(attack), str(ato)])
    # Oslo(여름 UTC+2) 기준: 낮 사람 = UTC 07~14시, 밤 사람 = 일부 UTC 20~21시(현지 22~23시)
    for u in range(12):
        for d in range(40):
            for k in range(3):
                h = 7 + rng.randint(0, 7)
                row(f"day{u}", base + timedelta(days=d, hours=h, minutes=rng.randint(0, 59)), "NO")
    for u in range(3):
        for d in range(40):
            row(f"night{u}", base + timedelta(days=d, hours=8), "NO")
            row(f"night{u}", base + timedelta(days=d, hours=20, minutes=30), "NO")
    for u in range(3):
        for d in range(40):
            row(f"trav{u}", base + timedelta(days=d, hours=9), "NO")
            row(f"trav{u}", base + timedelta(days=d, hours=12), "SE" if d % 6 == 0 else "NO")
    for d in range(40):                                   # 공격 표시가 있는 사용자는 제외돼야 함
        row("attacked", base + timedelta(days=d, hours=9), "NO")
    row("attacked", base + timedelta(days=3, hours=3), "RU", ok=False, attack=True)
    tmp.close()
    slots, meta = extract(tmp.name, progress=False)
    os.unlink(tmp.name)
    picked = {s: d["persona"] for s, d in slots.items()}
    assert set(picked) == {s for s, _ in SLOTS}, picked
    assert all(slots[s]["stats"]["night_share"] >= 0.12 for s, p in SLOTS if p == "night"), slots
    assert all(slots[s]["stats"]["foreign_share"] >= 0.05 and "JP" in slots[s]["stats"]["countries"]
               for s, p in SLOTS if p == "traveler"), slots
    assert all(slots[s]["stats"]["countries"] == ["KR"] for s, p in SLOTS if p == "day"), slots
    rba_ids = {d["rba_user"] for d in slots.values()}
    assert hashlib.sha256(b"attacked").hexdigest()[:12] not in rba_ids and len(rba_ids) == len(slots)
    assert all(0 <= e[0] < WINDOW_DAYS and 0 <= e[1] < 86400 for d in slots.values() for e in d["events"])
    night_hours = sorted({e[1] // 3600 for e in slots["employee01"]["events"]})
    assert 22 in night_hours, night_hours                # UTC 20:30 -> 오슬로 22:30 -> KST 22:30으로 옮겨짐
    print("self-test ok:", {s: (d["persona"], d["stats"]["logins"], d["stats"]["night_share"], d["stats"]["foreign_share"]) for s, d in slots.items()})


def main():
    ap = argparse.ArgumentParser(description="RBA 데이터셋 -> seed/login_seed.json")
    ap.add_argument("dataset", nargs="?", help="rba-dataset.zip 또는 rba-dataset.csv")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "seed", "login_seed.json"))
    ap.add_argument("--local-tz", default="Europe/Oslo")
    ap.add_argument("--salt", default="zt")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        self_test()
        return
    if not a.dataset:
        ap.error("데이터셋 경로가 필요합니다(또는 --self-test)")
    slots, meta = extract(a.dataset, a.local_tz, a.salt)
    write_seed(a.out, "rba", slots, meta)
    print(f"저장: {os.path.abspath(a.out)}")
    for s, d in slots.items():
        print(f"  {s:11s} {d['persona']:8s} {d['stats']}")


if __name__ == "__main__":
    main()
