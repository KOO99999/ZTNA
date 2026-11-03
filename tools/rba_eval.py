"""RBA 데이터셋으로 night_access / unknown_location 규칙 채점(탐지율·오탐률) + 예전 발생률 근거 다시 재기.

데이터: Wiefling et al., ACM TOPS 2022, github.com/das-group/rba-dataset (CC BY 4.0)
실행: python tools/rba_eval.py rba-dataset.zip [--out results.json] [--max-rows N]

무엇을 하나(보고서에 그대로 쓸 수 있게 결과 파일에도 기록):
  1) 3,300만 줄을 시간순으로 한 번 읽으며, 로그인에 성공한 줄마다 "그 시점까지의 그 사람 기록"만 보고 엔진과 같은 규칙으로 판정한다
     (미래 기록을 보지 않음 = 실제 운영과 같은 조건).
  2) 정답: Is Account Takeover=True -> 계정 탈취(우리 행동 신호가 잡아야 할 대상: 비밀번호가 맞은 공격자),
           Is Attack IP=True(탈취 아님) -> 공격 IP에서 온 성공 로그인, 둘 다 아니면 정상.
     로그인 실패 줄은 판정하지 않는다(우리 엔진은 비밀번호를 통과한 뒤에 판단하므로).
  3) 규칙
     - 공통 규칙(fixed): 현지 22~06시면 야간, 회사 나라(데이터에서 가장 많은 나라)가 아니면 위치 이상
     - 개인 기준(personal): 지난 30일 기록이 MIN건 이상이면, 지금 시각 앞뒤 W시간 안 비율 < P면 야간,
       지금 나라 비율 < P면 위치 이상. 기록이 MIN건 미만이면 공통 규칙(엔진과 같음)
     - 기록에 넣는 줄: 정상 성공 로그인 + 계정 탈취 성공 로그인(탈취를 못 막았다고 보는 보수적 가정. 공격자 기록이 '평소'에 섞임)
  4) 결과
     - 신호 수준: 야간/위치/둘 중 하나가 켜진 비율(정답별)
     - 판정 수준: 엔진 점수(야간 20, 위치 40)와 자원 등급 임계값(20/40/60, 초과 시 추가 인증 이상)으로 '개입'한 비율
       (야간+위치 이상이 함께면 기준선과 상관없이 최소 추가 인증 = 엔진의 행동 신호 최소 조치)
     - 민감도: MIN(5/10/20) x P(2/5/10%) x W(0/1/2시간)
     - 예전 근거 다시 재기: 야간(현지 22~06시) 발생률, 새 나라(과거 전체 기준 / 30일 기준) 발생률, 놀람도 비율
"""
import argparse
import csv
import io
import json
import math
import os
import sys
import time
import zipfile
from array import array
from collections import Counter
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

WINDOW = 30 * 86400
MAX_HIST = 3000
GRID_MIN = (5, 10, 20)
GRID_P = (0.02, 0.05, 0.10)
GRID_W = (0, 1, 2)
DEFAULT = (10, 0.05, 1)
SCORE_NIGHT, SCORE_COUNTRY = 20, 40
TIERS = {"top_secret(20)": 20, "confidential(40)": 40, "internal(60)": 60}
LABELS = ("legit", "ato", "attack_ip")


def rows(path):
    if path.lower().endswith(".zip"):
        zf = zipfile.ZipFile(path)
        name = next(n for n in zf.namelist() if n.lower().endswith(".csv"))
        f = io.TextIOWrapper(zf.open(name), encoding="utf-8", newline="")
    else:
        f = open(path, encoding="utf-8", newline="")
    r = csv.reader(f)
    header = next(r)
    return header, r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--out", default="rba_eval_results.json")
    ap.add_argument("--max-rows", type=int, default=0)
    ap.add_argument("--local-tz", default="Europe/Oslo")
    a = ap.parse_args()
    tz = ZoneInfo(a.local_tz)
    t0 = time.time()

    header, reader = rows(a.dataset)
    ix = {h: i for i, h in enumerate(header)}
    I_TS, I_UID, I_C, I_OK, I_ATK, I_ATO = (ix["Login Timestamp"], ix["User ID"], ix["Country"], ix["Login Successful"],
                                            ix["Is Attack IP"], ix["Is Account Takeover"])

    day_cache = {}           # 'YYYY-MM-DD' -> (epoch of 00:00 UTC, local offset seconds)
    hist = {}                # uid(int) -> list of packed ints: ts<<20 | country_id<<5 | local_hour
    cid = {}                 # country -> small id
    cname = []
    # 판정한 줄의 특징(성공 로그인만): 정답, 기록 수, 앞뒤 0/1/2시간 같은 시간대 건수, 같은 나라 건수, 공통 규칙 결과
    F_label, F_n, F_h0, F_h1, F_h2, F_cc, F_fn, F_fc = (array("b"), array("H"), array("H"), array("H"), array("H"),
                                                        array("H"), array("b"), array("H"))
    country_total = Counter()
    seen_ever = {}           # 예전 방식(과거 전체에 없던 나라) 다시 재기용: uid -> set of country ids
    ever_new = Counter()     # label -> 새 나라 수
    ever_elig = Counter()    # label -> 비교 가능한 줄 수
    total = ok_rows = unsorted = 0
    last_ts = 0
    label_count = Counter()

    for row in reader:
        total += 1
        if a.max_rows and total > a.max_rows:
            break
        if total % 2_000_000 == 0:
            print(f"  {total:,} rows  {time.time() - t0:.0f}s  users={len(hist):,}", file=sys.stderr, flush=True)
        s = row[I_TS]
        d = s[:10]
        dc = day_cache.get(d)
        if dc is None:
            base = int(datetime(int(d[:4]), int(d[5:7]), int(d[8:10]), tzinfo=timezone.utc).timestamp())
            off = int(datetime.fromtimestamp(base + 43200, tz).utcoffset().total_seconds())
            dc = day_cache[d] = (base, off)
        ts = dc[0] + int(s[11:13]) * 3600 + int(s[14:16]) * 60 + int(s[17:19])
        if ts < last_ts:
            unsorted += 1
        last_ts = ts
        if row[I_OK] != "True":
            continue
        ok_rows += 1
        country = row[I_C]
        c = cid.get(country)
        if c is None:
            c = cid[country] = len(cname)
            cname.append(country)
        country_total[c] += 1
        hour = ((ts + dc[1]) // 3600) % 24
        label = 1 if row[I_ATO] == "True" else (2 if row[I_ATK] == "True" else 0)
        label_count[label] += 1
        uid = int(row[I_UID])

        # 예전 방식: 과거 전체에 없던 나라
        se = seen_ever.get(uid)
        if se is None:
            seen_ever[uid] = {c}
        else:
            ever_elig[label] += 1
            if c not in se:
                ever_new[label] += 1
                se.add(c)

        # 30일 창
        h = hist.get(uid)
        if h is None:
            h = hist[uid] = []
        cut = (ts - WINDOW) << 20
        k = 0
        while k < len(h) and h[k] < cut:
            k += 1
        if k:
            del h[:k]
        n = len(h)
        h0 = h1 = h2 = cc = 0
        for p in h:
            hh = p & 31
            dd = abs(hh - hour)
            dd = min(dd, 24 - dd)
            if dd == 0:
                h0 += 1
            if dd <= 1:
                h1 += 1
            if dd <= 2:
                h2 += 1
            if (p >> 5) & 0x7FFF == c:
                cc += 1
        F_label.append(label)
        F_n.append(min(n, 65535)); F_h0.append(min(h0, 65535)); F_h1.append(min(h1, 65535)); F_h2.append(min(h2, 65535))
        F_cc.append(min(cc, 65535))
        F_fn.append(1 if (hour >= 22 or hour < 6) else 0)
        F_fc.append(c)       # 회사 나라는 끝나고 정함 -> 나라 id를 저장해 두고 나중에 비교
        if label in (0, 1):  # 기록에 넣는 줄(정상 + 탈취, 보수적 가정)
            h.append((ts << 20) | (c << 5) | hour)
            if len(h) > MAX_HIST:
                del h[: len(h) - MAX_HIST]

    elapsed = time.time() - t0
    print(f"read done: {total:,} rows, {ok_rows:,} successful, {elapsed:.0f}s", file=sys.stderr, flush=True)
    del hist, seen_ever

    import numpy as np
    lab = np.frombuffer(F_label, dtype=np.int8)
    n = np.frombuffer(F_n, dtype=np.uint16).astype(np.int32)
    hw = {0: np.frombuffer(F_h0, dtype=np.uint16), 1: np.frombuffer(F_h1, dtype=np.uint16), 2: np.frombuffer(F_h2, dtype=np.uint16)}
    cc = np.frombuffer(F_cc, dtype=np.uint16)
    fixed_night = np.frombuffer(F_fn, dtype=np.int8).astype(bool)
    country_ids = np.frombuffer(F_fc, dtype=np.uint16).astype(np.int32)
    home = country_total.most_common(1)[0][0]
    fixed_country = country_ids != home
    masks = {name: lab == i for i, name in enumerate(LABELS)}

    def rates(flag):
        return {name: round(float(flag[m].mean()) if m.any() else 0.0, 4) for name, m in masks.items()}

    def decision(night, ctry):
        score = SCORE_NIGHT * night.astype(np.int32) + SCORE_COUNTRY * ctry.astype(np.int32)
        # 엔진과 같이: 점수가 기준선을 넘거나, 야간+위치 이상이 함께 걸리면(행동 신호 최소 조치) 개입
        return {tier: rates((score > thr) | (night & ctry)) for tier, thr in TIERS.items()}

    def personal(mn, p, w):
        learned = n >= mn
        safe_n = np.maximum(n, 1)
        night = np.where(learned, hw[w] / safe_n < p, fixed_night)
        ctry = np.where(learned, cc / safe_n < p, fixed_country)
        return night, ctry, learned

    res = {"dataset": "Wiefling et al. RBA dataset (ACM TOPS 2022), github.com/das-group/rba-dataset, CC BY 4.0",
           "rows_read": total, "successful_logins_judged": int(len(lab)), "unsorted_rows": unsorted,
           "label_counts": {LABELS[k]: int(v) for k, v in label_count.items()},
           "home_country": cname[home], "local_tz": a.local_tz, "runtime_seconds": round(elapsed),
           "assumptions": ["실패한 로그인은 판정하지 않음(엔진은 비밀번호 통과 뒤 판단)",
                           "계정 탈취 로그인도 이력에 들어감(탈취를 못 막았다는 보수적 가정)",
                           "공통 규칙의 '회사 나라'는 데이터에서 가장 많은 나라",
                           "시각은 데이터셋 시각을 UTC로 보고 현지 시각(Europe/Oslo)으로 변환"]}

    res["fixed"] = {"signal_night": rates(fixed_night), "signal_country": rates(fixed_country),
                    "signal_any": rates(fixed_night | fixed_country), "decision": decision(fixed_night, fixed_country)}
    pn, pc, learned = personal(*DEFAULT)
    res["personal_default"] = {"params": {"min_logins": DEFAULT[0], "min_share": DEFAULT[1], "hour_window": DEFAULT[2]},
                               "learned_share": rates(learned),
                               "signal_night": rates(pn), "signal_country": rates(pc), "signal_any": rates(pn | pc),
                               "decision": decision(pn, pc)}
    grid = []
    for mn in GRID_MIN:
        for p in GRID_P:
            for w in GRID_W:
                gn, gc, _ = personal(mn, p, w)
                anyf = rates(gn | gc)
                grid.append({"min_logins": mn, "min_share": p, "hour_window": w,
                             "ato_detect": anyf["ato"], "attack_ip_detect": anyf["attack_ip"], "legit_flag": anyf["legit"],
                             "night_legit": rates(gn)["legit"], "country_legit": rates(gc)["legit"]})
    res["grid"] = grid
    # 기록이 충분한 사람(개인 기준이 실제로 작동하는 경우)만 따로: 매일 접속하는 직원에 더 가까운 집단
    sub = {}
    for mn in GRID_MIN:
        m = n >= mn
        gn, gc, _ = personal(mn, DEFAULT[1], DEFAULT[2])
        def r_on(flag):
            return {name: (round(float(flag[m & mk].mean()), 4) if (m & mk).any() else None) for name, mk in masks.items()}
        sub[f"history>={mn}"] = {"count": {name: int((m & mk).sum()) for name, mk in masks.items()},
                                 "fixed_any": r_on(fixed_night | fixed_country), "personal_any": r_on(gn | gc),
                                 "fixed_night": r_on(fixed_night), "personal_night": r_on(gn),
                                 "fixed_country": r_on(fixed_country), "personal_country": r_on(gc)}
    res["learned_subset"] = sub

    # 예전 근거 다시 재기(정상 로그인 기준 발생률과 놀람도)
    legit = masks["legit"]
    p_night = float(fixed_night[legit].mean())
    p_new_ever = ever_new[0] / max(ever_elig[0], 1)
    has_hist = legit & (n >= 1)
    p_new_30 = float((cc[has_hist] == 0).mean()) if has_hist.any() else 0.0
    res["base_rates_legit"] = {
        "night_local_22_06": round(p_night, 4), "new_country_ever": round(p_new_ever, 4), "new_country_30d": round(p_new_30, 4),
        "surprisal_night": round(-math.log2(p_night), 2), "surprisal_new_country_ever": round(-math.log2(p_new_ever), 2),
        "ratio_country_to_night_ever": round(math.log2(p_new_ever) / math.log2(p_night), 2),
        "ratio_country_to_night_30d": round(math.log2(p_new_30) / math.log2(p_night), 2) if p_new_30 > 0 else None,
        "current_score_ratio": SCORE_COUNTRY / SCORE_NIGHT}
    res["base_rates_ato"] = {"night_local_22_06": rates(fixed_night)["ato"],
                             "new_country_ever": round(ever_new[1] / max(ever_elig[1], 1), 4)}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
    print(json.dumps({k: res[k] for k in ("label_counts", "home_country", "fixed", "personal_default", "base_rates_legit")},
                     ensure_ascii=False, indent=1))
    print(f"saved {os.path.abspath(a.out)}  total {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
