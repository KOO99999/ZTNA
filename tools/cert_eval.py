"""CERT 내부자 위협 데이터(r4.2)로 night_access(평소 아닌 시간) 채점: 공통 규칙 vs 개인 기준.

데이터: CERT Insider Threat Test Dataset r4.2 (Carnegie Mellon University SEI, KiltHub) - 가상(합성) 데이터
  logon.csv  : id,date,user,pc,activity (Logon/Logoff) - 직원 1,000명, 2010.01~2011.05
  insiders.csv: dataset,scenario,details,user,start,end - 정답(내부자 행동 기간)
  시나리오 1: "원래 이동식 저장장치를 쓰거나 업무 시간 외에 일하지 않던 사용자가 업무 시간 외 로그온을 시작"
             -> 개인별 '평소 아닌 시간' 신호가 잡아야 할 정확한 대상
실행: python tools/cert_eval.py logon.csv insiders.csv [--out cert_eval_results.json]

방법(RBA 평가와 같은 규칙):
  - 로그온(Logon) 줄만 시간순으로 넘기며, 그 시점까지 30일 기록만 보고 판정(미래를 보지 않음)
  - 공통 규칙: 22~06시면 야간 / 개인 기준: 30일 기록 MIN건 이상이면 지금 시각 앞뒤 W시간 비율 < P면 평소 아님
  - 정답(양성): r4.2 시나리오 1 사용자의 내부자 기간(start~end) 안 로그온
    음성: 그 밖의 로그온(시나리오 2·3 사용자의 내부자 기간은 시간 신호와 무관한 행동이라 양쪽에서 제외)
  - 기록에 넣는 줄: 모든 로그온(내부자 기간 포함 = 못 막았다는 보수적 가정)
  - 결과: 줄 단위 탐지율/오탐률, 사람 단위(내부자 기간에 한 번이라도 걸렸나), 첫 탐지까지 걸린 시간, 직원 1명당 한 달 오탐 횟수
"""
import argparse
import csv
import json
import os
from collections import defaultdict
from datetime import datetime

WINDOW = 30 * 86400
GRID_MIN = (5, 10, 20)
GRID_P = (0.02, 0.05, 0.10)
GRID_W = (0, 1, 2)
DEFAULT = (10, 0.05, 1)


def parse(s):
    s = s.strip()
    if s.startswith("/"):
        return None
    return datetime.strptime(s, "%m/%d/%Y %H:%M:%S")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logon")
    ap.add_argument("insiders")
    ap.add_argument("--out", default="cert_eval_results.json")
    ap.add_argument("--release", default="4.2")
    a = ap.parse_args()

    windows, excluded = {}, defaultdict(list)
    with open(a.insiders, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["dataset"] != a.release:
                continue
            st, en = parse(r["start"]), parse(r["end"])
            if st is None or en is None:
                continue
            if r["scenario"] == "1":
                windows[r["user"]] = (st.timestamp(), en.timestamp())
            else:
                excluded[r["user"]].append((st.timestamp(), en.timestamp()))

    events = []
    with open(a.logon, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["activity"] != "Logon":
                continue
            dt = parse(r["date"])
            events.append((dt.timestamp(), r["user"], dt.hour))
    events.sort()

    hist = defaultdict(list)
    feats = []   # (label, n, h0, h1, h2, fixed_night, user, ts)   label: 1 양성 / 0 음성 / -1 제외
    for ts, user, hour in events:
        w = windows.get(user)
        if w and w[0] <= ts <= w[1]:
            label = 1
        elif any(s <= ts <= e for s, e in excluded.get(user, ())):
            label = -1
        else:
            label = 0
        h = hist[user]
        k = 0
        while k < len(h) and h[k][0] < ts - WINDOW:
            k += 1
        if k:
            del h[:k]
        h0 = h1 = h2 = 0
        for _, hh in h:
            d = abs(hh - hour)
            d = min(d, 24 - d)
            h0 += d == 0
            h1 += d <= 1
            h2 += d <= 2
        feats.append((label, len(h), h0, h1, h2, hour >= 22 or hour < 6, user, ts))
        h.append((ts, hour))

    def flags(rule):
        out = []
        for lab, n, h0, h1, h2, fixed, user, ts in feats:
            if rule == "fixed":
                f = fixed
            else:
                mn, p, w = rule
                f = (((h0, h1, h2)[w]) / n < p) if n >= mn else fixed
            out.append(f)
        return out

    span_days = (events[-1][0] - events[0][0]) / 86400
    n_users = len({u for _, u, _ in events})

    def score(fl):
        pos = [f for (lab, *_), f in zip(feats, fl) if lab == 1]
        neg = [f for (lab, *_), f in zip(feats, fl) if lab == 0]
        first = {}
        for (lab, n, *_rest, user, ts), f in zip(feats, fl):
            if lab == 1 and f and user not in first:
                first[user] = (ts - windows[user][0]) / 3600
        caught = len(first)
        return {"event_detect": round(sum(pos) / len(pos), 4), "event_false_flag": round(sum(neg) / len(neg), 4),
                "users_caught": f"{caught}/{len(windows)}", "user_detect": round(caught / len(windows), 4),
                "median_hours_to_first_flag": round(sorted(first.values())[len(first) // 2], 1) if first else None,
                "false_flags_per_user_per_30d": round(sum(neg) / n_users / (span_days / 30), 2)}

    res = {"dataset": f"CERT Insider Threat Test Dataset r{a.release} (CMU SEI, synthetic)",
           "logons": len(events), "users": n_users, "span_days": round(span_days),
           "scenario1_insiders": len(windows), "positive_logons": sum(1 for x in feats if x[0] == 1),
           "negative_logons": sum(1 for x in feats if x[0] == 0), "excluded_logons": sum(1 for x in feats if x[0] == -1),
           "fixed_22_06": score(flags("fixed")),
           "personal_default": {"params": {"min_logins": DEFAULT[0], "min_share": DEFAULT[1], "hour_window": DEFAULT[2]},
                                **score(flags(DEFAULT))},
           "grid": []}
    for mn in GRID_MIN:
        for p in GRID_P:
            for w in GRID_W:
                res["grid"].append({"min_logins": mn, "min_share": p, "hour_window": w, **score(flags((mn, p, w)))})
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in res.items() if k != "grid"}, ensure_ascii=False, indent=1))
    print("grid (min,p,w): event_detect user_detect false_flag false/user/30d")
    for g in res["grid"]:
        print(g["min_logins"], g["min_share"], g["hour_window"], "|", g["event_detect"], g["user_detect"], g["event_false_flag"],
              g["false_flags_per_user_per_30d"])
    print("saved", os.path.abspath(a.out))


if __name__ == "__main__":
    main()
