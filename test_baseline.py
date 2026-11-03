"""개인별 기준(시드 이력 + 실제 이력) 검사. 실행: python test_baseline.py
  - 시드 파일 형식, 시드 적재 함수(날짜 옮기기/계정 매핑/기존 시드 교체), RBA 뽑기 스크립트(가짜 CSV로),
  - 시드 -> 엔진 판정까지 이어 붙여 "공통 규칙이면 걸리던/통과하던 사람이 개인 기준으로 바뀌는지",
  - Terraform(baseline.tf) 최소 권한과 apply 때 자동 적재 설정.
"""
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tools"))
fails = 0


def ok(name, cond, detail=""):
    global fails
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        fails += 1
        if detail:
            print(f"    -> {detail}")


def read(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return f.read()


sys.modules["boto3"] = MagicMock()
os.environ.setdefault("EVALUATE_SHARED_SECRET", "x")
import seed_loader  # noqa: E402
import risk_score_engine as engine  # noqa: E402
from seed_common import SLOTS, WINDOW_DAYS  # noqa: E402

KST = timezone(timedelta(hours=9))

# ---------- 1. 시드 파일 ----------
seed = json.loads(read("seed/login_seed.json"))
ok("시드 파일: origin이 rba 또는 synthetic(가짜 기록인지 출처가 표시됨)", seed.get("origin") in ("rba", "synthetic"), seed.get("origin"))
ok("시드 파일: 계정 칸이 정해진 10개(비상 관리자 제외)와 같음", set(seed["slots"]) == {s for s, _ in SLOTS}, sorted(seed["slots"]))
ok("시드 파일: 이메일이 들어 있지 않음(관리자 이메일은 Terraform이 넘김)", "@" not in json.dumps(seed["slots"]))
ok("시드 파일: 모든 줄이 (0~29일째, 0~86399초, 두 글자 나라)",
   all(0 <= d < WINDOW_DAYS and 0 <= s < 86400 and re.fullmatch(r"[A-Z]{2}", c) for v in seed["slots"].values() for d, s, c in v["events"]))
ok("시드 파일: 계정마다 학습 기간을 넘는 이력(엔진 최소 건수 이상)",
   all(len(v["events"]) >= engine.BASELINE_MIN_LOGINS for v in seed["slots"].values()),
   {k: len(v["events"]) for k, v in seed["slots"].items()})

# ---------- 2. 시드 적재 함수 ----------
ACC = {"employee01": "employee01@xmcda.store", "employee08": "Employee08@xmcda.store", "admin": "boss@example.com", "employee02": ""}
NOW = int(datetime(2026, 11, 3, 15, 0, tzinfo=KST).timestamp())
items = seed_loader.seed_items(seed, ACC, NOW)
ids = {i["identity"] for i in items}
ok("적재: 매핑된 계정만, 이메일은 소문자, 빈 이메일 계정은 건너뜀",
   ids == {"employee01@xmcda.store", "employee08@xmcda.store", "boss@example.com"}, ids)
midnight = datetime(2026, 11, 3, tzinfo=KST)
ok("적재: 모든 시각이 '오늘 KST 자정 기준 지난 30일' 안(미래 없음, 29일째 = 어제)",
   all(midnight - timedelta(days=30) <= datetime.fromtimestamp(i["ts"], KST) < midnight + timedelta(seconds=3) for i in items))
ev0 = seed["slots"]["employee01"]["events"][0]
first = min(i["ts"] for i in items if i["identity"] == "employee01@xmcda.store")
ok("적재: (며칠째, 초)가 그대로 KST 시각으로 옮겨짐",
   datetime.fromtimestamp(first, KST) == midnight - timedelta(days=30) + timedelta(days=ev0[0], seconds=ev0[1]),
   (datetime.fromtimestamp(first, KST), ev0))
ok("적재: 모든 줄에 source=seed, origin(rba/synthetic), 31일 뒤 자동 삭제",
   all(i["source"] == "seed" and i["origin"] == seed["origin"] and i["expires_at"] - i["ts"] == 31 * 86400 for i in items))
ok("적재: (계정, 시각) 키가 겹치지 않음", len({(i["identity"], i["ts"]) for i in items}) == len(items))

tbl = MagicMock()
tbl.query.return_value = {"Items": [{"identity": "employee01@xmcda.store", "ts": 1}]}
bw = MagicMock()
tbl.batch_writer.return_value.__enter__.return_value = bw
seed_loader._table = tbl
seed_loader.SEED_FILE = os.path.join(HERE, "seed", "login_seed.json")   # Lambda zip에서는 seed_loader.py 옆에 들어감
out = seed_loader.handler({"accounts": ACC})
qk = tbl.query.call_args.kwargs
ok("적재 실행: 기존 시드 줄만 골라 지움(source=seed 조건, 실제 이력은 유지)",
   qk.get("FilterExpression") == "#src = :seed" and qk["ExpressionAttributeValues"][":seed"] == "seed"
   and bw.delete_item.called, qk)
ok("적재 실행: 줄 수 요약 반환(계정별 건수)", out["written"] == len(items) and out["deleted_old_seed"] >= 1
   and set(out["per_account"]) == ids, out)

# ---------- 3. 시드 -> 엔진 판정(공통 규칙 대비) ----------
def history(slot):
    return [(i["ts"], i["country"]) for i in seed_loader.seed_items(seed, {slot: f"{slot}@x"}, NOW)]


persona = dict(SLOTS)
night_slot = next(s for s, p in SLOTS if p == "night")
day_slot = next(s for s, p in SLOTS if p == "day")
trav_slot = next(s for s, p in SLOTS if p == "traveler")
night_hours = [h for h in range(24) if engine.baseline_judgement(history(night_slot), h, "KR")["unusual_time"] is False]
r = engine.baseline_judgement(history(night_slot), 23, "KR")
ok(f"{night_slot}(야간 근무형) 23시: 개인 기준으로 평소 시간(공통 규칙이면 야간으로 걸림)",
   r["mode"] == "personal" and r["unusual_time"] is False, r)
r = engine.baseline_judgement(history(day_slot), 21, "KR")
ok(f"{day_slot}(낮 근무형) 21시: 개인 기준으로 평소 아님(공통 규칙이면 통과)", r["mode"] == "personal" and r["unusual_time"] is True, r)
r = engine.baseline_judgement(history(day_slot), 4, "KR")
ok(f"{day_slot}(낮 근무형) 04시: 평소 아님", r["unusual_time"] is True, r)
foreign = [c for _, c in history(trav_slot) if c != "KR"]
r = engine.baseline_judgement(history(trav_slot), 11, foreign[0] if foreign else "JP")
ok(f"{trav_slot}(출장형) 출장 가던 나라: 평소 나라(공통 규칙이면 위치 이상)", r["unusual_country"] is False, r)
r = engine.baseline_judgement(history(day_slot), 11, "JP")
ok(f"{day_slot}(낮 근무형) 일본 접속: 처음 보는 나라 -> 위치 이상", r["unusual_country"] is True, r)

# ---------- 4. RBA 뽑기 스크립트(가짜 CSV) ----------
p = subprocess.run([sys.executable, os.path.join(HERE, "tools", "rba_seed_extract.py"), "--self-test"], capture_output=True, text=True)
ok("RBA 뽑기: 같은 칸 이름의 가짜 CSV로 전체 과정 확인(공격 표시 사용자 제외, 성향별 선택, 시각/나라 변환)",
   p.returncode == 0 and "self-test ok" in p.stdout, p.stdout + p.stderr)

# ---------- 5. Terraform ----------
tf, main, var = read("baseline.tf"), read("main.tf"), read("variables.tf")
ok("baseline.tf: login_history(identity + ts) + TTL(expires_at)",
   'hash_key     = "identity"' in tf and 'range_key    = "ts"' in tf and 'attribute_name = "expires_at"' in tf)
ok("baseline.tf: 엔진은 이 표에 Query/PutItem만",
   re.search(r'Action\s*=\s*\["dynamodb:Query", "dynamodb:PutItem"\]\s*\n\s*Resource = \[aws_dynamodb_table.login_history.arn\]', tf) is not None)
ok("baseline.tf: 시드 적재 함수는 login_history에만 쓰기/지우기/조회(Scan 없음, 다른 테이블 없음)",
   re.search(r'"dynamodb:Query", "dynamodb:BatchWriteItem", "dynamodb:PutItem", "dynamodb:DeleteItem"\]\s*\n\s*Resource = \[aws_dynamodb_table.login_history.arn\]', tf) is not None
   and "Scan" not in tf)
ok("baseline.tf: apply 때 자동 적재(aws_lambda_invocation), 시드/계정/코드/테이블이 바뀌면 다시 적재",
   'resource "aws_lambda_invocation" "seed_load"' in tf and all(k in tf for k in ("seed_hash = filesha256(local.seed_file)", "table_arn =", "code_hash =", "accounts  =")))
ok("baseline.tf: 비상 관리자(두 번째 관리자)는 시드 없음", "admin_allowed_emails[0]" in tf and "admin_allowed_emails[1]" not in tf)
ok("main.tf/variables.tf: BASELINE_MODE 스위치(personal/fixed, 기본 personal)",
   "BASELINE_MODE = var.baseline_mode" in main and 'variable "baseline_mode"' in var and 'default     = "personal"' in var.split('variable "baseline_mode"')[1])
code = read("seed_loader.py")
ok("seed_loader.py: 오늘 KST 자정 기준으로 날짜를 옮김(매일 destroy/apply해도 '최근 30일')",
   "replace(hour=0, minute=0, second=0, microsecond=0)" in code and "timedelta(days=WINDOW_DAYS)" in code)

print()
print("실패 수:", fails)
sys.exit(1 if fails else 0)
