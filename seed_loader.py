"""시드 이력 적재 Lambda(baseline.tf가 apply 때 한 번 호출).

login_seed.json(같은 zip에 들어 있음)의 계정별 접속 패턴을 "오늘 기준 지난 30일"로 옮겨 login_history 테이블에 넣는다.
  - 파일에는 날짜가 아니라 (며칠째, 하루 중 몇 초, 나라)만 있다. 매일 destroy/apply해도 항상 "최근 30일"이 되게
    적재하는 순간의 KST 자정을 기준으로 시각을 계산한다(29일째 = 어제).
  - 시드 줄은 source=seed, origin=rba(공개 데이터셋에서 뽑음) 또는 synthetic(가정 패턴)으로 표시해 실제 접속(source=real)과 섞이지 않게 한다.
  - 같은 계정의 기존 시드 줄은 지우고 다시 넣는다(실제 접속 줄은 건드리지 않음).
  - 계정 이름(employee01 등) -> 실제 이메일 매핑은 Terraform이 호출할 때 넘긴다(관리자 이메일을 저장소에 적지 않기 위해).
"""
import json
import os
import time
from datetime import datetime, timedelta, timezone

import boto3

KST = timezone(timedelta(hours=9))
WINDOW_DAYS = 30
TTL_SECONDS = (WINDOW_DAYS + 1) * 86400
SEED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "login_seed.json")

_table = None


def table():
    global _table
    if _table is None:
        _table = boto3.resource("dynamodb", region_name=os.environ.get("AWS_REGION", "ap-northeast-2")).Table(
            os.environ.get("HISTORY_TABLE", "login_history"))
    return _table


def seed_items(seed, accounts, now_ts):
    """시드 파일 + 계정 매핑 -> 넣을 줄 목록. 파일에 없는 계정/빈 이메일은 건너뛴다(예: 평소 쓰지 않는 비상 관리자)."""
    midnight = datetime.fromtimestamp(now_ts, KST).replace(hour=0, minute=0, second=0, microsecond=0)
    start = midnight - timedelta(days=WINDOW_DAYS)          # 0일째 = 30일 전, 29일째 = 어제
    origin = seed.get("origin", "synthetic")
    items, seen = [], set()
    for slot, data in (seed.get("slots") or {}).items():
        email = (accounts.get(slot) or "").strip().lower()
        if not email:
            continue
        for day, sec, country in data.get("events", []):
            day, sec = int(day), int(sec)
            if not (0 <= day < WINDOW_DAYS and 0 <= sec < 86400):
                continue
            ts = int((start + timedelta(days=day, seconds=sec)).timestamp())
            while (email, ts) in seen:       # 같은 초에 두 번 있으면 키가 겹치므로 1초씩 밀기
                ts += 1
            seen.add((email, ts))
            items.append({"identity": email, "ts": ts, "country": str(country or "").upper()[:2],
                          "source": "seed", "origin": origin, "persona": data.get("persona", ""),
                          "expires_at": ts + TTL_SECONDS})
    return items


def delete_old_seed(identity):
    """그 계정의 기존 시드 줄만 지운다(source=real은 남김)."""
    t, kwargs, deleted = table(), {}, 0
    while True:
        resp = t.query(KeyConditionExpression="#id = :id", FilterExpression="#src = :seed",
                       ExpressionAttributeNames={"#id": "identity", "#src": "source"},
                       ExpressionAttributeValues={":id": identity, ":seed": "seed"},
                       ProjectionExpression="#id, ts", **kwargs)
        with t.batch_writer() as bw:
            for it in resp.get("Items", []):
                bw.delete_item(Key={"identity": it["identity"], "ts": it["ts"]})
                deleted += 1
        if not resp.get("LastEvaluatedKey"):
            return deleted
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def handler(event, context=None):
    accounts = (event or {}).get("accounts") or {}
    with open(SEED_FILE, encoding="utf-8") as f:
        seed = json.load(f)
    items = seed_items(seed, accounts, int(time.time()))
    deleted = sum(delete_old_seed(e) for e in sorted({i["identity"] for i in items}))
    with table().batch_writer() as bw:
        for it in items:
            bw.put_item(Item=it)
    per_account = {}
    for it in items:
        per_account[it["identity"]] = per_account.get(it["identity"], 0) + 1
    summary = {"origin": seed.get("origin"), "written": len(items), "deleted_old_seed": deleted, "per_account": per_account}
    print("[SEED_LOADED]", json.dumps(summary, ensure_ascii=False))
    return summary
