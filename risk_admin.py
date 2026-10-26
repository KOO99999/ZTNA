"""User Risk 관리 전용 Lambda (목록 조회 / 해제).

왜 따로 있나: 위험 상태(user_risk)는 판단하는 쪽(risk_score_engine.py)이 소유하고, 사람이 그 상태를 바꾸는 일은
권한 검증과 기록을 거치는 이 함수 한 곳으로만 한다. 포털 앱 서버는 user_risk 테이블에 직접 쓸 권한이 없고,
이 함수를 AWS 권한(IAM, lambda:InvokeFunction)으로 호출만 한다. API Gateway도 공유 비밀키도 없고 외부에 열린 주소도 없다.

호출 형식 (boto3 lambda.invoke의 Payload, JSON):
  {"action": "list",    "actor": "<관리자 이메일>"}
  {"action": "release", "actor": "<관리자 이메일>", "identity": "<풀어줄 사람>", "signal": "<신호 이름>"}

규칙:
  - actor는 환경변수 ADMIN_EMAILS(Terraform의 admin_allowed_emails)에 있어야 한다. 호출자(포털 앱)가 이미 확인하지만
    영향이 큰 기능이라 여기서 한 번 더 확인한다(앱이 뚫려도 목록에 없는 이메일로는 못 풀게).
  - 자기 자신의 신호는 풀 수 없다(다른 관리자가 풀어야 함. 혼자일 때를 대비한 비상 관리자 계정은 문서 참고).
  - 해제는 지우는 게 아니라 status를 released로 바꾸고 누가/언제 풀었는지 남긴다. 판정 로그(risk_score_log)에도
    action=risk_release로 한 줄 남긴다.

환경변수: ADMIN_EMAILS (쉼표 구분)
"""
import json
import os
import re
import time
import uuid

import boto3

dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-2')
user_risk_table = dynamodb.Table('user_risk')
audit_table = dynamodb.Table('risk_score_log')

# risk_score_engine.STICKY_SIGNALS와 같아야 한다(test_risk_admin.py가 두 값이 같은지 검사함).
STICKY_SIGNALS = ("threat_intel_match", "waf_sqli", "waf_attack")

MAX_LIST_ITEMS = 500
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-']{1,64}@[A-Za-z0-9.\-]{1,190}$")


def _admin_emails():
    return {e.strip().lower() for e in os.environ.get('ADMIN_EMAILS', '').split(',') if e.strip()}


def _num(value):
    """DynamoDB는 숫자를 Decimal로 돌려준다 - JSON으로 보내려면 int로."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_conditional_failure(exc):
    code = getattr(exc, 'response', {}).get('Error', {}).get('Code', '') if hasattr(exc, 'response') else ''
    return code == 'ConditionalCheckFailedException' or 'ConditionalCheckFailed' in str(exc)


def _list_active():
    items, kwargs = [], {
        "FilterExpression": "#st = :active",
        "ExpressionAttributeNames": {"#st": "status"},
        "ExpressionAttributeValues": {":active": "active"},
    }
    truncated = False
    while True:
        resp = user_risk_table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if len(items) >= MAX_LIST_ITEMS:
            truncated = bool(last_key) or len(items) > MAX_LIST_ITEMS
            items = items[:MAX_LIST_ITEMS]
            break
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key
    rows = [{
        "identity": str(it.get("identity", "")),
        "signal": str(it.get("signal", "")),
        "set_at": _num(it.get("set_at")),
        "last_seen": _num(it.get("last_seen")),
        "source": str(it.get("source", "")),
    } for it in items]
    rows.sort(key=lambda r: r["set_at"] or 0, reverse=True)
    return {"ok": True, "items": rows, "truncated": truncated}


def _release(actor, identity, signal):
    if not isinstance(identity, str) or not _EMAIL_RE.match(identity):
        return {"ok": False, "error": "invalid"}
    if signal not in STICKY_SIGNALS:
        return {"ok": False, "error": "invalid"}
    if identity.strip().lower() == actor:
        return {"ok": False, "error": "self_release"}

    now_ts = int(time.time())
    try:
        user_risk_table.update_item(
            Key={"identity": identity, "signal": signal},
            UpdateExpression="SET #st = :released, released_by = :by, released_at = :now",
            ConditionExpression="#st = :active",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":released": "released", ":active": "active", ":by": actor, ":now": now_ts},
        )
    except Exception as e:
        if _is_conditional_failure(e):
            return {"ok": False, "error": "not_active"}
        print("user_risk 해제 실패:", str(e))
        return {"ok": False, "error": "failed"}

    audit_ok = True
    try:
        audit_table.put_item(Item={
            "session_id": str(uuid.uuid4()),
            "timestamp": now_ts,
            "risk_score": 0,
            "reasons": [signal, f"released_by:{actor}"],
            "allow": True,
            "action": "risk_release",
            "identity": identity,
            "resource_path": "user_risk",
            "resource_threshold": 0,
            "source": "ADMIN",
        })
    except Exception as e:
        audit_ok = False
        print("해제 기록(risk_score_log) 실패:", str(e))
    print(f"[RISK_RELEASE] actor={actor} identity={identity} signal={signal}")
    return {"ok": True, "audit": audit_ok}


def lambda_handler(event, context):
    event = event if isinstance(event, dict) else {}
    actor = str(event.get("actor", "")).strip().lower()
    if not actor or actor not in _admin_emails():
        return {"ok": False, "error": "forbidden"}

    action = event.get("action")
    if action == "list":
        try:
            return _list_active()
        except Exception as e:
            print("user_risk 목록 조회 실패:", str(e))
            return {"ok": False, "error": "failed"}
    if action == "release":
        return _release(actor, event.get("identity"), event.get("signal"))
    return {"ok": False, "error": "invalid"}
