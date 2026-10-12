"""risk_admin.py(User Risk 목록/해제 전용 Lambda)를 실제 AWS 없이 검증.
권한(관리자 목록), 자기 해제 금지, 입력 검증, 해제 기록(user_risk + risk_score_log), 실패 처리를 확인한다."""
import json
import os
import sys
from unittest.mock import MagicMock

os.environ["ADMIN_EMAILS"] = "Admin@Test.com, breakglass@test.com"
sys.modules['boto3'] = MagicMock()
import boto3

mock_user_risk = MagicMock()
mock_audit = MagicMock()
boto3.resource.return_value.Table.side_effect = lambda name: mock_user_risk if name == 'user_risk' else mock_audit

sys.path.insert(0, '.')
import risk_admin as ra
import risk_score_engine as engine

fails = 0

def check(name, cond, detail=""):
    global fails
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f"\n    -> {detail}" if detail else ""))
    if not cond:
        fails += 1

class CondFail(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"}}

def reset():
    mock_user_risk.reset_mock(side_effect=True, return_value=True)
    mock_audit.reset_mock(side_effect=True, return_value=True)

def call(event):
    return ra.lambda_handler(event, None)

# ---- 설정 일관성 ----
check("STICKY_SIGNALS가 엔진(risk_score_engine.py)과 같음", sorted(ra.STICKY_SIGNALS) == sorted(engine.STICKY_SIGNALS),
      (ra.STICKY_SIGNALS, engine.STICKY_SIGNALS))

# ---- 권한: 관리자 목록 ----
for ev in ({"action": "list"}, {"action": "list", "actor": ""}, {"action": "list", "actor": "kim@test.com"},
           {"action": "release", "actor": "kim@test.com", "identity": "x@test.com", "signal": "waf_sqli"}):
    reset()
    r = call(ev)
    check(f"관리자가 아니면 거부({ev.get('action')}, actor={ev.get('actor')!r})", r == {"ok": False, "error": "forbidden"}
          and mock_user_risk.update_item.call_count == 0 and mock_user_risk.scan.call_count == 0, r)

reset()
check("event가 dict가 아니어도 안전하게 거부", call(None) == {"ok": False, "error": "forbidden"} and call("x") == {"ok": False, "error": "forbidden"})
check("ADMIN_EMAILS 환경변수가 비어 있으면 모두 거부", (lambda: (os.environ.__setitem__("ADMIN_EMAILS", ""), call({"action": "list", "actor": "admin@test.com"}))[1])() == {"ok": False, "error": "forbidden"})
os.environ["ADMIN_EMAILS"] = "Admin@Test.com, breakglass@test.com"
reset()
mock_user_risk.scan.return_value = {"Items": []}
r = call({"action": "list", "actor": "ADMIN@test.com"})
check("관리자 이메일은 대소문자/공백과 상관없이 인식", r.get("ok") is True, r)
r = call({"action": "nope", "actor": "admin@test.com"})
check("알 수 없는 action은 invalid", r == {"ok": False, "error": "invalid"}, r)

# ---- 목록 ----
reset()
mock_user_risk.scan.return_value = {"Items": [
    {"identity": "a@test.com", "signal": "waf_sqli", "status": "active", "set_at": 100, "last_seen": 150, "source": "B"},
    {"identity": "b@test.com", "signal": "threat_intel_match", "status": "active", "set_at": 200, "last_seen": 200, "source": "A"},
]}
r = call({"action": "list", "actor": "admin@test.com"})
kw = mock_user_risk.scan.call_args.kwargs
check("목록: active만 요청(FilterExpression)하고 예약어는 이름 치환", kw["FilterExpression"] == "#st = :active" and kw["ExpressionAttributeNames"] == {"#st": "status"}, kw)
check("목록: 최근에 걸린 순서", [i["identity"] for i in r["items"]] == ["b@test.com", "a@test.com"], r)
check("목록: 필요한 값만 내려줌(숫자는 int)", r["items"][0] == {"identity": "b@test.com", "signal": "threat_intel_match", "set_at": 200, "last_seen": 200, "source": "A"}, r["items"][0])

reset()
mock_user_risk.scan.side_effect = [
    {"Items": [{"identity": f"u{i}@t.com", "signal": "waf_sqli", "set_at": i} for i in range(300)], "LastEvaluatedKey": {"k": 1}},
    {"Items": [{"identity": f"v{i}@t.com", "signal": "waf_sqli", "set_at": i} for i in range(300)]},
]
r = call({"action": "list", "actor": "admin@test.com"})
check("목록: 500건에서 자르고 truncated 표시, 페이지 이어 읽기", len(r["items"]) == 500 and r["truncated"] is True and mock_user_risk.scan.call_count == 2, (len(r["items"]), r["truncated"]))

reset()
mock_user_risk.scan.side_effect = RuntimeError("down")
r = call({"action": "list", "actor": "admin@test.com"})
check("목록 조회 실패는 내부 오류 문구를 노출하지 않고 failed", r == {"ok": False, "error": "failed"}, r)

# ---- 해제 ----
reset()
r = call({"action": "release", "actor": "Admin@Test.com", "identity": "kim@test.com", "signal": "waf_sqli"})
up = mock_user_risk.update_item.call_args.kwargs
check("해제 성공", r == {"ok": True, "audit": True}, r)
check("해제: status를 released로 바꾸고 해제자(소문자 이메일)/시각 기록", up["Key"] == {"identity": "kim@test.com", "signal": "waf_sqli"}
      and up["ExpressionAttributeValues"][":released"] == "released" and up["ExpressionAttributeValues"][":by"] == "admin@test.com"
      and "released_at" in up["UpdateExpression"], up)
check("해제: active일 때만 바꾸는 조건식(ConditionExpression)", up["ConditionExpression"] == "#st = :active", up)
check("해제: 삭제(delete_item)가 아니라 상태 변경(기록 보존)", mock_user_risk.delete_item.call_count == 0)
item = mock_audit.put_item.call_args.kwargs["Item"]
check("해제: 판정 로그에 risk_release 한 줄(누가/누구/무슨 신호)", item["action"] == "risk_release" and item["identity"] == "kim@test.com"
      and item["reasons"] == ["waf_sqli", "released_by:admin@test.com"] and item["source"] == "ADMIN", item)

for label, ev in {
    "자기 자신의 신호는 해제 불가": {"identity": "Admin@test.com", "signal": "waf_sqli"},
    "해제 대상이 아닌 신호 이름": {"identity": "kim@test.com", "signal": "night_access"},
    "임의 문자열 신호": {"identity": "kim@test.com", "signal": "waf_sqli' OR 1=1"},
    "이메일 형식이 아님": {"identity": "<script>alert(1)</script>", "signal": "waf_sqli"},
    "이메일 없음": {"signal": "waf_sqli"},
    "신호 없음": {"identity": "kim@test.com"},
    "identity가 문자열이 아님": {"identity": ["kim@test.com"], "signal": "waf_sqli"},
    "너무 긴 이메일": {"identity": "a" * 300 + "@t.com", "signal": "waf_sqli"},
}.items():
    reset()
    r = call({"action": "release", "actor": "admin@test.com", **ev})
    expected = "self_release" if "자기 자신" in label else "invalid"
    check(f"해제 거부: {label}", r == {"ok": False, "error": expected} and mock_user_risk.update_item.call_count == 0
          and mock_audit.put_item.call_count == 0, r)

reset()
mock_user_risk.update_item.side_effect = CondFail("x")
r = call({"action": "release", "actor": "admin@test.com", "identity": "kim@test.com", "signal": "waf_sqli"})
check("이미 해제됐거나 없는 항목은 not_active, 기록도 남기지 않음", r == {"ok": False, "error": "not_active"} and mock_audit.put_item.call_count == 0, r)

reset()
mock_user_risk.update_item.side_effect = RuntimeError("secret internal detail")
r = call({"action": "release", "actor": "admin@test.com", "identity": "kim@test.com", "signal": "waf_sqli"})
check("DynamoDB 오류는 내부 문구를 숨기고 failed", r == {"ok": False, "error": "failed"} and "secret" not in json.dumps(r), r)

reset()
mock_audit.put_item.side_effect = RuntimeError("audit down")
r = call({"action": "release", "actor": "admin@test.com", "identity": "kim@test.com", "signal": "waf_sqli"})
check("해제는 됐는데 감사 기록이 실패하면 ok이되 audit=False로 알림", r == {"ok": True, "audit": False}, r)

reset()
r = call({"action": "release", "actor": "breakglass@test.com", "identity": "admin@test.com", "signal": "threat_intel_match"})
check("비상 관리자 계정이 다른 관리자의 신호를 해제할 수 있음", r.get("ok") is True, r)

print(f"\n실패 {fails}건" if fails else "\n모두 통과")
sys.exit(1 if fails else 0)
