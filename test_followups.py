"""측정 후 수정 4건 검사: KST 알림 / device_unmanaged 유예 / brute_force 신호 분리 / idor 알림 필드. 실행: python test_followups.py"""
import json, os, sys, time
from unittest.mock import MagicMock, patch

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ.update(PDP_EVALUATE_URL="https://pdp.test/evaluate", EVALUATE_SHARED_SECRET="s3cret")
sys.modules["boto3"] = MagicMock()
fails = 0


def ok(name, cond, detail=""):
    global fails
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        fails += 1
        print(f"    -> {detail}")


rd = lambda f: open(os.path.join(HERE, f), encoding="utf-8").read()

# 1. KST
elk = rd("templates/user_data_elk.sh.tpl")
ok("Logstash가 zt.kst_time(UTC+9) 생성", "[zt][kst_time]" in elk and "9 * 3600" in elk)
ok("Discord 알림 시각이 @timestamp가 아니라 zt.kst_time", '"@timestamp"' not in elk and elk.count('"zt.kst_time"') == 2)

# 2. device_unmanaged
import risk_score_engine as e
now = int(time.time())
DEV = "01a16dae-7040-1d67-aca9-b05dc71233c1"
def rec(secs_ago, ident="kim@xmcda.store"):
    return {"device_id": DEV, "identity": ident, "active_until": now - secs_ago + e.DEVICE_ACTIVE_SECONDS}
def derive(items, ident="kim@xmcda.store"):
    e.device_state_table = MagicMock(); e.device_state_table.scan.return_value = {"Items": items}
    with patch.object(e, "sweep_signal_for", return_value=None):
        return e.derive_device_signals({"device_context": True, "identity": ident})
ok("기기 ID 없음 + 기록 없음 -> device_unmanaged", derive([]) == ["device_unmanaged"])
ok("기기 ID 없음 + 2분 전 기기 기록 -> 오탐 아님", derive([rec(120)]) == [])
ok("기기 ID 없음 + 기록이 오래됨(10분) -> device_unmanaged", derive([rec(600)]) == ["device_unmanaged"])
ok("다른 사람의 기록은 인정 안 함", derive([rec(60, "lee@xmcda.store")]) == ["device_unmanaged"])
e.device_state_table = MagicMock(); e.device_state_table.scan.side_effect = RuntimeError("down")
with patch.object(e, "sweep_signal_for", return_value=None):
    ok("기록 조회 실패 -> 기존처럼 device_unmanaged(안전한 쪽)", e.derive_device_signals({"device_context": True, "identity": "kim@xmcda.store"}) == ["device_unmanaged"])
e.device_state_table = MagicMock(); e.device_state_table.scan.return_value = {"Items": [rec(60)]}
with patch.object(e, "sweep_signal_for", return_value="device_posture_failed"):
    ok("유예 중이어도 순찰이 본 나쁜 상태(방화벽 꺼짐)는 반영", e.derive_device_signals({"device_context": True, "identity": "kim@xmcda.store"}) == ["device_posture_failed"])

# 3. brute_force
src = rd("auth_app.py")
ok("엔진 신호는 has_recent_brute_force, 잠금 화면은 check_brute_force로 분리",
   "brute_force_flag = has_recent_brute_force(email)" in src and src.count("if check_brute_force(email):") >= 3)
try:
    import auth_app as aa
    counts = {5: 0, 60: 0}
    with patch.object(aa, "recent_failure_count", lambda email, m: counts[m]):
        ok("실패 0회: 잠금 아님/신호 아님", not aa.check_brute_force("a") and not aa.has_recent_brute_force("a"))
        counts.update({5: 0, 60: 6})
        ok("잠금은 풀렸지만(5분 0회) 최근 60분에 6회 실패 -> 신호는 켜짐, 잠금은 아님", not aa.check_brute_force("a") and aa.has_recent_brute_force("a"))
        counts.update({5: 5, 60: 5})
        ok("5분에 5회 -> 잠금 + 신호", aa.check_brute_force("a") and aa.has_recent_brute_force("a"))
        counts.update({5: 0, 60: 4})
        ok("60분에 4회(임계 미만) -> 신호 아님", not aa.has_recent_brute_force("a"))
except ImportError as ex:
    print("[SKIP] auth_app import 불가:", ex)

# 4. idor 알림 필드
import zt_authz as z, zt_risk
line = json.dumps({"identity": "kim@xmcda.store", "host": "xmcda.store", "uri": "/payslip/210", "authz": "owner_mismatch",
                   "status": "404", "country": "kr", "client_ip": "203.0.113.5"})
ev = z.parse_line(line)
ok("로그 줄에서 나라/IP를 읽음(대문자/정규화)", ev.get("country") == "KR" and ev.get("client_ip") == "203.0.113.5", ev)
bad = z.parse_line(json.dumps({"identity": "kim@xmcda.store", "host": "xmcda.store", "uri": "/", "authz": "owner_mismatch", "country": "zzz!", "client_ip": "x"}))
ok("형식이 이상한 나라/IP는 버림", "country" not in bad and "client_ip" not in bad, bad)
events = []
with patch.object(zt_risk, "log_event", lambda name, **kw: events.append((name, kw))), patch("requests.post") as post:
    post.return_value = MagicMock(status_code=200, json=MagicMock(return_value={"action": "block_until_mfa", "score": 90}))
    z.report(ev, 3)
kw = dict(events)["idor_reported"]
ok("idor_reported에 action/score/signals/country/client_ip", kw.get("action") == "block_until_mfa" and kw.get("score") == 90
   and kw.get("signals") == ["resource_owner_mismatch"] and kw.get("country") == "KR" and kw.get("client_ip") == "203.0.113.5", kw)
events.clear()
with patch.object(zt_risk, "log_event", lambda name, **kw: events.append((name, kw))), patch("requests.post", side_effect=RuntimeError("x")):
    z.report(ev, 3)
ok("엔진 호출 실패해도 필드 채움(action 기본값)", dict(events)["idor_reported"].get("action") == "user_risk_set")
tpl = rd("templates/user_data_web.sh.tpl")
ok("nginx zt_authz 로그에 country/client_ip", '"country":"$http_cf_ipcountry"' in tpl and '"client_ip":"$http_cf_connecting_ip"' in tpl)

# 5. 임시 검색창
ok("search_deployments 코드 없음(저장소에 남아 있지 않음)", all("search_deployments" not in rd(f) for f in ("portal_app.py", "app.py", "demo_data.py")))
print("\n실패 수:", fails); sys.exit(1 if fails else 0)
