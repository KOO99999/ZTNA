"""IDOR(앱의 객체 접근 거부) -> 엔진 알림(zt_authz.py)과 포털 급여명세서 화면 검사. 실행: python test_authz.py"""
import json
import os
import sys
from unittest.mock import MagicMock, patch

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ["PDP_EVALUATE_URL"] = "https://pdp.test/evaluate"
os.environ["EVALUATE_SHARED_SECRET"] = "s3cret"
import zt_risk
import zt_authz

fails = 0


def ok(name, cond, detail=""):
    global fails
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        fails += 1
        if detail:
            print(f"    -> {detail}")


def line(identity="kim@xmcda.store", uri="/payslip/210", authz="owner_mismatch", host="xmcda.store"):
    return json.dumps({"time": "2026-11-04T10:00:00+00:00", "identity": identity, "host": host, "uri": uri,
                       "authz": authz, "status": "404"})


def reset():
    zt_authz._hits.clear()
    zt_authz._reported_at.clear()


# ---------- 1. 한 줄 해석 ----------
e = zt_authz.parse_line(line())
ok("정상 줄: 신원/호스트/경로/사유", e == {"identity": "kim@xmcda.store", "host": "xmcda.store", "path": "/payslip/210",
                                    "reason": "owner_mismatch"}, e)
ok("신원이 비었으면(앞단 인증 없이 들어온 요청) 무시", zt_authz.parse_line(line(identity="")) is None)
ok("이메일이 아닌 신원 값은 무시", zt_authz.parse_line(line(identity="kim\" OR 1=1")) is None)
ok("모르는 사유는 무시", zt_authz.parse_line(line(authz="whatever")) is None)
ok("JSON이 아니면 무시", zt_authz.parse_line("garbage") is None and zt_authz.parse_line("[1,2]") is None)
ok("쿼리는 떼고 경로만", zt_authz.parse_line(line(uri="/payslip/210?x=1"))["path"] == "/payslip/210")

# ---------- 2. 세기: 10분에 3번이면 알림, 그 창에서는 한 번만 ----------
reset()
ev = zt_authz.parse_line(line())
r1 = zt_authz.record(ev, now=1000)
r2 = zt_authz.record(ev, now=1100)
r3 = zt_authz.record(ev, now=1200)
r4 = zt_authz.record(ev, now=1250)
ok("1~2번째는 알리지 않음(주소 실수일 수 있음), 3번째에 알림", r1 == (False, 1) and r2 == (False, 2) and r3 == (True, 3), (r1, r2, r3))
ok("알린 뒤 같은 10분 창에서는 다시 알리지 않음", r4[0] is False, r4)
reset()
zt_authz.record(ev, now=1000)
zt_authz.record(ev, now=1300)
r = zt_authz.record(ev, now=1000 + 601)
ok("10분이 지난 시도는 세지 않음(창 밖)", r == (False, 2), r)
reset()
zt_authz.record(zt_authz.parse_line(line(identity="a@xmcda.store")), now=1000)
zt_authz.record(zt_authz.parse_line(line(identity="b@xmcda.store")), now=1001)
r = zt_authz.record(zt_authz.parse_line(line(identity="a@xmcda.store")), now=1002)
ok("사람별로 따로 셈(다른 사람 시도와 합치지 않음)", r == (False, 2), r)

# ---------- 3. 엔진 알림 ----------
reset()
posted = []


def fake_post(url, timeout=None, json=None, headers=None):
    posted.append({"url": url, "json": json, "headers": headers})
    m = MagicMock()
    m.status_code = 200
    return m


zt_risk._cache[("kim@xmcda.store", "xmcda.store/")] = {"expires_at": 9e12, "country": "KR", "client_ip": None,
                                                       "session_country": None, "result": {"allow": True}}
zt_risk._last_allow[("kim@xmcda.store", "xmcda.store/")] = 1.0
import io
import contextlib
buf = io.StringIO()
with patch.object(zt_authz.requests, "post", fake_post), contextlib.redirect_stdout(buf):
    for t in (1000, 1100, 1200):
        zt_authz.handle_line(line(), now=t)
out = buf.getvalue()
ok("3번째 거부에서 엔진에 한 번 알림", len(posted) == 1, len(posted))
body = posted[0]["json"] if posted else {}
ok("알림 내용: resource_owner_mismatch + persist_risk + 출처 app_authz + 자원",
   body.get("resource_owner_mismatch") is True and body.get("persist_risk") is True and body.get("source") == "app_authz"
   and body.get("identity") == "kim@xmcda.store" and body.get("resource_path") == "xmcda.store/payslip/210", body)
ok("공유 비밀키 헤더로 호출", posted and posted[0]["headers"].get("X-Evaluate-Secret") == "s3cret")
ok("알린 사람의 통과 캐시와 장애 모드 재사용 기록을 지움(다음 요청은 엔진이 다시 판단)",
   ("kim@xmcda.store", "xmcda.store/") not in zt_risk._cache and ("kim@xmcda.store", "xmcda.store/") not in zt_risk._last_allow)
events = [json.loads(l[len("ZT_EVENT "):]) for l in out.splitlines() if l.startswith("ZT_EVENT ")]
ok("관제 기록: 거부마다 authz_denied(횟수 포함), 알림 때 idor_reported",
   [e["event"] for e in events].count("authz_denied") == 3 and [e["event"] for e in events].count("idor_reported") == 1
   and events[-1].get("count") == 3, [e["event"] for e in events])
ok("관제 기록에 비밀키 없음", "s3cret" not in out)

reset()
posted.clear()


def failing_post(*a, **k):
    raise OSError("down")


with patch.object(zt_authz.requests, "post", failing_post), contextlib.redirect_stdout(io.StringIO()):
    for t in (1000, 1100, 1200):
        zt_authz.handle_line(line(), now=t)
ok("엔진 알림 실패 -> 다음 거부 때 바로 다시 알리도록 기록 삭제", "kim@xmcda.store" not in zt_authz._reported_at)

# ---------- 3b. 본인 아님 신고: 한 번에 바로 알림, IDOR 카운트와 따로 ----------
reset()
posted.clear()
buf = io.StringIO()
with patch.object(zt_authz.requests, "post", fake_post), contextlib.redirect_stdout(buf):
    zt_authz.handle_line(line(uri="/security/ack", authz="user_reported_not_me"), now=5000)
    zt_authz.handle_line(line(uri="/security/ack", authz="user_reported_not_me"), now=5010)
    zt_authz.handle_line(line(), now=5020)   # 같은 사람의 IDOR 1번은 따로 셈(신고 때문에 IDOR가 바로 알려지지 않음)
ok("신고 1번이면 바로 엔진에 user_reported_suspicious(persist_risk), 10분 안 반복은 한 번만",
   len(posted) == 1 and posted[0]["json"].get("user_reported_suspicious") is True and posted[0]["json"].get("persist_risk") is True
   and "resource_owner_mismatch" not in posted[0]["json"], [p["json"] for p in posted])
evs = [json.loads(l[len("ZT_EVENT "):])["event"] for l in buf.getvalue().splitlines() if l.startswith("ZT_EVENT ")]
ok("관제 기록: 신고 전달은 user_report_escalated(IDOR 기록과 섞이지 않음)",
   evs.count("user_report_escalated") == 1 and "idor_reported" not in evs and evs.count("authz_denied") == 1, evs)

# ---------- 4. nginx / 배포 설정 ----------
tpl = open(os.path.join(HERE, "templates/user_data_web.sh.tpl"), encoding="utf-8").read()
ok("nginx: X-ZT-Authz가 붙은 응답만 기록(map + access_log if=)",
   "map $upstream_http_x_zt_authz $zt_authz_event" in tpl and "access_log /var/log/modsec/zt_authz_app.log zt_authz if=$zt_authz_event;" in tpl)
ok("nginx: 기록의 신원은 앞단이 덮어쓴 X-ZT-Identity, JSON 이스케이프",
   "log_format zt_authz escape=json" in tpl and '"identity":"$http_x_zt_identity"' in tpl)
ok("nginx: 사용자 응답에서는 X-ZT-Authz를 지움", "proxy_hide_header X-ZT-Authz;" in tpl)
ok("배포: 판단 서비스가 zt_authz.py를 S3에서 받고 로그 경로 설정",
   "'zt_authz.py'" in tpl and "ZT_AUTHZ_LOG=/var/log/modsec/zt_authz_app.log" in tpl
   and '"web/zt_authz.py"' in open(os.path.join(HERE, "code_bucket.tf"), encoding="utf-8").read())
gate = open(os.path.join(HERE, "auth_gate.py"), encoding="utf-8").read()
ok("판단 서비스 시작 시 zt_authz도 시작", "import zt_authz" in gate and "zt_authz.start()" in gate)

print()
print("실패 수:", fails)
sys.exit(1 if fails else 0)
