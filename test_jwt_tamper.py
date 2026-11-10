"""JWT 위변조 -> IP 기준 jwt_tamper 신호(zt_jwt_signal.py, auth_gate.py, 엔진). 실행: python test_jwt_tamper.py"""
import io
import contextlib
import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ["PDP_EVALUATE_URL"] = "https://pdp.test/evaluate"
os.environ["EVALUATE_SHARED_SECRET"] = "s3cret"
os.environ["CF_TEAM_DOMAIN"] = "team-demo.cloudflareaccess.com"
os.environ["CF_ACCESS_AUDS"] = "aud-portal"
os.environ["AUTH_DOMAIN"] = "auth.xmcda.store"

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
import zt_jwt
import zt_jwt_signal as sig
import auth_gate

fails = 0


def ok(name, cond, detail=""):
    global fails
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        fails += 1
        if detail:
            print(f"    -> {detail}")


def reset():
    sig._hits.clear()
    sig._reported_at.clear()


GOOD, EVIL = rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 2048)
ISS = "https://team-demo.cloudflareaccess.com"
zt_jwt._fetch_jwks = lambda: {"kid-good": GOOD.public_key()}
zt_jwt._jwks.update({"keys": {}, "fetched_at": 0.0})


def tok(key=GOOD, exp=300):
    now = int(time.time())
    return pyjwt.encode({"email": "hana@xmcda.store", "iss": ISS, "aud": ["aud-portal"], "iat": now, "exp": now + exp},
                        key, algorithm="RS256", headers={"kid": "kid-good"})


# ---------- 1. 세기: 10분에 5번이면 알림, 그 창에서는 한 번만 ----------
reset()
res = [sig.record("1.2.3.4", now=1000 + i) for i in range(4)]
ok("4번까지는 알리지 않음", not any(r[0] for r in res), res)
ok("5번째에 알림 + 횟수 5", sig.record("1.2.3.4", now=1010) == (True, 5))
ok("알린 뒤 같은 창에서는 다시 알리지 않음", sig.record("1.2.3.4", now=1020)[0] is False)
ok("다른 IP는 따로 센다", sig.record("5.6.7.8", now=1030) == (False, 1))
ok("창(600초)이 지나면 다시 센다", sig.record("1.2.3.4", now=1010 + 700) == (False, 1))
reset()
for i in range(4):
    sig.record("9.9.9.9", now=2000 + i)
ok("오래된 시도는 창 밖으로 밀려나 세지 않음", sig.record("9.9.9.9", now=2000 + 650)[0] is False)

# ---------- 2. 센 대상 / 안 센 대상 ----------
ok("서명 위조/aud/iss/alg/형식은 센다", {"bad_signature", "bad_aud", "bad_iss", "bad_alg_or_kid", "malformed"} <= sig.TAMPER_REASONS)
ok("token_missing/expired/jwks_unavailable/config_missing은 세지 않는다(오탐 방지)",
   not ({"token_missing", "expired", "jwks_unavailable", "config_missing"} & sig.TAMPER_REASONS))
reset()
ok("expired는 몇 번을 보내도 기록 없음", not any(sig.handle("expired", "1.1.1.1", "xmcda.store", "/", background=False) for _ in range(20)) and not sig._hits)
ok("IP 헤더가 이상하면 무시(메모리 오염 방지)", sig.handle("bad_signature", "not-an-ip", "xmcda.store", "/", background=False) is False and not sig._hits)
ok("IP 정규화: 공백/여러 값 중 첫 번째", sig.normalize_ip(" 1.2.3.4 , 5.6.7.8") == "1.2.3.4" and sig.normalize_ip("2001:DB8::1") == "2001:db8::1")

# ---------- 3. 엔진 호출 내용: 신원 없이 IP만 ----------
reset()
with patch("requests.post") as post:
    post.return_value = MagicMock(status_code=200)
    for _ in range(5):
        fired = sig.handle("bad_signature", "203.0.113.7", "admin.xmcda.store", "/admin", background=False)
    ok("5번째에 엔진 호출", fired is True and post.call_count == 1)
    body = post.call_args.kwargs["json"]
    ok("본문: jwt_tamper + client_ip + source, identity 없음(남의 이메일 잠금 방지)",
       body.get("jwt_tamper") is True and body.get("client_ip") == "203.0.113.7" and body.get("source") == "gate_jwt"
       and "identity" not in body and "persist_risk" not in body, body)
    ok("공유 비밀키 헤더 사용", post.call_args.kwargs["headers"]["X-Evaluate-Secret"] == "s3cret")
with patch("requests.post", side_effect=RuntimeError("down")):
    reset()
    for _ in range(5):
        fired = sig.handle("bad_signature", "203.0.113.8", "xmcda.store", "/", background=False)
    ok("엔진 호출이 실패해도 예외 없음 + 다음 시도 때 다시 알림", fired is True and "203.0.113.8" not in sig._reported_at)

# ---------- 4. auth_gate: 위조 토큰은 항상 403, 신호가 실패해도 마찬가지 ----------
client = auth_gate.app.test_client()


def ask(token, ip="198.51.100.9"):
    h = {"X-Original-URI": "/", "X-Original-Host": "xmcda.store", "CF-IPCountry": "KR", "Cf-Connecting-Ip": ip}
    if token:
        h["Cf-Access-Jwt-Assertion"] = token
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = client.get("/auth", headers=h)
    return r, buf.getvalue()


reset()
with patch("zt_jwt_signal.threading.Thread") as th:
    codes = [ask(tok(key=EVIL))[0].status_code for _ in range(5)]
    ok("위조 토큰 5번 모두 403 + jwt_invalid", codes == [403] * 5)
    ok("5번째에 신호 보고 스레드 시작", th.call_count == 1, th.call_count)
r, log = ask(tok(key=EVIL), ip="198.51.100.10")
ok("로그에 토큰 원문(eyJ) 없음", "eyJ" not in log)
ok("로그에 jwt_verify_failed 이벤트(사유/IP)", "ZT_EVENT" in log and '"jwt_verify_failed"' in log and '"client_ip": "198.51.100.10"' in log, log[-300:])
with patch("zt_jwt_signal.handle", side_effect=RuntimeError("boom")):
    try:
        r, _ = ask(tok(key=EVIL), ip="198.51.100.11")
        ok("신호 모듈이 터져도 문제 없이 403이어야 함", r.status_code == 403)
    except Exception as e:
        ok("신호 모듈이 터져도 문제 없이 403이어야 함", False, repr(e))
reset()
for _ in range(10):
    r, _ = ask(tok(exp=-10), ip="198.51.100.12")
ok("만료 토큰(정상 사용자 실수)은 403이지만 신호는 세지 않음", r.status_code == 403 and not sig._hits)
reset()
r, _ = ask(None, ip="198.51.100.13")
ok("토큰 없음: 403, 신호 없음", r.status_code == 403 and not sig._hits)
with patch("zt_risk.requests.post") as p:
    p.return_value = MagicMock(status_code=200, json=MagicMock(return_value={"allow": True, "cache_ttl_seconds": 0, "score": 0}))
    r, _ = ask(tok())
ok("정상 토큰은 영향 없음(통과 경로 그대로)", r.status_code in (200, 403) and not sig._hits, r.status_code)

# ---------- 5. 엔진: 신호표 / sticky 제외 ----------
os.environ["EVALUATE_SHARED_SECRET"] = "s3cret"
sys.modules["boto3"] = MagicMock()
import risk_score_engine as engine
rule = engine.RISK_MATRIX.get("jwt_tamper")
ok("신호표에 jwt_tamper(security, 해제 불가, 90점, ip_based)",
   rule == {"risk": 90, "group": "security", "resettable": False, "ip_based": True}, rule)
ok("STICKY_SIGNALS에는 없음(계정에 저장되지 않음)", "jwt_tamper" not in engine.STICKY_SIGNALS)
engine.ABUSEIPDB_API_KEY = None
resp = engine.lambda_handler({"headers": {"x-evaluate-secret": "s3cret"},
                              "body": json.dumps({"jwt_tamper": True, "client_ip": "203.0.113.7", "source": "gate_jwt",
                                                  "resource_path": "/"})}, None)
out = json.loads(resp["body"])
ok("엔진 판정: 점수 90, 차단, 사유에 jwt_tamper", resp["statusCode"] == 200 and out["score"] == 90 and out["allow"] is False
   and any(x.startswith("jwt_tamper") for x in out["reasons"]), out)

# ---------- 6. 배포 / 관제 연결 ----------
tpl = open(os.path.join(HERE, "templates/user_data_web.sh.tpl"), encoding="utf-8").read()
ok("배포: S3 코드 목록과 웹 서버 다운로드 목록에 zt_jwt_signal.py",
   '"web/zt_jwt_signal.py"' in open(os.path.join(HERE, "code_bucket.tf"), encoding="utf-8").read() and "'zt_jwt_signal.py'" in tpl)
elk = open(os.path.join(HERE, "templates/user_data_elk.sh.tpl"), encoding="utf-8").read()
ok("관제: ElastAlert 즉시 대응 규칙에 jwt_tamper_reported", "jwt_tamper_reported" in elk)

print()
print("실패 수:", fails)
sys.exit(1 if fails else 0)
