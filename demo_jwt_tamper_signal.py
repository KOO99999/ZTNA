"""JWT 위변조 -> jwt_tamper 신호 데모 (demo_jwt_forgery.py의 다음 단계: 막기만 하던 것을 '신호'로 받는다)
====================================================================
같은 IP가 위조 토큰을 반복해서 던지면: 매번 auth_gate가 403으로 막고(1차 방어), 5번째에 '진짜 엔진'(risk_score_engine.py)에
jwt_tamper 신호가 전달되어 점수 90/차단으로 판정·기록된다. DynamoDB(boto3)만 가짜, 판단은 진짜 엔진 코드.
실행: 프로젝트 폴더에서 python demo_jwt_tamper_signal.py     필요 패키지: flask pyjwt cryptography requests
====================================================================
"""
import contextlib, io, json, os, sys, time
from unittest.mock import MagicMock

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa

SECRET = "demo-secret-local-only"
_tbl = MagicMock(); _tbl.query.return_value = {"Items": []}; _tbl.scan.return_value = {"Items": []}; _tbl.get_item.return_value = {}
_boto = MagicMock(); _boto.resource.return_value.Table.return_value = _tbl
sys.modules["boto3"] = _boto
os.environ.update(PDP_EVALUATE_URL="https://pdp.test/evaluate", EVALUATE_SHARED_SECRET=SECRET, AUTH_DOMAIN="auth.xmcda.store",
                  CF_TEAM_DOMAIN="team-demo.cloudflareaccess.com", CF_ACCESS_AUDS="aud-portal")
sys.path.insert(0, ".")
import risk_score_engine as engine, zt_jwt as zj, zt_risk as zr, zt_jwt_signal as sig, auth_gate as ag
engine.ABUSEIPDB_API_KEY = None

EVIL, GOOD = rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 2048)
zj._fetch_jwks = lambda: {"kid-good": GOOD.public_key()}
zj._jwks.update({"keys": {}, "fetched_at": 0.0})
engine_calls = []

def via_real_engine(url, headers=None, json=None, timeout=None):
    import json as j
    resp = engine.lambda_handler({"headers": {"x-evaluate-secret": headers["X-Evaluate-Secret"]}, "body": j.dumps(json)}, None)
    body = j.loads(resp["body"]); engine_calls.append((json, body))
    return MagicMock(status_code=resp["statusCode"], json=MagicMock(return_value=body))

zr.requests.post = via_real_engine
sig.requests.post = via_real_engine
client = ag.app.test_client()

def forged():
    now = int(time.time())
    return pyjwt.encode({"email": "hana@xmcda.store", "iss": "https://team-demo.cloudflareaccess.com", "aud": ["aud-portal"],
                         "iat": now, "exp": now + 300}, EVIL, algorithm="RS256", headers={"kid": "kid-good"})

print("=" * 66); print(" 위조 토큰 반복 -> jwt_tamper 신호 (같은 IP 203.0.113.50)"); print("=" * 66)
for i in range(1, 7):
    before = len(engine_calls)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = client.get("/auth", headers={"X-Original-URI": "/admin", "X-Original-Host": "admin.xmcda.store",
                                         "Cf-Connecting-Ip": "203.0.113.50", "Cf-Access-Jwt-Assertion": forged()})
    time.sleep(0.3)   # 신호 보고는 백그라운드 스레드
    print(f"  {i}번째 위조  -> HTTP {r.status_code}  X-ZT-Action={r.headers.get('X-ZT-Action')}  엔진에 알림: {'예' if len(engine_calls) > before else '아니오'}")
time.sleep(0.5)
print(f"\n  엔진이 받은 호출 수: {len(engine_calls)} (5번째에 1번, 6번째는 같은 창이라 다시 알리지 않음)")
if engine_calls:
    req, res = engine_calls[0]
    print(f"  보낸 내용  : jwt_tamper={req.get('jwt_tamper')} client_ip={req.get('client_ip')} identity={req.get('identity')} (신원 없음)")
    print(f"  엔진 판정  : score={res['score']} action={res['action']} allow={res['allow']} reasons={res['reasons']}")
print("\n 정상 사용자의 만료 토큰은 403이지만 신호로는 세지 않는다(오탐 방지):")
sig._hits.clear(); sig._reported_at.clear()
with contextlib.redirect_stdout(io.StringIO()):
    now = int(time.time())
    old = pyjwt.encode({"email": "hana@xmcda.store", "iss": "https://team-demo.cloudflareaccess.com", "aud": ["aud-portal"],
                        "iat": now - 900, "exp": now - 10}, GOOD, algorithm="RS256", headers={"kid": "kid-good"})
    for _ in range(10):
        r = client.get("/auth", headers={"X-Original-URI": "/", "X-Original-Host": "xmcda.store", "Cf-Connecting-Ip": "198.51.100.5", "Cf-Access-Jwt-Assertion": old})
print(f"  만료 토큰 10번 -> HTTP {r.status_code}, 세어진 IP 수: {len(sig._hits)}")
