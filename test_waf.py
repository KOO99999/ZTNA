"""WAF(ModSecurity + OWASP CRS) 신원 연결(zt_waf.py)과 배포 설정 검사.
tests_waf/의 로그는 실제 nginx 1.24 + libmodsecurity 3.0.12 + CRS v3.3.9로 이 저장소의 설정(user_data_web.sh.tpl)을
렌더링해 띄운 뒤 공격 요청을 보내 얻은 줄이다(SQL 삽입, 경로 조작+명령 실행, XSS, 스캐너 UA / 로그인 서버 SQL 삽입).
필요 패키지: requests"""
import os
import re
import sys
import tempfile
import threading
import time
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ.update(PDP_EVALUATE_URL="https://pdp.test/evaluate", EVALUATE_SHARED_SECRET="s3cret")
import zt_risk
import zt_waf

fails = 0


def ok(name, cond, detail=""):
    global fails
    fails += (not cond)
    print(("[PASS] " if cond else "[FAIL] ") + name + ("" if cond else f"\n    -> {detail}"))


def read(rel):
    return open(os.path.join(HERE, rel), encoding="utf-8").read().replace("\r\n", "\n")


# ---------- 1. 실제 로그 해석 ----------
app_lines = [l for l in read("tests_waf/sample_app.log").splitlines() if l.strip()]
auth_lines = [l for l in read("tests_waf/sample_auth.log").splitlines() if l.strip()]
parsed = [zt_waf.parse_line(l) for l in app_lines]
ok("SQL 삽입 차단 -> 검증된 신원(kim) + waf_sqli",
   parsed[0] == {"identity": "kim@xmcda.store", "host": "dev.xmcda.store", "path": "/list",
                 "signals": ["waf_sqli"], "scores": {"sqli": 20}}, parsed[0])
ok("경로 조작/명령 실행 차단 -> waf_attack (점수 lfi, rce)",
   parsed[1] and parsed[1]["identity"] == "lee@xmcda.store" and parsed[1]["signals"] == ["waf_attack"]
   and parsed[1]["scores"] == {"rce": 5, "lfi": 25}, parsed[1])
ok("XSS 차단 -> waf_attack", parsed[2] and parsed[2]["signals"] == ["waf_attack"] and parsed[2]["host"] == "admin.xmcda.store", parsed[2])
ok("스캐너 UA로만 막힌 요청(공격 점수 0) -> 사람에게 위험을 걸지 않음", parsed[3] is None, parsed[3])
ok("로그인 서버 단계 차단(신원 없음) -> 알리지 않음", all(zt_waf.parse_line(l) is None for l in auth_lines))
ok("클라이언트가 보낸 X-ZT-Identity(victim)는 기록에 없음(앞단이 검증된 값으로 덮어씀)",
   all("victim" not in l for l in app_lines))

warn = app_lines[0].replace("ModSecurity: Access denied with code 403 (phase 2).", "ModSecurity: Warning.")
ok("DetectionOnly(경고만) 줄은 알리지 않음", zt_waf.parse_line(warn) is None)
other_rule = app_lines[0].replace('[id "949110"]', '[id "942100"]')
ok("차단 규칙(949110) 줄이 아니면 무시", zt_waf.parse_line(other_rule) is None)
for bad, label in ((app_lines[0].replace("zt_identity=kim@xmcda.store", "zt_identity=kim"), "이메일 형식 아님"),
                   (app_lines[0].replace("zt_identity=kim@xmcda.store", "zt_identity="), "신원 비어 있음"),
                   (app_lines[0].replace("zt_host=dev.xmcda.store", "zt_host=dev.xmcda.store/../x"), "호스트 이상")):
    ok(f"기록 내용 이상({label}) -> 알리지 않음", zt_waf.parse_line(bad) is None)
ok("잘못된 줄/빈 줄 -> None", zt_waf.parse_line("garbage") is None and zt_waf.parse_line("") is None)
ok("엔진 신호 이름: SQL 삽입은 waf_sqli, 그 외 공격은 waf_attack",
   zt_waf.SCORE_SIGNAL["sqli"] == "waf_sqli" and {zt_waf.SCORE_SIGNAL[k] for k in ("xss", "rce", "lfi", "rfi", "php", "fixation")} == {"waf_attack"})

# ---------- 2. 같은 사람 반복 알림 억제 ----------
zt_waf._last_reported.clear()
ev = dict(parsed[0])
ok("처음 공격은 알림", zt_waf.should_report(ev, now=1000))
ok("60초 안 같은 사람/같은 종류는 다시 알리지 않음(공격 도구 폭주 대비)", not zt_waf.should_report(ev, now=1059))
ok("다른 종류(waf_attack)는 따로 알림", zt_waf.should_report({**ev, "signals": ["waf_attack"]}, now=1010))
ok("60초가 지나면 다시 알림", zt_waf.should_report(ev, now=1061))

# ---------- 3. 엔진에 알리기 + 캐시 지우기 ----------
sent = []


class _R:
    def __init__(self, code): self.status_code = code


def fake_post(url, **kw):
    sent.append((url, kw))
    return _R(200)


zt_risk._cache.clear()
zt_risk._cache[("kim@xmcda.store", "dev.xmcda.store/list")] = {"expires_at": time.time() + 300, "country": "KR", "result": {"allow": True}}
zt_risk._cache[("kim@xmcda.store", "admin.xmcda.store/")] = {"expires_at": time.time() + 300, "country": "KR", "result": {"allow": True}}
zt_risk._cache[("lee@xmcda.store", "hr.xmcda.store/")] = {"expires_at": time.time() + 300, "country": "KR", "result": {"allow": True}}
with patch.object(zt_waf.requests, "post", fake_post):
    res = zt_waf.report(parsed[0])
body = sent[0][1]["json"] if sent else {}
ok("엔진(PDP)에 공유 비밀키로 알림", sent and sent[0][0] == "https://pdp.test/evaluate"
   and sent[0][1]["headers"]["X-Evaluate-Secret"] == "s3cret" and res is True, sent)
ok("알리는 내용: 신원 + 신호 + persist_risk(해제 불가 위험으로 저장) + 출처 waf + 자원",
   body.get("identity") == "kim@xmcda.store" and body.get("waf_sqli") is True and body.get("persist_risk") is True
   and body.get("source") == "waf" and body.get("resource_path") == "dev.xmcda.store/list" and "waf_attack" not in body, body)
ok("그 사람의 '통과' 캐시는 모든 앱에서 지움(다음 요청부터 바로 엔진이 다시 판단), 다른 사람 캐시는 유지",
   list(zt_risk._cache.keys()) == [("lee@xmcda.store", "hr.xmcda.store/")], list(zt_risk._cache.keys()))

zt_waf._last_reported.clear()
zt_waf.should_report(parsed[1], now=time.time())
with patch.object(zt_waf.requests, "post", lambda url, **kw: _R(500)):
    res = zt_waf.report(parsed[1])
ok("엔진 오류면 실패로 보고, 다음 공격 때 바로 다시 알리도록 억제 기록을 지움",
   res is False and zt_waf.should_report(parsed[1], now=time.time()))
with patch.object(zt_waf.requests, "post", lambda url, **kw: (_ for _ in ()).throw(OSError("down"))):
    ok("엔진 호출 예외도 실패로 처리(서비스는 계속)", zt_waf.report(parsed[1]) is False)

# ---------- 4. 로그 따라 읽기(tail): 새 줄만, 덜 써진 줄, 교체, 잘림 ----------
tmp = tempfile.mkdtemp()
logp = os.path.join(tmp, "zt_waf_app.log")
with open(logp, "w") as f:
    f.write("OLD LINE BEFORE START\n")
stop = threading.Event()
got = []


def run():
    for line in zt_waf._follow(logp, sleep=lambda s: time.sleep(0.02), stop=stop.is_set):
        got.append(line)


th = threading.Thread(target=run, daemon=True)
th.start()
time.sleep(0.1)
with open(logp, "a") as f:
    f.write("line1\nline2-par")
    f.flush()
    time.sleep(0.1)
    f.write("tial\n")
time.sleep(0.2)
# logrotate(이름 바꾸고 새 파일)는 리눅스 서버 동작이다. Windows는 열려 있는 파일의 이름을 바꿀 수 없어
# (WinError 32) 이 단계만 리눅스에서 검사한다(실제 서버는 Ubuntu).
ROTATE_TESTABLE = os.name != "nt"
if ROTATE_TESTABLE:
    os.rename(logp, logp + ".1")
    with open(logp, "w") as f:
        f.write("after-rotate\n")
    time.sleep(0.3)
with open(logp, "w") as f:                       # 잘림(copytruncate 같은 경우)
    f.write("x\n")
time.sleep(0.3)
stop.set()
th.join(1)
ok("시작 전 기록은 다시 처리하지 않고 새 줄만 읽음", "OLD LINE BEFORE START" not in got and got[:2] == ["line1", "line2-partial"], got)
ok("덜 써진 줄은 끝까지 써진 뒤 한 줄로 읽음", "line2-par" not in got and "line2-partial" in got, got)
if ROTATE_TESTABLE:
    ok("로그 교체(rotate) 뒤 새 파일을 처음부터 읽음", "after-rotate" in got, got)
else:
    print("[SKIP] 로그 교체(rotate) 검사는 리눅스에서만(Windows는 열린 파일 이름 변경 불가) - 서버(Ubuntu)에서는 동작")
ok("로그가 잘리면(truncate) 다시 처음부터 읽음", "x" in got, got)

# ---------- 5. 시작 ----------
started = []
with patch.object(zt_waf.threading, "Thread", lambda **kw: type("T", (), {"start": lambda self: started.append(kw["name"])})()):
    zt_waf._started = False
    zt_waf.start()
    zt_waf.start()
ok("리포터 스레드는 한 번만 시작", started == ["zt-waf-reporter"], started)
gate = read("auth_gate.py")
ok("auth_gate: ZT_WAF_ENABLED=1일 때만 리포터 시작(위험도 캐시와 같은 프로세스)",
   'if os.environ.get("ZT_WAF_ENABLED") == "1":' in gate and "zt_waf.start()" in gate)

# ---------- 6. 배포 설정(user_data_web.sh.tpl / Terraform) ----------
tpl = read("templates/user_data_web.sh.tpl")
site = tpl.split("cat << 'NGINX' > /etc/nginx/sites-available/default")[1].split("\nNGINX\n")[0]
modsec = tpl.split("cat << 'MODSEC' > /etc/nginx/zt-modsec/main.conf")[1].split("\nMODSEC\n")[0]
servers = re.split(r"\nserver \{", site)[1:]
by_listen = {re.search(r"listen ([^;]+);", s).group(1): s for s in servers}
front_app = by_listen["80 default_server"]
front_auth = by_listen["80"]
waf_app = by_listen["127.0.0.1:8081"]
waf_auth = by_listen["127.0.0.1:8082"]
ok("WAF 단계는 127.0.0.1에서만 받음(외부에서 X-ZT-Identity를 직접 넣을 수 없음)", "127.0.0.1:8081" in by_listen and "127.0.0.1:8082" in by_listen)
ok("앞단(80)에는 WAF를 켜지 않고, 내부 단계 두 곳에만 켬",
   "modsecurity on" not in front_app and "modsecurity on" not in front_auth
   and "modsecurity on;" in waf_app and "modsecurity on;" in waf_auth)
ok("앞단(앱): 신원 확인(auth_request) 후 검증된 신원으로 X-ZT-Identity를 덮어써 WAF 단계로",
   "auth_request /_zt_auth;" in front_app and "auth_request_set $zt_identity $upstream_http_x_zt_identity;" in front_app
   and "proxy_set_header X-ZT-Identity $zt_identity;" in front_app and "proxy_pass http://127.0.0.1:8081;" in front_app)
ok("앞단(로그인 서버): 신원 헤더를 비워서 WAF 단계로(로그인 전 공격은 사람과 연결 안 함)",
   'proxy_set_header X-ZT-Identity "";' in front_auth and "proxy_pass http://127.0.0.1:8082;" in front_auth)
ok("WAF 단계(앱): 앱으로는 신원 헤더를 넘기지 않음 + mTLS 유지",
   'proxy_set_header X-ZT-Identity "";' in waf_app and "proxy_ssl_verify              on;" in waf_app
   and "proxy_ssl_name app.zt.internal;" in waf_app)
ok("WAF 단계(로그인 서버): mTLS 유지", "proxy_ssl_name auth.zt.internal;" in waf_auth and "proxy_ssl_verify              on;" in waf_auth)
ok("차단 기록 로그 분리: 앱 단계만 판단 서비스가 읽는 파일",
   "error_log /var/log/modsec/zt_waf_app.log warn;" in waf_app and "error_log /var/log/modsec/zt_waf_auth.log warn;" in waf_auth)
ok("차단 화면은 named location(실측에서 차단 기록이 정상으로 남는 방식)",
   "error_page 403 @zt_waf_blocked;" in waf_app and "location @zt_waf_blocked {" in waf_app)
ok("앱이 직접 보낸 403은 그대로 통과(proxy_intercept_errors 미사용)", "proxy_intercept_errors" not in site)
ok("앞단의 기존 보호 유지: 평문 이메일 헤더 제거, 임계값 헤더 덮어쓰기",
   'proxy_set_header Cf-Access-Authenticated-User-Email "";' in front_app and "proxy_set_header X-ZT-Threshold $zt_threshold;" in front_app)
ok("ModSecurity: 동작 모드는 Terraform 변수", "SecRuleEngine ${waf_engine_mode}" in modsec)
ok("ModSecurity: CRS 설정과 규칙을 읽음", "Include /etc/nginx/zt-modsec/crs-setup.conf" in modsec and "Include /etc/nginx/zt-modsec/crs-rules/*.conf" in modsec)
ok("ModSecurity: 차단 규칙 949110에 신원/공격 점수 기록 + 원래 동작(deny) 유지",
   'SecRuleUpdateActionById 949110 "deny,status:403,logdata:' in modsec and "zt_identity=%%{REQUEST_HEADERS.x-zt-identity}" in modsec
   and "sqli=%%{tx.sql_injection_score}" in modsec)
ok("Terraform 템플릿 이스케이프: ModSecurity 변수는 %%{ 로 적음(%{ 는 Terraform 지시어로 해석됨)",
   not re.search(r"(?<!%)%\{", modsec), re.findall(r"(?<!%)%\{[^}]*\}", modsec))
ok("CRS: 고정 버전을 받고 커밋 해시가 다르면 부팅 중단",
   "--branch ${crs_version}" in tpl and 'if [ "$(git -C "$CRS_TMP" rev-parse HEAD 2>/dev/null)" != "${crs_commit}" ]; then' in tpl
   and tpl.index("exit 1", tpl.index("CRS commit mismatch")) < tpl.index("cat << 'NGINX'"))
ok("WAF 로그 교체(logrotate) 후 nginx가 파일을 다시 열게 함", "/var/log/modsec/*.log {" in tpl and "invoke-rc.d nginx rotate" in tpl)
ok("판단 서비스: 코드(zt_waf.py 포함)는 S3에서 받고 ZT_WAF_ENABLED/로그 경로 환경변수 설정",
   "for name in ('auth_gate.py', 'zt_jwt.py', 'zt_risk.py', 'zt_waf.py'):" in tpl and "s3.download_file('${code_bucket}', 'web/' + name" in tpl
   and "ZT_WAF_ENABLED=1" in tpl and "ZT_WAF_LOG=/var/log/modsec/zt_waf_app.log" in tpl)
ok("코드 받기 실패하면 부팅 중단, 코드 버전(해시)이 user_data에 들어가 코드가 바뀌면 서버 교체",
   "test -s /opt/ztgate/auth_gate.py || {" in tpl and "${web_code_version}" in tpl
   and tpl.index("s3.download_file") < tpl.index("systemctl enable --now ztgate"))
cb = read("code_bucket.tf")
ok("S3: 웹 서버 역할은 자기 코드(web/) GetObject만", '"web/zt_waf.py"    = "${path.module}/zt_waf.py"' in cb
   and 'resource "aws_iam_role_policy" "web_code_read"' in cb and "role = aws_iam_role.ec2_role.id" in cb)
ok("웹 서버는 코드 파일과 읽기 권한이 생긴 뒤 생성", "aws_s3_object.web_code, aws_iam_role_policy.web_code_read]" in read("ec2_web.tf"))
ok("Ubuntu 24.04(PEP 668): 판단 서비스는 전용 가상환경으로 실행",
   "python3 -m venv /opt/ztgate/venv" in tpl and "ExecStart=/opt/ztgate/venv/bin/python -m gunicorn" in tpl
   and "pip3 install" not in tpl and "  if python3 -c" not in tpl)
ok("nginx ModSecurity 모듈 패키지 설치", "apt-get install -y nginx libnginx-mod-http-modsecurity" in tpl)

ec2 = read("ec2_web.tf")
net = read("network.tf")
var = read("variables.tf")
ok("웹 서버만 Ubuntu 24.04 이미지", "ami                  = data.aws_ami.ubuntu_noble.id" in ec2
   and 'values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]' in net)
ok("CRS v3.3.9를 커밋 해시로 고정", 'crs_version     = "v3.3.9"' in ec2 and 'crs_commit      = "29240641f78ddb535313eec2a322a89e6520b7e5"' in ec2)
ok("waf_engine_mode 변수: On/DetectionOnly만 허용, 기본 On",
   'variable "waf_engine_mode"' in var and 'contains(["On", "DetectionOnly"], var.waf_engine_mode)' in var)

app = read("auth_app.py")
ok("로그인 서버의 정규식 SQL 검사 제거(정상 비밀번호 오탐, 남의 이메일로 기록되는 문제) -> WAF가 대신 검사",
   "detect_sqli" not in app and "SQLI_PATTERN" not in app)

print(f"\n실패 {fails}건")
sys.exit(1 if fails else 0)
