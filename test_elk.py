"""관제 콘솔(ELK + ElastAlert2 -> Discord) 설정 검사. 실행: python test_elk.py
  - 구조화 로그(ZT_EVENT {json}) 형식이 서비스마다 같은지, Logstash가 같은 규칙으로 풀 수 있는지
  - elk.tf / 템플릿: 스위치(enable_elk), 상호 TLS, 내부 바인딩, Access 보호, 최소 권한, 비밀 값 전달 방식
  - 템플릿을 Terraform 규칙대로 펼쳐 bash 문법 검사(bash가 없는 Windows에서는 건너뜀)
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import contextlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def read(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return f.read()


def ok(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")
    if not cond and detail:
        print(f"    -> {detail}")


# Logstash filter와 같은 규칙: "ZT_EVENT " 뒤의 JSON
ZT_RE = re.compile(r"ZT_EVENT (\{.*\})")


def events(text):
    return [json.loads(m.group(1)) for m in ZT_RE.finditer(text)]


# ---------- 1. 웹 서버 쪽(zt_risk.log_event) ----------
import zt_risk
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    zt_risk.log_event("gate_deny", action="block", identity="kim@xmcda.store", host="dev.xmcda.store", path="/", client_ip=None)
ev = events(buf.getvalue())
ok("웹 서버 이벤트: 한 줄 JSON, event/service/ts 공통 키, 값 없는 키는 빼고", len(ev) == 1 and ev[0]["event"] == "gate_deny"
   and ev[0]["service"] == "gate" and isinstance(ev[0]["ts"], int) and "client_ip" not in ev[0], ev)

# ---------- 2. 코드에 이벤트가 들어간 곳 ----------
eng, auth, gate, waf, adm = read("risk_score_engine.py"), read("auth_app.py"), read("auth_gate.py"), read("zt_waf.py"), read("risk_admin.py")
for ev_name in ("login_allowed", "login_blocked", "login_failed", "login_locked", "pwned_password_detected", "password_changed",
                "stepup_blocked", "stepup_no_permission", "stepup_verified", "mtls_client_rejected"):
    ok(f"로그인 서버 이벤트: {ev_name}", f'log_event("{ev_name}"' in auth)
ok("로그인 서버: 무차별 대입 잠금(로그인/로그인 TOTP/재인증 화면 2곳) 모두 기록", auth.count('log_event("login_locked"') == 4)
ok("엔진: 판단(decision)과 기기 순찰(device_sweep) 이벤트", 'log_event("decision"' in eng and 'log_event("device_sweep"' in eng)
ok("웹 서버: 차단(gate_deny) 이벤트, 점수는 엔진 이벤트에만", 'log_event("gate_deny"' in gate and "score=" not in gate.split('log_event("gate_deny"')[1][:200])
ok("WAF: 신원 연결 보고(waf_reported) 이벤트", 'log_event("waf_reported"' in waf)
ok("관리자 해제(risk_release) 이벤트", '"event": "risk_release"' in adm)

# ---------- 3. elk.tf ----------
tf, var, tpl, fb = read("elk.tf"), read("variables.tf"), read("templates/user_data_elk.sh.tpl"), read("templates/filebeat_setup.sh.tpl")
ok("스위치: enable_elk 기본 false, 관제 서버/터널/Access 앱/DNS 모두 스위치에 묶임",
   'variable "enable_elk"' in var and "default     = false" in var.split('variable "enable_elk"')[1][:200]
   and all(f'resource "{r}" "{n}" {{\n  count' in tf for r, n in (
       ("aws_instance", "elk_server"), ("cloudflare_zero_trust_tunnel_cloudflared", "elk_tunnel"),
       ("cloudflare_record", "kibana_dns"), ("cloudflare_zero_trust_access_application", "kibana"))))
ok("끄면 다른 서버에 Filebeat를 넣지 않음(빈 문자열)", 'var.enable_elk ? templatefile("${path.module}/templates/filebeat_setup.sh.tpl"' in tf
   and all("filebeat_setup = local.filebeat_setup." in read(f) for f in ("ec2_web.tf", "ec2_auth.tf", "ec2_app.tf"))
   and all(read(f"templates/user_data_{r}.sh.tpl").rstrip().endswith("${filebeat_setup}") for r in ("web", "auth", "app")))
ok("Kibana: 관리자 그룹 + 위험점수 평가(External Evaluation) Access 뒤, 우리 로그인 서버만",
   "cloudflare_zero_trust_access_policy.risk_block_shared.id" in tf.split('cloudflare_zero_trust_access_application" "kibana"')[1]
   and "cloudflare_zero_trust_access_policy.admin_gate_console.id" in tf.split('cloudflare_zero_trust_access_application" "kibana"')[1]
   and "allowed_idps              = [cloudflare_zero_trust_access_identity_provider.login_server.id]" in tf)
ok("Kibana/Elasticsearch는 서버 안(127.0.0.1)에서만, 밖으로는 전용 터널만",
   'server.host: "127.0.0.1"' in tpl and "network.host: 127.0.0.1" in tpl and "service: http://127.0.0.1:5601" in tpl)
ok("관제 서버로 들어오는 건 5044(웹/앱 티어 보안그룹에서만)", "aws_vpc_security_group_ingress_rule" in tf and tf.count("aws_vpc_security_group_ingress_rule") == 1
   and "referenced_security_group_id = each.value" in tf and "cidr_ipv4" not in tf.split('"elk_from_tiers"')[1].split("resource")[0])
ok("Filebeat -> Logstash 상호 TLS: 서버는 클라이언트 인증서 필수, Filebeat는 서버 인증서 이름까지 확인",
   'ssl_client_authentication => "required"' in tpl and "ssl.verification_mode: full" in fb
   and 'allowed_uses          = each.key == "logs" ? ["digital_signature", "server_auth"] : ["digital_signature", "client_auth"]' in tf)
ok("Logstash 개인키는 PKCS#8(beats 입력 요구사항)", "private_key_pem_pkcs8" in tf)
ok("비밀 값(비밀번호/개인키/Discord 주소)은 SecureString, user_data에는 이름만", tf.count('type     = "SecureString"') + tf.count('type  = "SecureString"') == 3
   and "discord_webhook_url" not in tf.split('resource "aws_instance" "elk_server"')[1])
ok("Discord 주소: sensitive 변수 + 형식 검사 + 켜면 필수", 'variable "discord_webhook_url"' in var and "sensitive   = true" in var.split('variable "discord_webhook_url"')[1][:120]
   and "precondition" in tf)
ok("각 서버는 자기 Filebeat 인증서/키만 읽기", "aws_ssm_parameter.elk_cert[each.key].arn, aws_ssm_parameter.elk_key[each.key].arn" in tf)
ok("관제 서버: Lambda 3개 로그만 읽기(FilterLogEvents/DescribeLogGroups)", '["logs:FilterLogEvents", "logs:DescribeLogGroups"]' in tf
   and 'elk_lambda_names = ["risk-score-engine", "zt-device-sweep", "risk-admin"]' in tf)
ok("Elasticsearch 계정 최소 권한: Logstash는 쓰기만, ElastAlert2는 읽기 + 자기 상태 인덱스만",
   '"names":["zt-logs-*"],"privileges":["create_index","create_doc","write"]' in tpl
   and '"names":["zt-logs-*"],"privileges":["read","view_index_metadata"]' in tpl)
ok("IMDSv2 강제 + 디스크 암호화", 'http_tokens                 = "required"' in tf and "encrypted   = true" in tf)
ok("ElastAlert2 버전 고정 + 규칙 3개(즉시 대응/반복 차단/엔진 장애) + Discord",
   '"elastalert2==2.31.0"' in tpl and tpl.count("alert:\n  - discord") == 3 and "zt_pdp_unavailable.yaml" in tpl)
ok("알림 조건에 쓰는 필드가 실제 이벤트 이름과 같음",
   all(n in eng + auth + gate + waf + adm for n in ("waf_reported", "login_locked", "device_session_revoked", "pdp_unavailable", "risk_release")))
ok("Logstash 날짜/인덱스: Terraform 이스케이프(%%{, $${) 사용", "zt-logs-%%{+YYYY.MM.dd}" in tpl and 'password => "$${LS_ES_PW}"' in tpl)

# ---------- 4. 템플릿 펼치기 + bash 문법 검사 ----------
def render(text, v):
    lines = text.split("\n")

    def sub(line, vv):
        line = line.replace("$${", "\x00").replace("%%{", "\x01")
        line = re.sub(r"\$\{([^}]*)\}", lambda m: str(vv[m.group(1).strip()]), line)
        return line.replace("\x00", "${").replace("\x01", "%{")

    def block(ls, vv):
        res, i = [], 0
        while i < len(ls):
            m = re.match(r"\s*%\{ (for (\w+) in (\w+)|if length\((\w+)\) > 0) ~\}\s*$", ls[i])
            if m:
                depth, j = 1, i + 1
                while depth:
                    if re.match(r"\s*%\{ (for|if) ", ls[j]):
                        depth += 1
                    if re.match(r"\s*%\{ end(for|if) ~\}", ls[j]):
                        depth -= 1
                    j += 1
                inner = ls[i + 1:j - 1]
                if m.group(2):
                    for item in vv[m.group(3)]:
                        res += block(inner, {**vv, m.group(2): item})
                elif vv[m.group(4)]:
                    res += block(inner, vv)
                i = j
                continue
            res.append(sub(ls[i], vv))
            i += 1
        return res
    return "\n".join(block(lines, v))


fbv = {"role": "web", "units": ["ztgate.service", "nginx.service"], "paths": ["/var/log/modsec/zt_waf_app.log"], "python": "python3",
       "aws_region": "ap-northeast-2", "param_prefix": "/zt/elk", "logs_name": "logs.zt.internal", "logs_ip": "10.0.2.200"}
rendered = {
    "filebeat(web)": render(fb, fbv),
    "filebeat(auth, WAF 파일 없음)": render(fb, {**fbv, "role": "auth", "units": ["auth-app.service"], "paths": []}),
    "관제 서버": render(tpl, {"aws_region": "ap-northeast-2", "param_prefix": "/zt/elk", "ca_param": "/zt/mtls/ca_cert", "tunnel_token": "T",
                          "kibana_host": "kibana.xmcda.store", "lambda_groups": ["arn:aws:logs:r:1:log-group:/aws/lambda/a:*"],
                          "code_bucket": "b", "kibana_object_keys": '["elk/kibana/zt_saved_searches.ndjson"]', "kibana_version": "v"}),
}
ok("auth 서버 Filebeat에는 WAF 파일 입력이 없음", "zt-auth-waf" not in rendered["filebeat(auth, WAF 파일 없음)"])
bash = shutil.which("bash")
for name, text in rendered.items():
    if not bash or os.name == "nt":
        print(f"[SKIP] {name}: bash 문법 검사(bash 없음/Windows)")
        continue
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf-8") as f:
        f.write(text)
    r = subprocess.run([bash, "-n", f.name], capture_output=True, text=True)
    os.unlink(f.name)
    ok(f"{name}: 펼친 스크립트 bash 문법", r.returncode == 0, r.stderr[:300])
try:
    import yaml
    t = rendered["관제 서버"]
    rules = re.findall(r"<< EARULE\n(.*?)\nEARULE", t, re.S)
    parsed = [yaml.safe_load(x.replace('"$HOOK"', '"h"')) for x in rules]
    ok("ElastAlert2 규칙 YAML 3개 파싱 + Discord 주소 자리", len(parsed) == 3 and all(p["discord_webhook_url"] == "h" for p in parsed))
except ImportError:
    print("[SKIP] YAML 파싱(pyyaml 없음)")

mt = read("main.tf")
ok("Kibana를 켜면 로그인 서버가 Kibana를 알게 함: 복귀 주소/로그아웃 목록 + 관리자만(소속 안내 화면)",
   'var.enable_elk ? ["kibana.${var.domain_name}"] : []' in mt and 'var.enable_elk ? { "kibana.${var.domain_name}" = ["admin"] } : {}' in mt)

# ---------- 5. Kibana 저장 객체(표 6개) ----------
objs = [json.loads(l) for l in read("kibana/zt_saved_searches.ndjson").splitlines() if l.strip()]
searches = [o for o in objs if o["type"] == "search"]
dv = [o for o in objs if o["type"] == "index-pattern"]
ok("Kibana: 데이터 보기 1개(zt-logs-*, 시간 필드 @timestamp) + 표(저장된 검색) 6개",
   len(dv) == 1 and dv[0]["attributes"]["title"] == "zt-logs-*" and dv[0]["attributes"]["timeFieldName"] == "@timestamp" and len(searches) == 6)
ok("표는 모두 같은 데이터 보기를 참조하고, 최신순·KQL 검색", all(o["references"] == [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": dv[0]["id"]}]
   and o["attributes"]["sort"] == [["@timestamp", "desc"]] and json.loads(o["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])["query"]["language"] == "kuery"
   for o in searches))
all_events = set(re.findall(r'"([a-z_]+)"', " ".join(json.loads(o["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])["query"]["query"] for o in searches)))
code_events = set(re.findall(r'log_event\("([a-z_]+)"', eng + auth + gate + waf)) | {"risk_release"}
ok("표가 시스템이 남기는 이벤트 종류를 모두 덮음(빠진 이벤트 없음)", not (code_events - all_events), code_events - all_events)
ok("관제 서버: kibana/*.ndjson을 S3에서 받아 가져오기(같은 ID 덮어씀), 읽기 권한은 elk/kibana/*만",
   'fileset("${path.module}/kibana", "*.ndjson")' in tf and '"${aws_s3_bucket.app_code.arn}/elk/kibana/*"' in tf
   and "/api/saved_objects/_import?overwrite=true" in tpl and "${kibana_version}" in tpl)

# ---------- Kibana 비밀번호 고정 + 사용 통계(telemetry) 끄기 ----------
outs, ex = read("outputs.tf"), read("terraform.tfvars.example")
ok("kibana_password: sensitive, 비우면 무작위, 15~64자 허용 문자만",
   'variable "kibana_password"' in var and re.search(r'variable "kibana_password" \{[^}]*sensitive\s*=\s*true', var, re.S)
   and 'default     = ""' in var.split('variable "kibana_password"')[1].split("validation")[0]
   and "^[A-Za-z0-9!@#%^*_+=.~-]{15,64}$" in var)
pat = re.compile(r"^[A-Za-z0-9!@#%^*_+=.~-]{15,64}$")
ok("허용 문자 규칙: 따옴표/$/역슬래시/공백/짧은 값은 거부",
   pat.match("Zt-Kibana_2026!x") and not any(pat.match(x) for x in ('short1!', 'Elevenchar12345'[:14], 'has"quote1234', 'dollar$sign1234', 'back\\slash1234', 'has space 1234', "it's-apostrophe1")))
ok("elastic 비밀번호만 tfvars 값 사용(나머지 서버끼리 쓰는 비밀번호는 계속 무작위)",
   'k == "elastic" && var.kibana_password != "" ? var.kibana_password : v.result' in tf
   and "value    = local.elk_secret_values[each.key]" in tf)
ok("output kibana_elastic_password도 같은 값(고정값 또는 무작위)", 'local.elk_secret_values["elastic"]' in outs)
ok("tfvars.example: 비밀번호 칸은 비어 있음(예시 파일에 실제 비밀번호 없음)", 'kibana_password     = ""' in ex)
ok("kibana.yml: 사용 통계 끄기 + 화면에서 다시 켜지 못하게(배너 없음)",
   "telemetry.optIn: false" in tpl and "telemetry.allowChangingOptInStatus: false" in tpl)

# ---------- Lambda 자동 줄(시작/끝/실행 시간) 버리기 ----------
m = re.search(r"if (\[message\] =~ /.*?/(?: or \[message\] =~ /.*?/)*) \{\n\s*drop \{ \}", tpl)
ok("Logstash: 조건에 맞는 줄은 drop(저장 안 함)", m is not None)
if m:
    pats = [re.compile(x) for x in re.findall(r"=~ /(.*?)/(?= or|$)", m.group(1))]
    dropped = lambda line: any(p.search(line) for p in pats)
    drop_lines = ["START RequestId: 8c1f-e21 Version: $LATEST", "END RequestId: 8c1f-e21",
                  "REPORT RequestId: 8c1f-e21\tDuration: 498.21 ms\tBilled Duration: 499 ms",
                  "INIT_START Runtime Version: python:3.12.v40",
                  '[DEVICE_SWEEP_SUMMARY] {"active": 0, "checked": 0, "bad": 0, "revoked": [], "unknown": 0, "mode": "report"}']
    keep_lines = ['ZT_EVENT {"event": "device_sweep", "identity": "a@b.c"}', 'ZT_EVENT {"event": "decision", "msg": "START RequestId: x"}',
                  '[DEVICE_SWEEP_SUMMARY] {"active": 2, "checked": 2, "bad": 1, "revoked": ["a@b.c"]}',
                  "[GEO_VELOCITY] identity=a from=KR to=JP", "Traceback (most recent call last):",
                  '127.0.0.1 - - "GET /REPORT RequestId: " 200']
    ok("버리는 줄: START/END/REPORT/INIT_START, 할 일 없던 순찰 요약", all(dropped(l) for l in drop_lines), [l for l in drop_lines if not dropped(l)])
    ok("남기는 줄: 보안 기록(ZT_EVENT), 실제로 기기를 본 순찰 요약, 오류, 사람이 읽는 태그 줄", not any(dropped(l) for l in keep_lines), [l for l in keep_lines if dropped(l)])

# ---------- 설치 순서: 터널은 Kibana 직후, 부가 단계 실패는 설치를 멈추지 않음 ----------
i_kb, i_cf = tpl.index("systemctl enable --now kibana"), tpl.index("cloudflared service install")
i_ea, i_imp = tpl.index("# ---------- ElastAlert2"), tpl.index("/api/saved_objects/_import")
ok("관제 서버: cloudflared(터널)를 Kibana 시작 직후, 알림/표 가져오기보다 먼저 설치", i_kb < i_cf < i_ea and i_cf < i_imp)
ea_block = tpl[i_ea:tpl.index("# ---------- Kibana 저장 객체")]
ok("관제 서버: ElastAlert2는 set +e + 하위 셸(set -e) + 종료 코드 판정(실패해도 다음 단계 진행)",
   "set +e\n(\nset -e\n" in ea_block and "rc=$?" in ea_block and "elastalert setup FAILED" in ea_block and not re.search(r"^\) \|\|", ea_block, re.M))
ok("Filebeat 설치: '( ... ) ||' 대신 종료 코드 판정 + 원래 set -e 상태 복원",
   not re.search(r"^\) \|\|", fb, re.M) and "zt_fb_rc=$?" in fb and "zt_fb_opts=$-" in fb)
if shutil.which("bash"):
    demo = lambda wrapper: subprocess.run(["bash", "-c", wrapper], capture_output=True, text=True).stdout
    old = demo('set -e; ( set -e; false; echo CONTINUED ) || echo FAILED')
    new = demo('set -e; set +e; ( set -e; false; echo CONTINUED ); rc=$?; set -e; [ "$rc" -eq 0 ] || echo FAILED; echo NEXT')
    ok("bash 동작 확인: 옛 방식은 실패를 못 잡고 계속 진행, 새 방식은 실패를 잡고 다음 단계로", "CONTINUED" in old and "FAILED" not in old
       and "CONTINUED" not in new and "FAILED" in new and "NEXT" in new, (old, new))
