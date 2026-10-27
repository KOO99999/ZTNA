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
                          "kibana_host": "kibana.xmcda.store", "lambda_groups": ["arn:aws:logs:r:1:log-group:/aws/lambda/a:*"]}),
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
