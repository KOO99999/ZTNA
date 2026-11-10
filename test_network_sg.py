"""네트워크 보안그룹 구조 검사(terraform 없이 .tf 파일만 읽음). 실행: python test_network_sg.py   (pip install python-hcl2)
확인: DB 아웃바운드 전체 허용 삭제 / 로그인 서버 전용 auth_sg 분리와 필요한 규칙 / RDS 다중 AZ 스위치."""
import glob
import os
import sys

import hcl2

HERE = os.path.dirname(os.path.abspath(__file__))
fails = 0


def ok(name, cond, detail=""):
    global fails
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        fails += 1
        if detail:
            print(f"    -> {detail}")


res = {}          # (type, name) -> body
for f in glob.glob(os.path.join(HERE, "*.tf")):
    with open(f, encoding="utf-8") as fh:
        for block in hcl2.load(fh).get("resource", []):
            for rtype, named in block.items():
                for name, body in named.items():
                    res[(rtype.strip(chr(34)), name.strip(chr(34)))] = body

SG = "aws_security_group"
EG = "aws_vpc_security_group_egress_rule"
IN = "aws_vpc_security_group_ingress_rule"


def rules(kind, sg):
    return [b for (t, _), b in res.items() if t == kind and f"aws_security_group.{sg}." in str(b.get("security_group_id"))]


def ref(b, key="referenced_security_group_id"):
    return str(b.get(key, ""))


ok("db_out_all(DB 아웃바운드 전체 허용) 삭제됨", (EG, "db_out_all") not in res)
ok("DB SG에 아웃바운드 규칙이 하나도 없음", rules(EG, "db_sg") == [])
ok("auth_sg 존재", (SG, "auth_sg") in res)
auth_ec2 = str(res[("aws_instance", "auth_server")].get("vpc_security_group_ids"))
ok("로그인 서버는 auth_sg 사용(app_sg 아님)", "auth_sg" in auth_ec2 and "app_sg" not in auth_ec2, auth_ec2)
app_ec2 = str(res[("aws_instance", "app_server")].get("vpc_security_group_ids"))
ok("포털 서버는 그대로 app_sg", "app_sg" in app_ec2 and "auth_sg" not in app_ec2, app_ec2)

ing = rules(IN, "auth_sg")
ok("auth_sg 인바운드: web_sg에서 8080 하나뿐",
   len(ing) == 1 and "web_sg" in ref(ing[0]) and str(ing[0].get("from_port")) == "8080", ing)
eg = rules(EG, "auth_sg")
ports = sorted((str(b.get("to_port")), "sg" if b.get("referenced_security_group_id") else "cidr") for b in eg)
ok("auth_sg 아웃바운드: DB 3306(SG) + 인터넷 80/443 (+ELK 5044는 elk.tf)",
   ports == [("3306", "sg"), ("443", "cidr"), ("80", "cidr")], ports)
ok("auth_sg 아웃바운드에 전체 허용(-1) 없음", all(str(b.get("ip_protocol")) != "-1" for b in eg))
ok("web_sg -> auth_sg 8080 아웃바운드 있음(없으면 로그인 서버 접속이 끊김)",
   any("auth_sg" in ref(b) and str(b.get("to_port")) == "8080" for b in rules(EG, "web_sg")))
ok("db_sg 인바운드: app_sg, auth_sg에서 3306만",
   sorted(("auth" if "auth_sg" in ref(b) else "app" if "app_sg" in ref(b) else "?", str(b.get("to_port"))) for b in rules(IN, "db_sg"))
   == [("app", "3306"), ("auth", "3306")])
ok("app_sg 인바운드에는 아직 web_sg 8080만(로그인 서버 규칙을 분리해도 포털 경로 유지)",
   len(rules(IN, "app_sg")) == 1 and "web_sg" in ref(rules(IN, "app_sg")[0]))
elk = open(os.path.join(HERE, "elk.tf"), encoding="utf-8").read()
ok("관제: auth_sg도 ELK(5044) 대상(Filebeat가 로그인 서버에서도 돈다)", elk.count("auth = aws_security_group.auth_sg.id") == 2)
ok("RDS 다중 AZ 스위치(db_multi_az, 기본 false)",
   "var.db_multi_az" in str(res[("aws_db_instance", "login_db")].get("multi_az")))
vars_tf = open(os.path.join(HERE, "variables.tf"), encoding="utf-8").read()
ok("db_multi_az 변수 기본값 false", 'variable "db_multi_az"' in vars_tf and "default     = false" in vars_tf.split('variable "db_multi_az"')[1].split("}")[0])

print()
print("실패 수:", fails)
sys.exit(1 if fails else 0)
