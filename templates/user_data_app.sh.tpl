#!/bin/bash
exec > /var/log/user-data.log 2>&1
apt-get update -y
apt-get install -y python3-pip
# 포털/부서/관리자 페이지는 DB 연결이 필요 없음 (DynamoDB만 사용) - 로그인 관련
# 패키지(flask-sqlalchemy, pymysql, pyotp)는 auth_server 쪽으로 이관됨. pyjwt+cryptography는 Access JWT 서명 검증용으로 이 서버에도 필요.
# 위험도 판단(Lambda 호출)은 web 서버 앞단(auth_gate.py)이 하므로, 이 서버에는 Lambda 호출 코드도 비밀키도 두지 않는다.
pip3 install flask boto3 requests pyjwt cryptography

# 전용 계정(ztapp)으로 실행한다. 예전에는 root로 실행해서, 앱이 뚫리면 서버 전체가 넘어가는 구조였음.
# 코드는 root 소유(읽기만 가능)로 두고, 환경변수 파일은 root만 읽을 수 있게 한다(systemd가 읽어서 넘겨줌).
useradd --system --no-create-home --shell /usr/sbin/nologin ztapp || true
mkdir -p /opt/ztapp /etc/ztapp

# [코드 받기] 앱 코드(portal_app.py, zt_jwt.py, zt_mtls.py)는 S3(code_bucket.tf)에 있고, 이 서버 역할은 자기 코드 파일만 읽을 수 있다.
# user_data에 코드를 넣지 않는 이유: 16KB 한도(압축 후 약 14.5KB까지 차서 화면 수정/관제 설정을 더 넣을 수 없었음).
# 코드 버전(파일 해시) - 코드가 바뀌면 이 줄이 바뀌어 서버가 새로 만들어진다: ${app_code_version}
for i in $(seq 1 30); do
  if python3 -c "
import boto3
s3 = boto3.client('s3', region_name='${aws_region}')
for name in ('portal_app.py', 'zt_jwt.py', 'zt_mtls.py', 'zt_ui.py'):
    s3.download_file('${code_bucket}', 'app/' + name, '/opt/ztapp/' + name)
"; then echo "app code ok after $i tries"; break; fi
  sleep 10
done
test -s /opt/ztapp/portal_app.py || { echo "app code download failed"; exit 1; }

# [Web->WAS mTLS] 내부 CA 인증서 + 이 서버의 인증서/개인키를 SSM에서 받는다(mtls.tf, 자기 것만 읽기 권한).
# IAM 권한이 막 붙은 직후일 수 있어 최대 5분 재시도한다.
mkdir -p /etc/zt-mtls
for i in $(seq 1 30); do
  if python3 -c "
import boto3, sys
ssm = boto3.client('ssm', region_name='${aws_region}')
for name, out in (('ca_cert', 'ca.crt'), ('${mtls_role}_cert', 'me.crt'), ('${mtls_role}_key', 'me.key')):
    v = ssm.get_parameter(Name='${mtls_param_prefix}/' + name, WithDecryption=True)['Parameter']['Value']
    open('/etc/zt-mtls/' + out, 'w').write(v)
"; then echo "mtls material ok after $i tries"; break; fi
  sleep 10
done
chown root:ztapp /etc/zt-mtls/me.key && chmod 640 /etc/zt-mtls/me.key
chmod 644 /etc/zt-mtls/ca.crt /etc/zt-mtls/me.crt

chown -R root:root /opt/ztapp
chmod 755 /opt/ztapp
chmod 644 /opt/ztapp/*.py

cat << 'ZTENV' > /etc/ztapp/env
AUTH_DOMAIN=${auth_domain}
MTLS_CERT=/etc/zt-mtls/me.crt
MTLS_KEY=/etc/zt-mtls/me.key
MTLS_CLIENT_CA=/etc/zt-mtls/ca.crt
MTLS_ALLOWED_CLIENT=${mtls_allowed_client}
ZT_DEBUG_HEADERS=${debug_headers}
CF_TEAM_DOMAIN=${cf_team_domain}
CF_ACCESS_AUDS=${cf_access_auds}
ADMIN_EMAILS=${admin_emails}
RISK_ADMIN_FUNCTION=${risk_admin_function}
ACCOUNT_DEPARTMENTS='${account_departments}'
ZTENV
# 해제 폼의 CSRF 토큰 서명 키: 서버가 처음 뜰 때 한 번 만든다(코드/Terraform/저장소에 값이 남지 않음, root 전용 파일)
echo "CSRF_SECRET=$(openssl rand -hex 32)" >> /etc/ztapp/env
chown root:root /etc/ztapp/env
chmod 600 /etc/ztapp/env

# --- systemd 서비스로 등록 (기존 nohup 방식 대체) ---
# - Restart=always: 프로세스가 죽어도 systemd가 자동으로 재시작
# - 8080은 1024 이상이라 root 권한이 필요 없음
# - NoNewPrivileges/ProtectSystem/ProtectHome/PrivateTmp: 뚫렸을 때 할 수 있는 일을 줄이는 기본 잠금
#   (이 앱은 디스크에 쓰는 일이 없고 DynamoDB는 인스턴스 역할로 네트워크를 통해 접근함)
cat << 'SERVICE' > /etc/systemd/system/portal-app.service
[Unit]
Description=ZT Portal Server (portal_app.py)
After=network.target

[Service]
User=ztapp
Group=ztapp
ExecStart=/usr/bin/python3 /opt/ztapp/portal_app.py
EnvironmentFile=/etc/ztapp/env
Environment=PYTHONDONTWRITEBYTECODE=1
WorkingDirectory=/opt/ztapp
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now portal-app
${filebeat_setup}
