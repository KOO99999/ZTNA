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

cat << 'APP' > /opt/ztapp/portal_app.py
${app_code}
APP

# 신원 확인(Access JWT 서명 검증) 모듈. portal_app.py가 같은 폴더에서 가져다 씀
# (판단 서비스(web 서버의 auth_gate.py)와 같은 코드).
cat << 'ZTJWT' > /opt/ztapp/zt_jwt.py
${zt_jwt_code}
ZTJWT

chown -R root:root /opt/ztapp
chmod 755 /opt/ztapp
chmod 644 /opt/ztapp/*.py

cat << 'ZTENV' > /etc/ztapp/env
AUTH_DOMAIN=${auth_domain}
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
