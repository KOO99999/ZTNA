#!/bin/bash
exec > /var/log/user-data.log 2>&1
apt-get update -y
apt-get install -y python3-pip
pip3 install flask boto3 pymysql flask-sqlalchemy cryptography pyotp pyjwt requests

# 전용 계정(ztauth)으로 실행한다. 예전에는 root로 실행해서, 로그인 서버가 뚫리면 서버 전체가(DB 접속 정보 포함)
# 넘어가는 구조였음. 코드는 root 소유(읽기만 가능), 환경변수 파일은 root만 읽을 수 있게 한다.
useradd --system --no-create-home --shell /usr/sbin/nologin ztauth || true
mkdir -p /opt/ztauth /etc/ztauth

cat << 'APP' > /opt/ztauth/auth_app.py
${app_code}
APP

chown -R root:root /opt/ztauth
chmod 755 /opt/ztauth
chmod 644 /opt/ztauth/auth_app.py

# PATH_PERMISSIONS: 자원별로 열 수 있는 소속 표 ("경로=소속,소속;경로=소속"). 세미콜론이 들어 있어서
# 작은따옴표로 감싼다(systemd EnvironmentFile과 셸에서 `. /etc/ztauth/env` 둘 다 안전).
cat << 'ZTENV' > /etc/ztauth/env
DB_HOST=${db_host}
DB_NAME=${db_name}
DB_USER=${db_user}
DB_PASSWORD=${db_password}
PDP_EVALUATE_URL=${pdp_evaluate_url}
EVALUATE_SHARED_SECRET=${evaluate_shared_secret}
DOMAIN_NAME=${domain_name}
OIDC_CLIENT_ID=${oidc_client_id}
OIDC_CLIENT_SECRET=${oidc_client_secret}
PATH_PERMISSIONS='${path_permissions}'
ACCOUNT_DEPARTMENTS='${account_departments}'
ZTENV
chown root:root /etc/ztauth/env
chmod 600 /etc/ztauth/env

# --- systemd 서비스로 등록 (기존 nohup 방식 대체) ---
# - Restart=always: 프로세스가 죽어도 systemd가 자동으로 재시작
# - WantedBy=multi-user.target + enable: 인스턴스 재부팅 시에도 자동 기동
# - 8080은 1024 이상이라 root 권한이 필요 없음
# - NoNewPrivileges/ProtectSystem/ProtectHome/PrivateTmp: 뚫렸을 때 할 수 있는 일을 줄이는 기본 잠금
cat << 'SERVICE' > /etc/systemd/system/auth-app.service
[Unit]
Description=ZT Auth Server (auth_app.py)
After=network.target

[Service]
User=ztauth
Group=ztauth
ExecStart=/usr/bin/python3 /opt/ztauth/auth_app.py
EnvironmentFile=/etc/ztauth/env
Environment=PYTHONDONTWRITEBYTECODE=1
WorkingDirectory=/opt/ztauth
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
systemctl enable --now auth-app
