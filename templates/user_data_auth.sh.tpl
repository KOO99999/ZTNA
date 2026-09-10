#!/bin/bash
exec > /var/log/user-data.log 2>&1
apt-get update -y
apt-get install -y python3-pip
pip3 install flask boto3 pymysql flask-sqlalchemy cryptography pyotp pyjwt requests

cat << 'APP' > /home/ubuntu/auth_app.py
${app_code}
APP

cat << ENV > /home/ubuntu/.env
DB_HOST=${db_host}
DB_NAME=${db_name}
DB_USER=${db_user}
DB_PASSWORD=${db_password}
PDP_EVALUATE_URL=${pdp_evaluate_url}
EVALUATE_SHARED_SECRET=${evaluate_shared_secret}
DOMAIN_NAME=${domain_name}
OIDC_CLIENT_ID=${oidc_client_id}
OIDC_CLIENT_SECRET=${oidc_client_secret}
ENV

# --- systemd 서비스로 등록 (기존 nohup 방식 대체) ---
# - Restart=always: 프로세스가 죽어도 systemd가 자동으로 재시작
# - WantedBy=multi-user.target + enable: 인스턴스 재부팅 시에도 자동 기동
cat << 'SERVICE' > /etc/systemd/system/auth-app.service
[Unit]
Description=ZT Auth Server (auth_app.py)
After=network.target

[Service]
ExecStart=/usr/bin/python3 /home/ubuntu/auth_app.py
EnvironmentFile=/home/ubuntu/.env
WorkingDirectory=/home/ubuntu
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now auth-app
