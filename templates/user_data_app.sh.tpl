#!/bin/bash
exec > /var/log/user-data.log 2>&1
apt-get update -y
apt-get install -y python3-pip
# 포털/부서/관리자 페이지는 DB 연결이 필요 없음 (DynamoDB만 사용) - 로그인 관련
# 패키지(flask-sqlalchemy, pymysql, cryptography, pyotp, pyjwt)는 auth_server 쪽으로 이관됨
pip3 install flask boto3 requests

cat << 'APP' > /home/ubuntu/portal_app.py
${app_code}
APP

# [B 계층] Lambda(PDP) 호출 정보. auth_server의 .env와 같은 방식.
cat << ENV > /home/ubuntu/.env
PDP_EVALUATE_URL=${pdp_evaluate_url}
EVALUATE_SHARED_SECRET=${evaluate_shared_secret}
AUTH_DOMAIN=${auth_domain}
ZT_DEBUG_HEADERS=${debug_headers}
ENV
chmod 600 /home/ubuntu/.env

# --- systemd 서비스로 등록 (기존 nohup 방식 대체) ---
cat << 'SERVICE' > /etc/systemd/system/portal-app.service
[Unit]
Description=ZT Portal Server (portal_app.py)
After=network.target

[Service]
ExecStart=/usr/bin/python3 /home/ubuntu/portal_app.py
EnvironmentFile=/home/ubuntu/.env
WorkingDirectory=/home/ubuntu
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now portal-app
