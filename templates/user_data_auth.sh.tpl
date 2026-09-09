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

set -a
source /home/ubuntu/.env
set +a

nohup python3 /home/ubuntu/auth_app.py > /home/ubuntu/auth_app.log 2>&1 &
