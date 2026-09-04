#!/bin/bash
exec > /var/log/user-data.log 2>&1
apt-get update -y
apt-get install -y python3-pip
# flask-sqlalchemy: RDS(login_server) 테이블(accounts/backup_codes/login_failures) 관리용
# cryptography: MySQL 8 기본 인증 방식(caching_sha2_password)에 pymysql이 필요로 함
pip3 install flask boto3 pymysql flask-sqlalchemy cryptography

cat << 'APP' > /home/ubuntu/app.py
${app_code}
APP

cat << ENV > /home/ubuntu/.env
DB_HOST=${db_host}
DB_NAME=${db_name}
DB_USER=${db_user}
DB_PASSWORD=${db_password}
ENV

# .env 값을 실제 프로세스 환경변수로 로드 (app.py가 os.environ으로 읽음)
set -a
source /home/ubuntu/.env
set +a

nohup python3 /home/ubuntu/app.py > /home/ubuntu/app.log 2>&1 &
