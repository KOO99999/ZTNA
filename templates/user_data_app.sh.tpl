#!/bin/bash
exec > /var/log/user-data.log 2>&1
apt-get update -y
apt-get install -y python3-pip
# 포털/부서/관리자 페이지는 DB 연결이 필요 없음 (DynamoDB만 사용) - 로그인 관련
# 패키지(flask-sqlalchemy, pymysql, cryptography, pyotp, pyjwt)는 auth_server 쪽으로 이관됨
pip3 install flask boto3

cat << 'APP' > /home/ubuntu/portal_app.py
${app_code}
APP

nohup python3 /home/ubuntu/portal_app.py > /home/ubuntu/portal_app.log 2>&1 &
