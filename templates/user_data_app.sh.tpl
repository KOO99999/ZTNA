#!/bin/bash
exec > /var/log/user-data.log 2>&1
apt-get update -y
apt-get install -y python3-pip
pip3 install flask boto3 pymysql

cat << 'APP' > /home/ubuntu/app.py
${app_code}
APP

cat << ENV > /home/ubuntu/.env
DB_HOST=${db_host}
DB_NAME=${db_name}
DB_USER=${db_user}
DB_PASSWORD=${db_password}
ENV

nohup python3 /home/ubuntu/app.py > /home/ubuntu/app.log 2>&1 &
