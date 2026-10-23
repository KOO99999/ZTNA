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

# [WAS->DB TLS] AWS 공식 RDS 인증서 묶음(전 리전 공통). 앱이 이 파일로 DB 서버 인증서를 검증한다.
# 주소 출처: AWS RDS 사용 설명서 "Using SSL/TLS to encrypt a connection to a DB instance".
curl -fsSL --retry 5 --retry-delay 3 -o /etc/ztauth/rds-ca.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
chmod 644 /etc/ztauth/rds-ca.pem

# PATH_PERMISSIONS: 자원(호스트)별로 열 수 있는 소속 표 ("호스트=소속,소속;호스트=소속"). 세미콜론이 들어 있어서
# 작은따옴표로 감싼다(systemd EnvironmentFile과 셸에서 `. /etc/ztauth/env` 둘 다 안전).
# 앱 서비스용: DB 계정은 앱 전용 계정(행 읽기/쓰기만). 마스터 계정과 AWS 관련 값은 여기 없다.
cat << 'ZTENV' > /etc/ztauth/env
DB_HOST=${db_host}
DB_NAME=${db_name}
DB_USER=${app_db_user}
DB_PASSWORD=${app_db_password}
DB_SSL_CA=/etc/ztauth/rds-ca.pem
PDP_EVALUATE_URL=${pdp_evaluate_url}
EVALUATE_SHARED_SECRET=${evaluate_shared_secret}
DOMAIN_NAME=${domain_name}
OIDC_CLIENT_ID=${oidc_client_id}
OIDC_CLIENT_SECRET=${oidc_client_secret}
PATH_PERMISSIONS='${path_permissions}'
APP_HOSTS=${app_hosts}
ACCOUNT_DEPARTMENTS='${account_departments}'
ZTENV
chown root:root /etc/ztauth/env
chmod 600 /etc/ztauth/env

# 부팅 단계 전용(root): 마스터 계정 + 만들 앱 계정 + 계정 시딩 위치. 끝나면 지운다.
cat << 'ZTBOOT' > /etc/ztauth/bootstrap.env
DB_USER=${master_db_user}
DB_PASSWORD=${master_db_password}
APP_DB_USER=${app_db_user}
APP_DB_PASSWORD=${app_db_password}
APP_DB_HOST=${app_db_host}
SEED_PARAM_NAME=${seed_param_name}
AWS_REGION=${aws_region}
ZTBOOT
chown root:root /etc/ztauth/bootstrap.env
chmod 600 /etc/ztauth/bootstrap.env

# [부팅 단계] 마스터 계정으로 테이블 생성/컬럼 추가 -> 앱 전용 계정 생성·권한 -> 계정 시딩(SSM, 이 서버의 IAM 역할 사용).
# RDS가 막 만들어진 직후일 수 있어 최대 10분 재시도. 앱 서비스는 이 단계를 하지 않는다.
for i in $(seq 1 60); do
  if bash -c 'set -a; . /etc/ztauth/env; . /etc/ztauth/bootstrap.env; set +a; python3 /opt/ztauth/auth_app.py --bootstrap'; then
    echo "bootstrap ok after $i tries"
    break
  fi
  echo "bootstrap failed (try $i), retrying"
  sleep 10
done
shred -u /etc/ztauth/bootstrap.env || rm -f /etc/ztauth/bootstrap.env

# --- systemd 서비스로 등록 (기존 nohup 방식 대체) ---
# - Restart=always: 프로세스가 죽어도 systemd가 자동으로 재시작
# - WantedBy=multi-user.target + enable: 인스턴스 재부팅 시에도 자동 기동
# - 8080은 1024 이상이라 root 권한이 필요 없음
# - NoNewPrivileges/ProtectSystem/ProtectHome/PrivateTmp: 뚫렸을 때 할 수 있는 일을 줄이는 기본 잠금
# - IPAddressDeny=169.254.169.254: 앱 프로세스는 인스턴스 메타데이터(IAM 임시 키, user_data의 마스터 비밀번호)에
#   접근하지 못한다. 앱은 AWS 권한이 필요 없다(계정 시딩은 위 부팅 단계에서 root가 끝냄). 앱이 뚫려도
#   서버의 IAM 권한과 DB 마스터 계정까지는 넘어가지 않게 하는 장치(systemd.resource-control).
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
IPAddressDeny=169.254.169.254

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now auth-app
