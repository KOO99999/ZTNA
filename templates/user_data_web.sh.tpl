#!/bin/bash
exec > /var/log/user-data.log 2>&1
apt-get update -y
apt-get install -y python3-pip curl

# ==========================================================================
# 판단 서비스(auth_gate.py): nginx가 요청을 앱에 넘기기 전에 먼저 묻는 곳 (auth_request)
#   - 이 서버 안에서 127.0.0.1:9000으로만 받음. 전용 계정(ztgate)으로 실행해서 nginx 프로세스가
#     비밀키(.env)를 읽지 못하게 함 (env 파일은 root만 읽기 가능, systemd가 읽어서 넘겨줌)
#   - 죽어도 systemd가 바로 다시 띄움(재시작 횟수 제한 없음). 응답이 없으면 nginx가 차단(fail-closed)
# ==========================================================================
# gunicorn은 --no-control-socket 옵션이 있는 버전(26.2.0에서 확인)으로 고정함. 이 옵션이 없는 옛 버전이
# 깔리면 서비스가 시작되지 않으므로, 버전을 올릴 때는 옵션 존재 여부를 먼저 확인할 것.
pip3 install flask "gunicorn==26.2.0" pyjwt cryptography requests boto3

useradd --system --no-create-home --shell /usr/sbin/nologin ztgate || true
mkdir -p /opt/ztgate /etc/ztgate

cat << 'ZTJWT' > /opt/ztgate/zt_jwt.py
${zt_jwt_code}
ZTJWT

cat << 'ZTRISK' > /opt/ztgate/zt_risk.py
${zt_risk_code}
ZTRISK

cat << 'ZTGATE' > /opt/ztgate/auth_gate.py
${auth_gate_code}
ZTGATE

chown -R root:root /opt/ztgate
chmod 755 /opt/ztgate
chmod 644 /opt/ztgate/*.py

cat << 'ZTENV' > /etc/ztgate/env
PDP_EVALUATE_URL=${pdp_evaluate_url}
EVALUATE_SHARED_SECRET=${evaluate_shared_secret}
AUTH_DOMAIN=${auth_domain}
CF_TEAM_DOMAIN=${cf_team_domain}
CF_ACCESS_AUDS=${cf_access_auds}
ZTENV
chown root:root /etc/ztgate/env
chmod 600 /etc/ztgate/env

# --no-control-socket: gunicorn 관리용 유닉스 소켓(기본 위치가 실행 계정의 홈 디렉터리)을 만들지 않음.
#   ztgate는 홈이 없고 파일시스템이 읽기 전용(ProtectSystem=strict)이라 불필요하며, 열려 있는 관리 통로도 줄임.
# workers=1, threads=8: 위험도 캐시와 공개키 캐시가 프로세스 안 메모리에 있으므로 프로세스를
# 하나로 두고 스레드로 동시 요청을 처리함(프로세스를 여러 개 두면 캐시가 쪼개져 Lambda 호출이 늘어남).
# 프로세스가 죽으면 gunicorn 관리자가 새로 띄우고, 관리자까지 죽으면 systemd가 다시 띄움.
cat << 'ZTSERVICE' > /etc/systemd/system/ztgate.service
[Unit]
Description=ZT Auth Gate (auth_gate.py) - nginx auth_request decision service
After=network.target
StartLimitIntervalSec=0

[Service]
User=ztgate
Group=ztgate
WorkingDirectory=/opt/ztgate
EnvironmentFile=/etc/ztgate/env
ExecStart=/usr/bin/python3 -m gunicorn --workers 1 --threads 8 --bind 127.0.0.1:9000 --timeout 15 --graceful-timeout 5 --no-control-socket auth_gate:app
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
ZTSERVICE

systemctl daemon-reload
systemctl enable --now ztgate

# 판단 서비스가 뜰 때까지 최대 30초 기다리며 상태를 기록 (nginx는 이후에 설정을 적용)
for i in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:9000/healthz > /dev/null 2>&1; then
    echo "ztgate healthy after $i s"
    break
  fi
  sleep 1
done

# ==========================================================================
# nginx: 모든 요청을 앱에 넘기기 전에 판단 서비스에 먼저 묻는다 (auth_request)
#   통과(200)면 앱으로, 403이면 판단 서비스가 만든 차단/재인증 응답, 그 외(서비스 장애/타임아웃)는
#   503(fail-closed). 앱 쪽 Cf-Access-Authenticated-User-Email 전달은 제거함
#   (앱은 이제 서명 검증된 JWT의 email만 사용하며, 평문 이메일 헤더는 무시함).
# ==========================================================================
apt-get install -y nginx
# [Web->WAS mTLS] 내부 CA 인증서 + 이 서버(웹)의 클라이언트 인증서/개인키를 SSM에서 받는다(mtls.tf, 자기 것만 읽기 권한).
# nginx는 시작할 때 root로 이 파일들을 읽으므로 개인키는 root만 읽을 수 있게 둔다. IAM 권한 반영을 기다려 최대 5분 재시도.
mkdir -p /etc/zt-mtls
for i in $(seq 1 30); do
  if python3 -c "
import boto3
ssm = boto3.client('ssm', region_name='${aws_region}')
for name, out in (('ca_cert', 'ca.crt'), ('web_cert', 'me.crt'), ('web_key', 'me.key')):
    v = ssm.get_parameter(Name='${mtls_param_prefix}/' + name, WithDecryption=True)['Parameter']['Value']
    open('/etc/zt-mtls/' + out, 'w').write(v)
"; then echo "mtls material ok after $i tries"; break; fi
  sleep 10
done
chown root:root /etc/zt-mtls/me.key && chmod 600 /etc/zt-mtls/me.key
chmod 644 /etc/zt-mtls/ca.crt /etc/zt-mtls/me.crt

cat << 'NGINX' > /etc/nginx/sites-available/default
map $request_uri $zt_unavailable_target {
    ~^/api/  @zt_unavailable_api;
    default  @zt_unavailable;
}

# [Web->WAS mTLS] 로그인 서버(auth.xmcda.store)도 이 nginx를 거쳐 mTLS로 보낸다. 예전엔 cloudflared가 인증 서버로
# 평문 HTTP를 바로 보냈다. 로그인 서버 자체는 위험도 판단(auth_request) 대상이 아니므로 그대로 넘기기만 한다
# (로그인 화면을 보기 전에 Access 토큰을 요구하면 로그인을 할 수 없다).
server {
    listen 80;
    server_name ${auth_domain};

    location / {
        proxy_pass https://${auth_private_ip}:8080;
        proxy_ssl_name auth.zt.internal;
        # [Web->WAS mTLS] 앱 서버로 TLS 접속: 내 클라이언트 인증서(web.zt.internal)를 보여주고,
        # 앱 서버 인증서가 내부 CA가 발급한 app.zt.internal인지 확인한다(아니면 연결하지 않음 -> 502 -> fail-closed 503).
        proxy_ssl_certificate         /etc/zt-mtls/me.crt;
        proxy_ssl_certificate_key     /etc/zt-mtls/me.key;
        proxy_ssl_trusted_certificate /etc/zt-mtls/ca.crt;
        proxy_ssl_verify              on;
        proxy_ssl_verify_depth        2;
        proxy_ssl_server_name         on;
        proxy_ssl_protocols           TLSv1.2 TLSv1.3;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

server {
    listen 80 default_server;

    location = /_zt_auth {
        internal;
        proxy_pass http://127.0.0.1:9000/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_connect_timeout 1s;
        proxy_read_timeout 5s;
    }

    location @zt_denied {
        internal;
        rewrite ^ /deny break;
        proxy_pass http://127.0.0.1:9000;
        proxy_method GET;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Host $host;
        proxy_set_header X-ZT-Action $zt_action;
        proxy_connect_timeout 1s;
        proxy_read_timeout 5s;
    }

    location @zt_unavailable {
        internal;
        default_type "text/html; charset=utf-8";
        return 503 '<!DOCTYPE html><html><head><meta charset="utf-8"><title>일시적으로 확인할 수 없습니다</title></head><body><h2>일시적으로 확인할 수 없습니다</h2><p>접근 판단 서비스에 연결할 수 없어 접근을 차단했습니다. 잠시 후 다시 시도해 주세요.</p></body></html>';
    }

    location @zt_unavailable_api {
        internal;
        default_type "application/json; charset=utf-8";
        return 503 '{"status":"Error","message":"접근 판단 서비스에 연결할 수 없어 접근을 차단했습니다."}';
    }

    location / {
        auth_request /_zt_auth;
        auth_request_set $zt_action $upstream_http_x_zt_action;
        auth_request_set $zt_threshold $upstream_http_x_zt_threshold;
        auth_request_set $zt_tier $upstream_http_x_zt_tier;
        error_page 401 403 = @zt_denied;
        error_page 500 502 503 504 = $zt_unavailable_target;

        proxy_pass https://${app_private_ip}:8080;
        proxy_ssl_name app.zt.internal;
        # [Web->WAS mTLS] 앱 서버로 TLS 접속: 내 클라이언트 인증서(web.zt.internal)를 보여주고,
        # 앱 서버 인증서가 내부 CA가 발급한 app.zt.internal인지 확인한다(아니면 연결하지 않음 -> 502 -> fail-closed 503).
        proxy_ssl_certificate         /etc/zt-mtls/me.crt;
        proxy_ssl_certificate_key     /etc/zt-mtls/me.key;
        proxy_ssl_trusted_certificate /etc/zt-mtls/ca.crt;
        proxy_ssl_verify              on;
        proxy_ssl_verify_depth        2;
        proxy_ssl_server_name         on;
        proxy_ssl_protocols           TLSv1.2 TLSv1.3;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # 앱은 서명 검증된 JWT의 email만 쓴다. 믿을 수 없는 평문 이메일 헤더는 앱에 넘기지 않음
        proxy_set_header Cf-Access-Authenticated-User-Email "";
        # 화면 표시용 임계값/등급: 판단 서비스가 알려준 값으로 항상 덮어씀(값이 비면 헤더 자체를 보내지 않음).
        # 클라이언트가 같은 이름의 헤더를 보내도 앱에는 닿지 않는다.
        proxy_set_header X-ZT-Threshold $zt_threshold;
        proxy_set_header X-ZT-Tier $zt_tier;
    }
}
NGINX

nginx -t && systemctl restart nginx

curl -L --output /tmp/cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
dpkg -i /tmp/cloudflared.deb

# [로컬 config 전환] 기존에는 cloudflared service install <token>만 실행해
# ingress 규칙을 매번 Cloudflare 서버에 원격으로 물어보는 방식(Dashboard-managed)
# 이었는데, 이 원격 설정 전달이 간헐적으로 실패해 503(No ingress rules were
# defined...)이 발생하는 문제가 있었음. ingress 규칙을 Terraform이 이미 알고
# 있는 값(auth_server/app_server IP)으로 아래 config.yml에 직접 적어두면,
# cloudflared가 인터넷 너머로 설정을 받아오길 기다릴 필요 없이 로컬 파일만
# 보고 즉시 동작함 (Locally-managed Tunnel).
mkdir -p /etc/cloudflared
cat << 'CFCONFIG' > /etc/cloudflared/config.yml
tunnel: ${tunnel_id}
ingress:
  - hostname: ${auth_domain}
    service: http://localhost:80
  - hostname: admin.${domain_name}
    service: http://localhost:80
  - hostname: dev.${domain_name}
    service: http://localhost:80
  - hostname: marketing.${domain_name}
    service: http://localhost:80
  - hostname: hr.${domain_name}
    service: http://localhost:80
  - hostname: ${domain_name}
    service: http://localhost:80
  - service: http_status:404
CFCONFIG
chmod 600 /etc/cloudflared/config.yml

cloudflared service install ${tunnel_token}
systemctl restart cloudflared
