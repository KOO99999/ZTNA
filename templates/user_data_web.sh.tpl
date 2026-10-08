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
pip3 install flask gunicorn pyjwt cryptography requests

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
ExecStart=/usr/bin/python3 -m gunicorn --workers 1 --threads 8 --bind 127.0.0.1:9000 --timeout 15 --graceful-timeout 5 auth_gate:app
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
cat << 'NGINX' > /etc/nginx/sites-available/default
map $request_uri $zt_unavailable_target {
    ~^/api/  @zt_unavailable_api;
    default  @zt_unavailable;
}

server {
    listen 80;

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
        error_page 401 403 = @zt_denied;
        error_page 500 502 503 504 = $zt_unavailable_target;

        proxy_pass http://${app_private_ip}:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # 앱은 서명 검증된 JWT의 email만 쓴다. 믿을 수 없는 평문 이메일 헤더는 앱에 넘기지 않음
        proxy_set_header Cf-Access-Authenticated-User-Email "";
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
    service: http://${auth_private_ip}:8080
  - hostname: admin.${domain_name}
    service: http://localhost:80
  - hostname: ${domain_name}
    service: http://localhost:80
  - service: http_status:404
CFCONFIG
chmod 600 /etc/cloudflared/config.yml

cloudflared service install ${tunnel_token}
systemctl restart cloudflared
