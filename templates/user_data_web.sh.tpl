#!/bin/bash
exec > /var/log/user-data.log 2>&1
apt-get update -y
apt-get install -y nginx

cat << 'NGINX' > /etc/nginx/sites-available/default
server {
    listen 80;

    location / {
        proxy_pass http://${app_private_ip}:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Cf-Access-Authenticated-User-Email $http_cf_access_authenticated_user_email;
    }
}
NGINX

systemctl restart nginx

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
  - hostname: ${domain_name}
    service: http://localhost:80
  - service: http_status:404
CFCONFIG
chmod 600 /etc/cloudflared/config.yml

cloudflared service install ${tunnel_token}
systemctl restart cloudflared
