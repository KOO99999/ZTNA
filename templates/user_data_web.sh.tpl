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
cloudflared service install ${tunnel_token}
systemctl start cloudflared
