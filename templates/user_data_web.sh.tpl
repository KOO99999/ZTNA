#!/bin/bash
exec > /var/log/user-data.log 2>&1
apt-get update -y
apt-get install -y python3-venv curl git

# ==========================================================================
# 판단 서비스(auth_gate.py): nginx가 요청을 앱에 넘기기 전에 먼저 묻는 곳 (auth_request)
#   - 이 서버 안에서 127.0.0.1:9000으로만 받음. 전용 계정(ztgate)으로 실행해서 nginx 프로세스가
#     비밀키(.env)를 읽지 못하게 함 (env 파일은 root만 읽기 가능, systemd가 읽어서 넘겨줌)
#   - 죽어도 systemd가 바로 다시 띄움(재시작 횟수 제한 없음). 응답이 없으면 nginx가 차단(fail-closed)
# ==========================================================================
# gunicorn은 --no-control-socket 옵션이 있는 버전(26.2.0에서 확인)으로 고정함. 이 옵션이 없는 옛 버전이
# 깔리면 서비스가 시작되지 않으므로, 버전을 올릴 때는 옵션 존재 여부를 먼저 확인할 것.
# Ubuntu 24.04부터 시스템 Python에 pip로 직접 설치하는 것이 막혀 있어(PEP 668 "externally managed"),
# 판단 서비스 전용 가상환경(/opt/ztgate/venv)에 설치한다. 이 서버에서 Python을 쓰는 곳은 모두 이 가상환경을 쓴다.
useradd --system --no-create-home --shell /usr/sbin/nologin ztgate || true
mkdir -p /opt/ztgate /etc/ztgate
python3 -m venv /opt/ztgate/venv
/opt/ztgate/venv/bin/pip install --no-cache-dir flask "gunicorn==26.2.0" pyjwt cryptography requests boto3

# [코드 받기] 판단 서비스 코드(auth_gate.py, zt_jwt.py, zt_risk.py, zt_waf.py)는 S3(code_bucket.tf)에서 받는다.
# user_data에 넣으면 압축 후에도 16KB 한도를 넘는다(WAF 모듈 추가 후). 이 서버 역할은 자기 코드 파일만 읽을 수 있다.
# 코드 버전(파일 해시) - 코드가 바뀌면 이 줄이 바뀌어 서버가 새로 만들어진다: ${web_code_version}
for i in $(seq 1 30); do
  if /opt/ztgate/venv/bin/python -c "
import boto3
s3 = boto3.client('s3', region_name='${aws_region}')
for name in ('auth_gate.py', 'zt_jwt.py', 'zt_risk.py', 'zt_waf.py'):
    s3.download_file('${code_bucket}', 'web/' + name, '/opt/ztgate/' + name)
"; then echo "gate code ok after $i tries"; break; fi
  sleep 10
done
test -s /opt/ztgate/auth_gate.py || { echo "gate code download failed"; exit 1; }

chown -R root:root /opt/ztgate
chmod 755 /opt/ztgate
chmod 644 /opt/ztgate/*.py

cat << 'ZTENV' > /etc/ztgate/env
PDP_EVALUATE_URL=${pdp_evaluate_url}
EVALUATE_SHARED_SECRET=${evaluate_shared_secret}
AUTH_DOMAIN=${auth_domain}
ZT_WAF_ENABLED=1
ZT_WAF_LOG=/var/log/modsec/zt_waf_app.log
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
ExecStart=/opt/ztgate/venv/bin/python -m gunicorn --workers 1 --threads 8 --bind 127.0.0.1:9000 --timeout 15 --graceful-timeout 5 --no-control-socket auth_gate:app
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
# [WAF] ModSecurity v3(libmodsecurity) + nginx 연결 모듈. Ubuntu 24.04 저장소의 패키지를 쓴다
# (22.04 저장소에는 nginx용 연결 모듈 패키지가 없어 웹 서버만 24.04로 올림 - network.tf ubuntu_noble).
apt-get install -y nginx libnginx-mod-http-modsecurity
# [Web->WAS mTLS] 내부 CA 인증서 + 이 서버(웹)의 클라이언트 인증서/개인키를 SSM에서 받는다(mtls.tf, 자기 것만 읽기 권한).
# nginx는 시작할 때 root로 이 파일들을 읽으므로 개인키는 root만 읽을 수 있게 둔다. IAM 권한 반영을 기다려 최대 5분 재시도.
mkdir -p /etc/zt-mtls
for i in $(seq 1 30); do
  if /opt/ztgate/venv/bin/python -c "
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

# ==========================================================================
# [WAF] ModSecurity + OWASP CRS(Core Rule Set)
#   CRS 버전: Ubuntu 24.04의 libmodsecurity는 3.0.12다. CRS 4.x 최신과 3.3.10은 3.0.16 이상을 요구해
#   설정 로딩 자체가 실패한다(실측 + CRS CHANGES). 그래서 이 엔진에서 동작하는 최신 3.3.x인 v3.3.9를 쓴다.
#   받은 파일이 바뀌지 않았는지 커밋 해시로 확인하고, 다르면 부팅을 멈춘다(웹 서버가 안 뜨면 터널도 안 열려 접근 불가 = fail-closed).
# ==========================================================================
CRS_TMP=/tmp/coreruleset
for i in $(seq 1 5); do
  rm -rf "$CRS_TMP"
  git clone --quiet --depth 1 --branch ${crs_version} https://github.com/coreruleset/coreruleset "$CRS_TMP" && break
  sleep 5
done
if [ "$(git -C "$CRS_TMP" rev-parse HEAD 2>/dev/null)" != "${crs_commit}" ]; then
  echo "CRS commit mismatch or download failed - stop"
  exit 1
fi
mkdir -p /etc/nginx/zt-modsec /var/log/modsec
rm -rf /etc/nginx/zt-modsec/crs-rules
cp -r "$CRS_TMP/rules" /etc/nginx/zt-modsec/crs-rules
cp "$CRS_TMP/crs-setup.conf.example" /etc/nginx/zt-modsec/crs-setup.conf
rm -rf "$CRS_TMP"

cat << 'MODSEC' > /etc/nginx/zt-modsec/main.conf
# 패키지 기본 권장 설정(요청 본문 검사, 크기 제한, JSON/XML 본문 해석 등)을 읽고, 아래에서 필요한 것만 덮어쓴다.
Include /etc/nginx/modsecurity.conf
# On = 막음, DetectionOnly = 기록만(오탐 확인용). Terraform 변수 waf_engine_mode로 바꾼다.
SecRuleEngine ${waf_engine_mode}
# 응답 본문 검사는 끈다(이 프로젝트의 앱 응답은 우리가 만든 페이지라 정보 유출 검사 대상이 아니고, 메모리를 아낌).
SecResponseBodyAccess Off
# JSON 감사 로그는 쓰지 않는다: 차단 화면(error_page)을 쓰면 감사 로그에 탐지 내용이 비어서 남았다(실측).
# 차단 기록은 nginx 오류 로그(아래 서버별 error_log)에 남고, 판단 서비스(zt_waf.py)는 그 로그를 읽는다.
SecAuditEngine Off
Include /etc/nginx/zt-modsec/crs-setup.conf
Include /etc/nginx/zt-modsec/crs-rules/*.conf
# CRS 차단 규칙(949110)의 기록 내용에 "누가(검증된 신원), 어디서, 어떤 공격 점수로" 막혔는지를 넣는다.
# X-ZT-Identity는 앞단 nginx가 판단 서비스의 JWT 검증 결과로 덮어쓴 값이라 클라이언트가 위조할 수 없다.
# (이 지시어는 규칙의 동작을 통째로 바꾸므로 원래 동작인 deny도 다시 적는다 - 빼면 막지 않게 됨을 실측으로 확인)
SecRuleUpdateActionById 949110 "deny,status:403,logdata:'zt_identity=%%{REQUEST_HEADERS.x-zt-identity} zt_host=%%{REQUEST_HEADERS.host} sqli=%%{tx.sql_injection_score} xss=%%{tx.xss_score} rce=%%{tx.rce_score} lfi=%%{tx.lfi_score} rfi=%%{tx.rfi_score} php=%%{tx.php_injection_score} fixation=%%{tx.session_fixation_score}'"
MODSEC

# WAF 로그 교체(매일, 7일 보관). nginx에 로그 파일을 다시 열게 해서 판단 서비스가 새 파일을 이어 읽는다.
cat << 'LOGROTATE' > /etc/logrotate.d/zt-modsec
/var/log/modsec/*.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        invoke-rc.d nginx rotate >/dev/null 2>&1 || true
    endscript
}
LOGROTATE

cat << 'NGINX' > /etc/nginx/sites-available/default
map $request_uri $zt_unavailable_target {
    ~^/api/  @zt_unavailable_api;
    default  @zt_unavailable;
}

# ==========================================================================
# nginx 2단계 구조: 앞단(80) = 신원 확인(auth_request)  ->  내부 단계(127.0.0.1) = WAF(ModSecurity) 검사 -> 앱
#   ModSecurity는 nginx의 인증 단계(auth_request)보다 먼저 돌기 때문에, 한 단계 안에서는 "누가" 보냈는지 모른다.
#   그래서 앞단에서 신원을 확인해 X-ZT-Identity로 덮어써 넘기고, 내부 단계의 WAF가 그 값을 차단 기록에 남긴다.
#   내부 단계는 127.0.0.1에서만 받으므로 외부에서 X-ZT-Identity를 직접 넣을 수 없다.
# ==========================================================================

# [Web->WAS mTLS] 로그인 서버(auth.xmcda.store)도 이 nginx를 거쳐 mTLS로 보낸다. 로그인 서버 자체는 위험도 판단
# (auth_request) 대상이 아니므로(로그인 화면을 보기 전에 Access 토큰을 요구하면 로그인을 할 수 없다) 신원 없이 WAF 단계로 넘긴다.
server {
    listen 80;
    server_name ${auth_domain};

    location / {
        proxy_pass http://127.0.0.1:8082;
        proxy_set_header Host $host;
        # 로그인 전에는 검증된 신원이 없다: 클라이언트가 보낸 같은 이름의 헤더는 버린다
        proxy_set_header X-ZT-Identity "";
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
        auth_request_set $zt_identity $upstream_http_x_zt_identity;
        error_page 401 403 = @zt_denied;
        error_page 500 502 503 504 = $zt_unavailable_target;

        # WAF 단계로: 신원은 판단 서비스가 JWT 서명 검증으로 확인한 값으로 항상 덮어쓴다(클라이언트가 보낸 값은 버려짐)
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-ZT-Identity $zt_identity;
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

# ---- 내부 단계(WAF): 앱 ----
server {
    listen 127.0.0.1:8081;
    # 앱 단계 WAF 차단 기록만 따로 남긴다(판단 서비스 zt_waf.py가 이 파일을 읽어 신원과 연결)
    error_log /var/log/modsec/zt_waf_app.log warn;
    modsecurity on;
    modsecurity_rules_file /etc/nginx/zt-modsec/main.conf;
    # WAF가 막으면 보여줄 화면(named location: 실측에서 이 방식일 때 차단 기록이 정상으로 남음)
    error_page 403 @zt_waf_blocked;

    location @zt_waf_blocked {
        default_type "text/html; charset=utf-8";
        return 403 '<!DOCTYPE html><html><head><meta charset="utf-8"><title>요청이 차단되었습니다</title></head><body style="font-family:sans-serif;margin:40px;background:#f4f6f9;"><div style="background:white;padding:30px;border-radius:12px;max-width:520px;margin:60px auto;"><h2>요청이 차단되었습니다</h2><p>보안 정책에 맞지 않는 요청이 감지되어 차단했습니다. 이 기록은 계정의 위험도에 반영되며, 계속 접근이 막히면 관리자에게 문의하세요.</p></div></body></html>';
    }

    location / {
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
        proxy_set_header X-Real-IP $http_x_real_ip;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
        # WAF 기록용 신원 헤더는 앱에 넘기지 않는다(앱은 서명 검증된 JWT만 씀)
        proxy_set_header X-ZT-Identity "";
    }
}

# ---- 내부 단계(WAF): 로그인 서버 ----
server {
    listen 127.0.0.1:8082;
    # 로그인 전 공격은 신원이 없어 사람과 연결하지 않는다(막기만 함). 앱 단계와 다른 파일에 남긴다.
    error_log /var/log/modsec/zt_waf_auth.log warn;
    modsecurity on;
    modsecurity_rules_file /etc/nginx/zt-modsec/main.conf;
    error_page 403 @zt_waf_blocked;

    location @zt_waf_blocked {
        default_type "text/html; charset=utf-8";
        return 403 '<!DOCTYPE html><html><head><meta charset="utf-8"><title>요청이 차단되었습니다</title></head><body style="font-family:sans-serif;margin:40px;background:#f4f6f9;"><div style="background:white;padding:30px;border-radius:12px;max-width:520px;margin:60px auto;"><h2>요청이 차단되었습니다</h2><p>보안 정책에 맞지 않는 요청이 감지되어 차단했습니다.</p></div></body></html>';
    }

    location / {
        proxy_pass https://${auth_private_ip}:8080;
        proxy_ssl_name auth.zt.internal;
        proxy_ssl_certificate         /etc/zt-mtls/me.crt;
        proxy_ssl_certificate_key     /etc/zt-mtls/me.key;
        proxy_ssl_trusted_certificate /etc/zt-mtls/ca.crt;
        proxy_ssl_verify              on;
        proxy_ssl_verify_depth        2;
        proxy_ssl_server_name         on;
        proxy_ssl_protocols           TLSv1.2 TLSv1.3;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $http_x_real_ip;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
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
