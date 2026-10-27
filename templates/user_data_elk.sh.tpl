#!/bin/bash
# ==========================================================================
# 관제 서버: Elasticsearch + Kibana + Logstash + Filebeat(CloudWatch) + ElastAlert2(Discord) + cloudflared(Kibana 전용 터널)
#   모든 서비스는 이 서버 안(127.0.0.1)에서만 듣는다. 밖에서 들어오는 건 Filebeat -> Logstash 5044(상호 TLS, 보안그룹으로 웹/앱 티어만)뿐.
#   비밀번호/인증서/Discord 주소는 user_data에 넣지 않고 부팅 때 SSM에서 읽는다(elk.tf).
# ==========================================================================
exec > /var/log/user-data.log 2>&1
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y gnupg curl jq python3-boto3 python3-venv
install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor --yes -o /etc/apt/keyrings/elastic.gpg
echo "deb [signed-by=/etc/apt/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
apt-get update -y
# 같은 저장소에서 한 번에 받으므로 네 제품의 버전이 같다(Elasticsearch/Kibana/Logstash는 버전을 맞춰야 함)
apt-get install -y elasticsearch kibana logstash filebeat

# ---------- 비밀 값(SSM) ----------
install -d -m 0700 /root/zt
python3 - << 'PY'
import boto3
ssm = boto3.client('ssm', region_name='${aws_region}')
get = lambda n: ssm.get_parameter(Name=n, WithDecryption=True)['Parameter']['Value']
for name in ('elastic', 'kibana_system', 'logstash_writer', 'elastalert', 'kibana_encryption_key', 'discord_webhook_url', 'logs_cert', 'logs_key'):
    open('/root/zt/' + name, 'w').write(get('${param_prefix}/' + name))
open('/root/zt/ca.crt', 'w').write(get('${ca_param}'))
PY
chmod 600 /root/zt/*
pw() { cat "/root/zt/$1"; }

# ---------- Elasticsearch: 이 서버 안에서만, 힙 2GB(t3.large 8GB 중 Logstash 1GB, Kibana 약 1GB 몫을 남김) ----------
sed -i -E 's/^#?network\.host:.*/network.host: 127.0.0.1/; s/^http\.host:.*/http.host: 127.0.0.1/' /etc/elasticsearch/elasticsearch.yml
grep -q '^network.host' /etc/elasticsearch/elasticsearch.yml || echo 'network.host: 127.0.0.1' >> /etc/elasticsearch/elasticsearch.yml
printf -- '-Xms2g\n-Xmx2g\n' > /etc/elasticsearch/jvm.options.d/heap.options
systemctl daemon-reload
systemctl enable --now elasticsearch
ES=https://127.0.0.1:9200
ESCA=/etc/elasticsearch/certs/http_ca.crt
for i in $(seq 1 60); do curl -s --cacert $ESCA $ES >/dev/null && break; sleep 5; done
# 설치 때 자동 생성된 elastic 비밀번호를 받아 우리 값(SSM)으로 바꾼다
GEN=$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b -s)
es() { curl -sf --cacert $ESCA -u "elastic:$(pw elastic)" -H 'Content-Type: application/json' "$@"; }
# 보안 인덱스가 막 만들어지는 중이면 실패할 수 있어 몇 번 다시 시도한다
for i in $(seq 1 30); do
  curl -sf --cacert $ESCA -u "elastic:$GEN" -H 'Content-Type: application/json' -X POST $ES/_security/user/elastic/_password -d "{\"password\":\"$(pw elastic)\"}" && break
  sleep 5
done
es -X POST $ES/_security/user/kibana_system/_password -d "{\"password\":\"$(pw kibana_system)\"}"
# 최소 권한 계정: Logstash는 zt-logs-* 쓰기만, ElastAlert2는 zt-logs-* 읽기 + 자기 상태 인덱스(elastalert*)만
es -X POST $ES/_security/role/zt_logs_writer -d '{"cluster":["monitor","manage_index_templates"],"indices":[{"names":["zt-logs-*"],"privileges":["create_index","create_doc","write"]}]}'
es -X POST $ES/_security/user/logstash_writer -d "{\"password\":\"$(pw logstash_writer)\",\"roles\":[\"zt_logs_writer\"]}"
es -X POST $ES/_security/role/zt_alert_reader -d '{"cluster":["monitor"],"indices":[{"names":["zt-logs-*"],"privileges":["read","view_index_metadata"]},{"names":["elastalert*"],"privileges":["all"]}]}'
es -X POST $ES/_security/user/elastalert -d "{\"password\":\"$(pw elastalert)\",\"roles\":[\"zt_alert_reader\"]}"
# 필드 형식 고정(점수는 숫자, 이름/신호는 정확히 일치하는 keyword) - 대시보드 집계와 알림 조건이 흔들리지 않게
es -X PUT $ES/_index_template/zt-logs -d '{"index_patterns":["zt-logs-*"],"template":{"settings":{"number_of_replicas":0},"mappings":{"dynamic_templates":[{"zt_strings":{"path_match":"zt.*","match_mapping_type":"string","mapping":{"type":"keyword","ignore_above":1024}}}],"properties":{"zt":{"properties":{"score":{"type":"integer"},"allow":{"type":"boolean"},"ts":{"type":"long"},"client_ip":{"type":"ip"},"src":{"properties":{"geo":{"properties":{"location":{"type":"geo_point"}}}}}}},"message":{"type":"text"}}}}}'

# ---------- Kibana: 이 서버 안에서만(밖에서는 Cloudflare Tunnel + Access를 거쳐야 함) ----------
cp $ESCA /etc/kibana/http_ca.crt && chown root:kibana /etc/kibana/http_ca.crt
cat >> /etc/kibana/kibana.yml << KBCONF
server.host: "127.0.0.1"
server.publicBaseUrl: "https://${kibana_host}"
elasticsearch.hosts: ["https://127.0.0.1:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "$(pw kibana_system)"
elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/http_ca.crt"]
xpack.encryptedSavedObjects.encryptionKey: "$(pw kibana_encryption_key)"
KBCONF
systemctl enable --now kibana

# ---------- Logstash: 5044(다른 서버 Filebeat, 상호 TLS) + 127.0.0.1:5045(이 서버 Filebeat, CloudWatch) ----------
install -d -m 0750 -o root -g logstash /etc/logstash/zt
cp /root/zt/ca.crt /etc/logstash/zt/ca.crt
cp /root/zt/logs_cert /etc/logstash/zt/logs.crt
cp /root/zt/logs_key /etc/logstash/zt/logs.key
cp $ESCA /etc/logstash/zt/http_ca.crt
chown root:logstash /etc/logstash/zt/* && chmod 640 /etc/logstash/zt/*
echo "LS_ES_PW=$(pw logstash_writer)" > /etc/default/logstash && chmod 600 /etc/default/logstash
cat > /etc/logstash/conf.d/zt.conf << 'LSCONF'
input {
  beats {
    port => 5044
    ssl_enabled => true
    ssl_certificate => "/etc/logstash/zt/logs.crt"
    ssl_key => "/etc/logstash/zt/logs.key"
    ssl_certificate_authorities => ["/etc/logstash/zt/ca.crt"]
    ssl_client_authentication => "required"
  }
  beats {
    host => "127.0.0.1"
    port => 5045
  }
}
filter {
  # 서비스마다 같은 형식의 구조화 줄: "ZT_EVENT {json}" -> zt.* 필드
  if [message] =~ /ZT_EVENT \{/ {
    grok { match => { "message" => "ZT_EVENT %%{GREEDYDATA:[@metadata][zt_json]}" } }
    json { source => "[@metadata][zt_json]" target => "zt" }
    date { match => ["[zt][ts]", "UNIX"] }
    mutate { add_tag => ["zt_event"] }
    if [zt][client_ip] {
      # Logstash에 들어 있는 GeoLite2(Elastic이 자동 갱신)로 지도용 위치를 붙인다
      geoip { source => "[zt][client_ip]" target => "[zt][src]" }
    }
  } else if [message] =~ /^\[[A-Z_]+\]/ {
    # 사람이 읽는 기존 줄: [TAG] 이름만 따로 뽑아 검색하기 쉽게
    grok { match => { "message" => "^\[%%{DATA:log_tag}\]" } }
  }
  if [message] =~ /ModSecurity: Access denied/ {
    mutate { add_tag => ["waf_block"] }
  }
}
output {
  elasticsearch {
    hosts => ["https://127.0.0.1:9200"]
    user => "logstash_writer"
    password => "$${LS_ES_PW}"
    ssl_certificate_authorities => ["/etc/logstash/zt/http_ca.crt"]
    index => "zt-logs-%%{+YYYY.MM.dd}"
  }
}
LSCONF
# Logstash 힙은 기본값(1GB) 그대로 쓴다
systemctl enable --now logstash

# ---------- Filebeat(이 서버): Lambda 로그(CloudWatch Logs) -> Logstash ----------
cat > /etc/filebeat/filebeat.yml << 'FBCONF'
filebeat.inputs:
%{ for g in lambda_groups ~}
  - type: aws-cloudwatch
    log_group_arn: ${g}
    scan_frequency: 30s
    start_position: end
    fields:
      zt_server: lambda
    fields_under_root: true
%{ endfor ~}
output.logstash:
  hosts: ["127.0.0.1:5045"]
logging.level: warning
FBCONF
chmod 600 /etc/filebeat/filebeat.yml
systemctl enable --now filebeat

# ---------- ElastAlert2 -> Discord (Kibana 무료 등급은 외부 웹훅 알림이 유료) ----------
python3 -m venv /opt/elastalert/venv
/opt/elastalert/venv/bin/pip install --no-cache-dir "elastalert2==2.31.0"
useradd --system --home /opt/elastalert --shell /usr/sbin/nologin elastalert || true
install -d -m 0750 /opt/elastalert/rules
cp $ESCA /opt/elastalert/http_ca.crt
cat > /opt/elastalert/config.yaml << EACONF
rules_folder: /opt/elastalert/rules
run_every:
  seconds: 30
buffer_time:
  minutes: 15
es_host: 127.0.0.1
es_port: 9200
use_ssl: true
verify_certs: true
ca_certs: /opt/elastalert/http_ca.crt
es_username: elastalert
es_password: "$(pw elastalert)"
writeback_index: elastalert_status
alert_time_limit:
  days: 1
EACONF
HOOK="$(pw discord_webhook_url)"
# 규칙 1: 바로 봐야 하는 사건(사람마다 5분에 한 번)
cat > /opt/elastalert/rules/zt_high_severity.yaml << EARULE
name: "ZT 즉시 대응"
type: any
index: zt-logs-*
filter:
  - query:
      query_string:
        query: 'zt.event:(waf_reported OR login_locked OR pwned_password_detected OR mtls_client_rejected OR risk_release) OR (zt.event:device_sweep AND zt.action:device_session_revoked) OR (zt.event:decision AND zt.signals:(threat_intel_match OR geo_velocity OR session_country_change OR waf_sqli OR waf_attack))'
query_key: zt.identity
realert:
  minutes: 5
alert:
  - discord
discord_webhook_url: "$HOOK"
discord_embed_color: 0xe74c3c
alert_subject: "[ZT 즉시 대응] {0} / {1}"
alert_subject_args: ["zt.event", "zt.identity"]
alert_text_type: alert_text_only
alert_text: "사용자: {0}\n판단/행동: {1}\n점수: {2}\n신호: {3}\n자원: {4}\n접속 IP: {5}\n서비스: {6}\n시각: {7}\n대응 절차: docs/runbook.md"
alert_text_args: ["zt.identity", "zt.action", "zt.score", "zt.signals", "zt.resource", "zt.client_ip", "zt.service", "@timestamp"]
EARULE
# 규칙 2: 같은 사람이 10분에 5번 이상 막힘(반복 시도)
cat > /opt/elastalert/rules/zt_repeated_denials.yaml << EARULE
name: "ZT 반복 차단"
type: frequency
index: zt-logs-*
num_events: 5
timeframe:
  minutes: 10
filter:
  - query:
      query_string:
        query: 'zt.event:decision AND zt.allow:false'
query_key: zt.identity
realert:
  minutes: 10
alert:
  - discord
discord_webhook_url: "$HOOK"
discord_embed_color: 0xf39c12
alert_subject: "[ZT 반복 차단] {0}"
alert_subject_args: ["zt.identity"]
alert_text_type: alert_text_only
alert_text: "10분 안에 5번 이상 차단/재인증 요구됨\n사용자: {0}\n마지막 판단: {1} (점수 {2})\n신호: {3}\n대응 절차: docs/runbook.md"
alert_text_args: ["zt.identity", "zt.action", "zt.score", "zt.signals"]
EARULE
# 규칙 3: 판단 엔진 장애(웹 서버가 엔진에 물어보지 못해 막은 요청이 5분에 3건 이상) - 전 직원이 막히는 상황
cat > /opt/elastalert/rules/zt_pdp_unavailable.yaml << EARULE
name: "ZT 판단 엔진 장애"
type: frequency
index: zt-logs-*
num_events: 3
timeframe:
  minutes: 5
filter:
  - query:
      query_string:
        query: 'zt.event:gate_deny AND zt.action:pdp_unavailable'
realert:
  minutes: 15
alert:
  - discord
discord_webhook_url: "$HOOK"
discord_embed_color: 0x8e44ad
alert_subject: "[ZT 장애] 판단 엔진 응답 없음"
alert_text_type: alert_text_only
alert_text: "웹 서버가 판단 엔진(Lambda)에 묻지 못해 요청을 막고 있습니다(fail-closed).\n마지막 사용자: {0}\n대응 절차: docs/runbook.md"
alert_text_args: ["zt.identity"]
EARULE
chown -R elastalert:elastalert /opt/elastalert && chmod 600 /opt/elastalert/config.yaml /opt/elastalert/rules/*.yaml
sudo -u elastalert /opt/elastalert/venv/bin/elastalert-create-index --config /opt/elastalert/config.yaml || true
cat > /etc/systemd/system/elastalert.service << 'EASVC'
[Unit]
Description=ElastAlert2 (ZT alerts to Discord)
After=elasticsearch.service
[Service]
User=elastalert
WorkingDirectory=/opt/elastalert
ExecStart=/opt/elastalert/venv/bin/elastalert --config /opt/elastalert/config.yaml --verbose
Restart=always
RestartSec=10
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EASVC
systemctl daemon-reload
systemctl enable --now elastalert

# ---------- Kibana 데이터 보기(zt-logs-*) 자동 생성 ----------
for i in $(seq 1 60); do curl -s -u "elastic:$(pw elastic)" http://127.0.0.1:5601/api/status | grep -q '"level":"available"' && break; sleep 5; done
curl -s -u "elastic:$(pw elastic)" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/api/data_views/data_view \
  -d '{"data_view":{"title":"zt-logs-*","name":"ZT 로그","timeFieldName":"@timestamp"}}' || true

# ---------- cloudflared: Kibana 전용 터널(이 서버 -> Cloudflare 바깥 방향 연결만, 열린 포트 없음) ----------
curl -L --output /tmp/cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
dpkg -i /tmp/cloudflared.deb
mkdir -p /etc/cloudflared
cat > /etc/cloudflared/config.yml << CFCONFIG
ingress:
  - hostname: ${kibana_host}
    service: http://127.0.0.1:5601
  - service: http_status:404
CFCONFIG
cloudflared service install ${tunnel_token}
systemctl restart cloudflared
rm -rf /root/zt
echo "ELK setup done"
