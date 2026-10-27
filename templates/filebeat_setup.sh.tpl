
# ==========================================================================
# [관제] Filebeat: 이 서버(${role})의 서비스 로그와 WAF 로그를 관제 서버 Logstash로 보낸다(elk.tf, enable_elk=true일 때만 들어감).
#   - 전송 구간은 내부 CA 인증서로 상호 TLS(Logstash 서버 인증서 ${logs_name} 확인 + 이 서버의 클라이언트 인증서 제출)
#   - 실패해도 서비스 동작에는 영향이 없게 하위 셸에서 실행하고 결과만 남긴다.
# ==========================================================================
(
set -e
apt-get install -y gnupg curl
install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor --yes -o /etc/apt/keyrings/elastic.gpg
echo "deb [signed-by=/etc/apt/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
apt-get update -y
apt-get install -y filebeat
echo "${logs_ip} ${logs_name}" >> /etc/hosts
install -d -m 0750 /etc/filebeat/zt
for i in $(seq 1 30); do
  if ${python} -c "
import boto3
ssm = boto3.client('ssm', region_name='${aws_region}')
get = lambda n: ssm.get_parameter(Name=n, WithDecryption=True)['Parameter']['Value']
open('/etc/filebeat/zt/ca.crt', 'w').write(get('/zt/mtls/ca_cert'))
open('/etc/filebeat/zt/beats.crt', 'w').write(get('${param_prefix}/${role}_cert'))
open('/etc/filebeat/zt/beats.key', 'w').write(get('${param_prefix}/${role}_key'))
"; then break; fi
  sleep 5
done
chmod 600 /etc/filebeat/zt/beats.key
cat > /etc/filebeat/filebeat.yml << 'FBCONF'
filebeat.inputs:
  - type: journald
    id: zt-${role}-services
    include_matches.match:
%{ for u in units ~}
      - _SYSTEMD_UNIT=${u}
%{ endfor ~}
    fields:
      zt_server: ${role}
    fields_under_root: true
%{ if length(paths) > 0 ~}
  - type: filestream
    id: zt-${role}-waf
    paths:
%{ for p in paths ~}
      - ${p}
%{ endfor ~}
    fields:
      zt_server: ${role}
      zt_source: waf
    fields_under_root: true
%{ endif ~}
output.logstash:
  hosts: ["${logs_name}:5044"]
  ssl.enabled: true
  ssl.certificate_authorities: ["/etc/filebeat/zt/ca.crt"]
  ssl.certificate: "/etc/filebeat/zt/beats.crt"
  ssl.key: "/etc/filebeat/zt/beats.key"
  ssl.verification_mode: full
logging.level: warning
FBCONF
chmod 600 /etc/filebeat/filebeat.yml
systemctl enable --now filebeat
echo "filebeat setup ok"
) || echo "filebeat setup FAILED (service continues without log shipping)"
