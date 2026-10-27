# ==========================================
# 관제 콘솔(SOC 스타일): Elastic Stack(Filebeat -> Logstash -> Elasticsearch -> Kibana) + ElastAlert2 -> Discord
#
#  흐름
#   - 웹/인증/앱 서버: Filebeat가 서비스 로그(journald)와 WAF 로그를 읽어 Logstash로 보낸다(내부 CA 인증서로 상호 TLS).
#   - Lambda(엔진/순찰/해제): print가 CloudWatch Logs로 가고, 관제 서버의 Filebeat(aws-cloudwatch 입력)가 가져온다.
#   - Logstash: "ZT_EVENT {json}" 줄을 JSON으로 풀고(서비스마다 같은 키), 접속 IP 위치(GeoIP)를 붙여 Elasticsearch에 저장.
#   - Kibana: 관리자만. 공개 포트 없이 관제 서버 전용 Cloudflare Tunnel + Access(관리자 그룹 + 위험점수 평가) 뒤에 둔다.
#     우리 서비스의 접근 통제(로그인 + 위험점수)를 관제 도구에도 똑같이 적용한다.
#   - 알림: Kibana 무료(Basic) 등급은 외부(웹훅) 알림 커넥터가 유료라, 직접 구축 환경에서 흔히 쓰는 오픈소스
#     ElastAlert2가 Elasticsearch를 주기적으로 조회해 조건이 맞으면 Discord로 보낸다.
#
#  스위치: enable_elk(기본 false). 큰 서버(m7i-flex.large, 8GB)라 시험/데모 날만 켠다. 켜고 끄면 웹/인증/앱 서버의 user_data(Filebeat 설치)가
#          바뀌어 그 서버들도 다시 만들어지므로, 하루 시작할 때 apply에서 정한다.
#  데이터: 매일 destroy하므로 로그도 그날치만 남는다(시연용). 오래 보관하려면 S3 스냅샷 저장소를 쓴다(향후 과제).
# ==========================================
locals {
  elk_enabled      = var.enable_elk ? 1 : 0
  elk_private_ip   = "10.0.2.200"          # 고정 IP: 다른 서버의 Filebeat 설정이 관제 서버 생성 순서에 묶이지 않게
  elk_logs_name    = "logs.zt.internal"    # Logstash 인증서 이름(Filebeat가 이 이름으로 서버 인증서를 확인)
  elk_param_prefix = "/zt/elk"
  kibana_host      = "kibana.${var.domain_name}"
  # Filebeat를 설치할 서버: 역할 -> (읽을 서비스, 추가 로그 파일, boto3가 있는 파이썬)
  elk_beats = {
    web  = { units = ["ztgate.service", "nginx.service"], paths = ["/var/log/modsec/zt_waf_app.log", "/var/log/modsec/zt_waf_auth.log"], python = "/opt/ztgate/venv/bin/python" }
    auth = { units = ["auth-app.service"], paths = [], python = "python3" }
    app  = { units = ["portal-app.service"], paths = [], python = "python3" }
  }
  # 각 서버 user_data에 끼워 넣을 Filebeat 설치 스크립트(끄면 빈 문자열)
  filebeat_setup = {
    for role, b in local.elk_beats : role => var.enable_elk ? templatefile("${path.module}/templates/filebeat_setup.sh.tpl", {
      role         = role
      units        = b.units
      paths        = b.paths
      python       = b.python
      aws_region   = var.aws_region
      param_prefix = local.elk_param_prefix
      logs_name    = local.elk_logs_name
      logs_ip      = local.elk_private_ip
    }) : ""
  }
}

# ---------- 비밀번호(관제 서버가 부팅 때 SSM에서 읽음) ----------
resource "random_password" "elk" {
  for_each = var.enable_elk ? toset(["elastic", "kibana_system", "logstash_writer", "elastalert", "kibana_encryption_key"]) : toset([])
  length   = each.key == "kibana_encryption_key" ? 48 : 24
  special  = false
}

resource "aws_ssm_parameter" "elk_password" {
  for_each = random_password.elk
  name     = "${local.elk_param_prefix}/${each.key}"
  type     = "SecureString"
  value    = each.value.result
}

resource "aws_ssm_parameter" "elk_discord_webhook" {
  count = local.elk_enabled
  name  = "${local.elk_param_prefix}/discord_webhook_url"
  type  = "SecureString"
  value = var.discord_webhook_url
  lifecycle {
    precondition {
      condition     = var.discord_webhook_url != ""
      error_message = "enable_elk=true이면 terraform.tfvars에 discord_webhook_url을 넣어야 합니다."
    }
  }
}

# ---------- 인증서: 내부 CA(mtls.tf)로 Logstash 서버 인증서 + 서버별 Filebeat 클라이언트 인증서 ----------
resource "tls_private_key" "elk" {
  for_each    = var.enable_elk ? toset(concat(["logs"], keys(local.elk_beats))) : toset([])
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "elk" {
  for_each        = tls_private_key.elk
  private_key_pem = each.value.private_key_pem
  dns_names       = [each.key == "logs" ? local.elk_logs_name : "beats-${each.key}.zt.internal"]
  subject {
    common_name  = each.key == "logs" ? local.elk_logs_name : "beats-${each.key}.zt.internal"
    organization = "ZT Project"
  }
}

resource "tls_locally_signed_cert" "elk" {
  for_each              = tls_cert_request.elk
  cert_request_pem      = each.value.cert_request_pem
  ca_private_key_pem    = tls_private_key.zt_ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.zt_ca.cert_pem
  validity_period_hours = local.mtls_validity_hours
  set_subject_key_id    = true
  allowed_uses          = each.key == "logs" ? ["digital_signature", "server_auth"] : ["digital_signature", "client_auth"]
}

resource "aws_ssm_parameter" "elk_cert" {
  for_each = tls_locally_signed_cert.elk
  name     = "${local.elk_param_prefix}/${each.key}_cert"
  type     = "String"
  value    = each.value.cert_pem
}

# Logstash beats 입력은 개인키를 PKCS#8 형식으로 요구한다(Logstash beats input 문서). Filebeat는 둘 다 읽는다.
resource "aws_ssm_parameter" "elk_key" {
  for_each = tls_private_key.elk
  name     = "${local.elk_param_prefix}/${each.key}_key"
  type     = "SecureString"
  value    = each.value.private_key_pem_pkcs8
}

# 각 서버 역할: 자기 Filebeat 인증서/키만 읽기(CA 인증서는 mtls.tf 권한으로 이미 읽을 수 있음)
resource "aws_iam_role_policy" "elk_beats_read" {
  for_each = var.enable_elk ? local.mtls_role_ids : {}
  name     = "zt-elk-beats-read-${each.key}"
  role     = each.value
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadOwnBeatsMaterial"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = [aws_ssm_parameter.elk_cert[each.key].arn, aws_ssm_parameter.elk_key[each.key].arn]
      },
      {
        Sid       = "DecryptViaSsmOnly"
        Effect    = "Allow"
        Action    = ["kms:Decrypt"]
        Resource  = [data.aws_kms_alias.ssm.target_key_arn]
        Condition = { StringEquals = { "kms:ViaService" = "ssm.${var.aws_region}.amazonaws.com" } }
      }
    ]
  })
}

# ---------- 관제 서버 IAM ----------
resource "aws_iam_role" "elk_role" {
  count = local.elk_enabled
  name  = "zt-elk-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "elk_ssm_core" {
  count      = local.elk_enabled
  role       = aws_iam_role.elk_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "elk_read" {
  count = local.elk_enabled
  name  = "zt-elk-read"
  role  = aws_iam_role.elk_role[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadElkSecrets"
        Effect = "Allow"
        Action = ["ssm:GetParameter"]
        Resource = concat(
          [for p in aws_ssm_parameter.elk_password : p.arn],
          [aws_ssm_parameter.elk_discord_webhook[0].arn, aws_ssm_parameter.mtls_ca_cert.arn,
          aws_ssm_parameter.elk_cert["logs"].arn, aws_ssm_parameter.elk_key["logs"].arn]
        )
      },
      {
        Sid       = "DecryptViaSsmOnly"
        Effect    = "Allow"
        Action    = ["kms:Decrypt"]
        Resource  = [data.aws_kms_alias.ssm.target_key_arn]
        Condition = { StringEquals = { "kms:ViaService" = "ssm.${var.aws_region}.amazonaws.com" } }
      },
      {
        # Kibana 저장 객체 파일만 읽기(다른 코드 파일, 목록 보기, 쓰기 없음)
        Sid      = "ReadKibanaObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${aws_s3_bucket.app_code.arn}/elk/kibana/*"]
      },
      {
        # Filebeat aws-cloudwatch 입력에 필요한 권한(Filebeat 문서: DescribeLogGroups, FilterLogEvents). 우리 Lambda 3개 로그만.
        Sid    = "ReadLambdaLogs"
        Effect = "Allow"
        Action = ["logs:FilterLogEvents", "logs:DescribeLogGroups"]
        Resource = [for f in local.elk_lambda_names :
        "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${f}:*"]
      }
    ]
  })
}

locals {
  elk_lambda_names = ["risk-score-engine", "zt-device-sweep", "risk-admin"]
  # 관제 콘솔 Kibana 저장 객체(데이터 보기, 저장된 검색, 대시보드). 폴더에 ndjson을 넣으면 자동으로 올라가고 불러와진다.
  kibana_files = { for f in fileset("${path.module}/kibana", "*.ndjson") : "elk/kibana/${f}" => "${path.module}/kibana/${f}" }
}

resource "aws_s3_object" "kibana" {
  for_each = var.enable_elk ? local.kibana_files : {}
  bucket   = aws_s3_bucket.app_code.id
  key      = each.key
  source   = each.value
  etag     = filemd5(each.value)

  depends_on = [aws_s3_bucket_server_side_encryption_configuration.app_code]
}

resource "aws_iam_instance_profile" "elk_profile" {
  count = local.elk_enabled
  name  = "zt-elk-profile"
  role  = aws_iam_role.elk_role[0].name
}

# ---------- 네트워크: 들어오는 건 Filebeat(5044, 웹/앱 티어 보안그룹에서만), 나가는 건 패키지/Cloudflare/AWS API ----------
resource "aws_security_group" "elk_sg" {
  count       = local.elk_enabled
  name_prefix = "zt-elk-sg-"
  description = "ELK monitor: Beats 5044 from web/app tiers only"
  vpc_id      = aws_vpc.zt_vpc.id
}

resource "aws_vpc_security_group_ingress_rule" "elk_from_tiers" {
  for_each                     = var.enable_elk ? { web = aws_security_group.web_sg.id, app = aws_security_group.app_sg.id } : {}
  security_group_id            = aws_security_group.elk_sg[0].id
  referenced_security_group_id = each.value
  description                  = "Filebeat to Logstash (mTLS) from ${each.key} tier"
  from_port                    = 5044
  to_port                      = 5044
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "tiers_to_elk" {
  for_each                     = var.enable_elk ? { web = aws_security_group.web_sg.id, app = aws_security_group.app_sg.id } : {}
  security_group_id            = each.value
  referenced_security_group_id = aws_security_group.elk_sg[0].id
  description                  = "Filebeat to Logstash 5044"
  from_port                    = 5044
  to_port                      = 5044
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "elk_out" {
  for_each = var.enable_elk ? {
    https      = { port = 443, proto = "tcp" }
    http       = { port = 80, proto = "tcp" }
    tunnel_udp = { port = 7844, proto = "udp" }
    tunnel_tcp = { port = 7844, proto = "tcp" }
  } : {}
  security_group_id = aws_security_group.elk_sg[0].id
  cidr_ipv4         = "0.0.0.0/0"
  description       = "ELK outbound ${each.key} (packages, AWS API, Cloudflare Tunnel)"
  from_port         = each.value.port
  to_port           = each.value.port
  ip_protocol       = each.value.proto
}

# ---------- Kibana 공개 경로: 관제 서버 전용 터널 + DNS + Access 앱(관리자 + 위험점수) ----------
resource "random_id" "elk_tunnel_secret" {
  count       = local.elk_enabled
  byte_length = 35
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "elk_tunnel" {
  count      = local.elk_enabled
  account_id = var.cloudflare_account_id
  name       = "zt-elk-tunnel"
  secret     = random_id.elk_tunnel_secret[0].b64_std
}

# 원격 설정도 같이 둔다(웹 터널과 같은 방식: 서버의 로컬 config.yml과 같은 내용)
resource "cloudflare_zero_trust_tunnel_cloudflared_config" "elk_tunnel_config" {
  count      = local.elk_enabled
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.elk_tunnel[0].id
  config {
    ingress_rule {
      hostname = local.kibana_host
      service  = "http://127.0.0.1:5601"
    }
    ingress_rule {
      service = "http_status:404"
    }
  }
}

resource "cloudflare_record" "kibana_dns" {
  count   = local.elk_enabled
  zone_id = var.cloudflare_zone_id
  name    = "kibana"
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.elk_tunnel[0].id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
}

resource "cloudflare_zero_trust_access_application" "kibana" {
  count                     = local.elk_enabled
  account_id                = var.cloudflare_account_id
  name                      = "ZT Kibana (관제 콘솔)"
  domain                    = local.kibana_host
  type                      = "self_hosted"
  session_duration          = "15m"
  allowed_idps              = [cloudflare_zero_trust_access_identity_provider.login_server.id]
  auto_redirect_to_identity = true
  app_launcher_visible      = false
  custom_deny_url           = "https://auth.xmcda.store/stepup"
  # 관리자 콘솔과 같은 등급(엔진 RESOURCE_TIERS: kibana = top_secret): 위험점수 평가 + 관리자 그룹만
  policies = [
    cloudflare_zero_trust_access_policy.risk_block_shared.id,
    cloudflare_zero_trust_access_policy.admin_gate_console.id,
  ]
}

# ---------- 관제 서버 ----------
resource "aws_instance" "elk_server" {
  count                = local.elk_enabled
  ami                  = data.aws_ami.ubuntu_noble.id
  instance_type        = var.elk_instance_type
  subnet_id            = aws_subnet.app_subnet.id
  private_ip           = local.elk_private_ip
  iam_instance_profile = aws_iam_instance_profile.elk_profile[0].name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  vpc_security_group_ids      = [aws_security_group.elk_sg[0].id]
  user_data_replace_on_change = true
  user_data_base64 = base64gzip(templatefile("${path.module}/templates/user_data_elk.sh.tpl", {
    aws_region    = var.aws_region
    param_prefix  = local.elk_param_prefix
    ca_param      = aws_ssm_parameter.mtls_ca_cert.name
    tunnel_token  = cloudflare_zero_trust_tunnel_cloudflared.elk_tunnel[0].tunnel_token
    kibana_host   = local.kibana_host
    lambda_groups = [for f in local.elk_lambda_names : "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${f}:*"]
    # Kibana 저장 객체(kibana/*.ndjson): S3에서 받아 가져오기. 파일 내용이 바뀌면 키 목록 해시가 바뀌어 관제 서버가 다시 만들어진다
    code_bucket        = local.code_bucket_name
    kibana_object_keys = jsonencode([for k in sort(keys(local.kibana_files)) : k])
    kibana_version     = md5(join(",", [for k in sort(keys(local.kibana_files)) : filemd5(local.kibana_files[k])]))
  }))

  depends_on = [aws_ssm_parameter.elk_password, aws_ssm_parameter.elk_cert, aws_ssm_parameter.elk_key, aws_ssm_parameter.elk_discord_webhook,
  aws_s3_object.kibana, aws_iam_role_policy.elk_read]

  tags = {
    Name        = "ZT-ELK-Monitor"
    Environment = "ZeroTrust-Project"
  }
}
