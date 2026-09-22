# ==========================================
# 0. Provider 및 기본 설정
# ==========================================
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# ==========================================
# 0-1. 부서별 이메일 목록 + 로그인서버 서브도메인
#   (2026-09: 로그인서버를 login.xmcda.store로 분리 - Access가 xmcda.store를 통째로
#   지켜도 로그인서버 자신은 보호 대상 밖에 있어 "자기 자신을 지키는 문제"가 원천 차단됨)
# ==========================================
locals {
  auth_domain = "auth.${var.domain_name}"

  dev_team_emails       = ["employee01@xmcda.store", "employee02@xmcda.store", "employee03@xmcda.store", "employee04@xmcda.store"]
  marketing_team_emails = ["employee05@xmcda.store", "employee06@xmcda.store", "employee07@xmcda.store"]
  hr_team_emails        = ["employee08@xmcda.store", "employee09@xmcda.store"]
  all_employee_emails   = concat(local.dev_team_emails, local.marketing_team_emails, local.hr_team_emails, var.admin_allowed_emails)
}

# ==========================================
# 1. AWS DynamoDB (Risk Score & Audit Log)
# ==========================================
resource "aws_dynamodb_table" "risk_score_log" {
  name         = "risk_score_log"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"
  range_key    = "timestamp"

  attribute {
    name = "session_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "N"
  }

  tags = {
    Environment = "ZeroTrust-Project"
  }
}

# ==========================================
# 2. AWS IAM Role (EC2 DynamoDB 읽기 권한)
# ==========================================
resource "aws_iam_role" "ec2_role" {
  name_prefix = "zt-ec2-role-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_role_policy_attachment" "ec2_dynamodb" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
}

# EC2를 AWS 콘솔의 Session Manager로 SSH 없이 접속하기 위한 권한
# (부팅 스크립트 실패 원인 확인 등, 문제 해결 목적으로 추가)
resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name_prefix = "zt-ec2-profile-"
  role        = aws_iam_role.ec2_role.name

  lifecycle {
    create_before_destroy = true
  }
}

# ==========================================
# 3. AWS Lambda PDP Engine (History Decay & DynamoDB 저장)
# ==========================================
resource "aws_iam_role" "lambda_role" {
  name_prefix = "risk-score-lambda-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_dynamodb" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda.zip"
  source_file = "${path.module}/risk_score_engine.py"
}

# /evaluate가 인증 없이 URL만 알면 호출 가능한 문제 보완용 공유 비밀키.
# HTTP API(v2)는 API Key/Usage Plan을 지원하지 않아, Lambda가 직접 헤더를 검증하는 방식으로 대체.
# (2026-09: random_password -> variable로 전환. terraform.tfvars에 값 고정, destroy해도 유지됨)

resource "aws_lambda_function" "pdp_engine" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "risk-score-engine"
  role             = aws_iam_role.lambda_role.arn
  handler          = "risk_score_engine.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      EVALUATE_SHARED_SECRET = var.evaluate_shared_secret
    }
  }
}

# ==========================================
# 4. AWS API Gateway (HTTP API)
# ==========================================
resource "aws_apigatewayv2_api" "pdp_api" {
  name          = "risk-score-pdp-api"
  protocol_type = "HTTP"
  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["POST", "OPTIONS"]
    allow_headers = ["*"]
  }
}

resource "aws_apigatewayv2_integration" "pdp_integration" {
  api_id                 = aws_apigatewayv2_api.pdp_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.pdp_engine.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "pdp_route" {
  api_id    = aws_apigatewayv2_api.pdp_api.id
  route_key = "POST /evaluate"
  target    = "integrations/${aws_apigatewayv2_integration.pdp_integration.id}"
}

resource "aws_apigatewayv2_stage" "pdp_stage" {
  api_id      = aws_apigatewayv2_api.pdp_api.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "apigw_lambda" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pdp_engine.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.pdp_api.execution_arn}/*/*"
}

# ==========================================
# 5-0. Cloudflare Access Identity Provider — 우리 로그인서버를 OIDC IdP로 등록
#   Access가 "이메일 OTP" 대신 우리 로그인서버(app.py의 /authorize, /token,
#   /.well-known/jwks.json)로 신원을 확인하도록 등록. client_id/client_secret은
#   /token이 검증하는 값과 반드시 동일해야 함(variables.tf에서 관리, ec2_app.tf가
#   같은 값을 Flask 환경변수로도 전달함).
#   Access는 /token이 돌려주는 id_token(JWT)의 클레임(email 등)을 certs_url(JWKS)로
#   서명 검증해서 직접 읽어옴 — /userinfo를 따로 호출하진 않음(OIDC 표준 동작).
# ==========================================
resource "cloudflare_zero_trust_access_identity_provider" "login_server" {
  account_id = var.cloudflare_account_id
  name       = "ZT Login Server"
  type       = "oidc"

  config {
    client_id     = var.oidc_client_id
    client_secret = var.oidc_client_secret
    auth_url      = "https://${local.auth_domain}/authorize"
    token_url     = "https://${local.auth_domain}/token"
    certs_url     = "https://${local.auth_domain}/.well-known/jwks.json"
    scopes        = ["openid", "email", "profile"]
  }
}

# ==========================================
# 5-1. Cloudflare Access — Admin Tier 보호 (v7 추가, v7.1에서 구조 수정)
#   워커(https://ztna-access-evaluator.xmcda.workers.dev)를 External Evaluation으로 연결.
#   [v7.1 수정] 원래는 재사용 가능한 정책(application_id 미지정) 하나를 admin_console/admin_api
#   두 애플리케이션이 공유하는 구조였으나, 프로바이더가 "precedence를 쓰려면 application_id도
#   반드시 같이 지정해야 한다"는 제약이 있어(Missing required argument 에러 발생) 재사용형 정책이
#   정상 동작하지 않았다. 그래서 애플리케이션마다 내용이 동일한 정책을 각각 별도로 만드는
#   구조로 변경함 (application_id를 명시적으로 지정).
#   require 블록에 넣어야 "이메일 로그인" AND "신뢰점수 통과"가 둘 다 필요한 조건이 된다
#   (include만 쓰면 둘 중 하나만 통과해도 되는 OR 조건이 되어버리므로 주의)
# ==========================================
# ==========================================
# 5-0-1. Cloudflare Access Groups — 이메일을 재사용 가능한 이름표로 묶어둠
#   (개별 정책마다 이메일을 나열하지 않고, 그룹만 참조. 인원 변경 시 여기만 수정하면 됨)
# ==========================================
resource "cloudflare_zero_trust_access_group" "all_employees" {
  account_id = var.cloudflare_account_id
  name       = "전체 직원"
  include {
    email = local.all_employee_emails
  }
}

resource "cloudflare_zero_trust_access_group" "dev_team" {
  account_id = var.cloudflare_account_id
  name       = "개발팀"
  include {
    email = local.dev_team_emails
  }
}

resource "cloudflare_zero_trust_access_group" "marketing_team" {
  account_id = var.cloudflare_account_id
  name       = "마케팅팀"
  include {
    email = local.marketing_team_emails
  }
}

resource "cloudflare_zero_trust_access_group" "hr_team" {
  account_id = var.cloudflare_account_id
  name       = "인사팀"
  include {
    email = local.hr_team_emails
  }
}

resource "cloudflare_zero_trust_access_group" "admins" {
  account_id = var.cloudflare_account_id
  name       = "관리자"
  include {
    email = var.admin_allowed_emails
  }
}

# ==========================================
# 5-2. 포털 홈 + 부서별 애플리케이션 (전체 직원 / 개발팀 / 마케팅팀 / 인사팀)
# ==========================================
resource "cloudflare_zero_trust_access_application" "portal" {
  account_id                = var.cloudflare_account_id
  name                       = "ZT Portal (전사 공통)"
  domain                     = var.domain_name
  type                       = "self_hosted"
  session_duration           = "24h"
  allowed_idps               = [cloudflare_zero_trust_access_identity_provider.login_server.id]
  auto_redirect_to_identity  = true

  # [통일 관리 방식 확장] 로그인 필수 + 세션 위험화 가능성은 다른 페이지와 동일해 risk_block_shared 추가.
  policies = [
    cloudflare_zero_trust_access_policy.risk_block_shared.id,
    cloudflare_zero_trust_access_policy.portal_gate.id,
  ]
}

resource "cloudflare_zero_trust_access_policy" "portal_gate" {
  account_id = var.cloudflare_account_id
  name       = "Portal - All Employees"
  decision   = "allow"
  include {
    group = [cloudflare_zero_trust_access_group.all_employees.id]
  }
}

resource "cloudflare_zero_trust_access_application" "dev" {
  account_id                = var.cloudflare_account_id
  name                       = "ZT Dev Team"
  domain                     = "${var.domain_name}/dev"
  type                       = "self_hosted"
  session_duration           = "24h"
  allowed_idps               = [cloudflare_zero_trust_access_identity_provider.login_server.id]
  auto_redirect_to_identity  = true

  # [통일 관리 방식 재시도] Deny(risk_block_shared)와 Allow(dev_gate) 둘 다 이 리스트 하나로만 관리함(관리 방식 섞음 방지).
  # 리스트 순서 = precedence (먼저 = Deny 먼저 평가)
  policies = [
    cloudflare_zero_trust_access_policy.risk_block_shared.id,
    cloudflare_zero_trust_access_policy.dev_gate.id,
  ]
}

# [통일 관리 방식 재시도] application_id를 빼서 이것도 재사용형 정책으로 전환.
# precedence는 위 dev 앱의 policies 리스트 순서가 결정하며, 여기서 명시하면 중복 지정이 되므로 빼도 됨.
resource "cloudflare_zero_trust_access_policy" "dev_gate" {
  account_id = var.cloudflare_account_id
  name       = "Dev - Dev Team Only"
  decision   = "allow"
  include {
    group = [cloudflare_zero_trust_access_group.dev_team.id]
  }
}

resource "cloudflare_zero_trust_access_application" "marketing" {
  account_id                = var.cloudflare_account_id
  name                       = "ZT Marketing Team"
  domain                     = "${var.domain_name}/marketing"
  type                       = "self_hosted"
  session_duration           = "24h"
  allowed_idps               = [cloudflare_zero_trust_access_identity_provider.login_server.id]
  auto_redirect_to_identity  = true

  policies = [
    cloudflare_zero_trust_access_policy.risk_block_shared.id,
    cloudflare_zero_trust_access_policy.marketing_gate.id,
  ]
}

resource "cloudflare_zero_trust_access_policy" "marketing_gate" {
  account_id = var.cloudflare_account_id
  name       = "Marketing - Marketing Team Only"
  decision   = "allow"
  include {
    group = [cloudflare_zero_trust_access_group.marketing_team.id]
  }
}

resource "cloudflare_zero_trust_access_application" "hr" {
  account_id                = var.cloudflare_account_id
  name                       = "ZT HR Team"
  domain                     = "${var.domain_name}/hr"
  type                       = "self_hosted"
  session_duration           = "24h"
  allowed_idps               = [cloudflare_zero_trust_access_identity_provider.login_server.id]
  auto_redirect_to_identity  = true

  policies = [
    cloudflare_zero_trust_access_policy.risk_block_shared.id,
    cloudflare_zero_trust_access_policy.hr_gate.id,
  ]
}

resource "cloudflare_zero_trust_access_policy" "hr_gate" {
  account_id = var.cloudflare_account_id
  name       = "HR - HR Team Only"
  decision   = "allow"
  include {
    group = [cloudflare_zero_trust_access_group.hr_team.id]
  }
}

resource "cloudflare_zero_trust_access_application" "admin_console" {
  account_id       = var.cloudflare_account_id
  name             = "ZT Admin Console"
  # [실험] 경로 기반(xmcda.store/admin)에서 서브도메인 기반으로 변경.
  # 경로 기반 구조에서는 CF_AppSession이 도메인 전체(xmcda.store)로 공유돼,
  # /dev·/marketing처럼 임계값이 느슨한 형제 앱의 통과 판정이 /admin에도 새어들어와
  # 위험판단이 무력화되는 문제가 있었음(path_cookie_attribute로도 해결 안 됨).
  # 서브도메인은 브라우저 입장에서 완전히 다른 origin이라 이 문제가 구조적으로 발생하지 않음.
  domain           = "admin.${var.domain_name}"
  type             = "self_hosted"
  session_duration = "24h"
  # 이메일 OTP 선택지를 없애고, 이 앱은 우리 로그인서버(TOTP 2단계)로만 로그인 가능하게 제한
  allowed_idps     = [cloudflare_zero_trust_access_identity_provider.login_server.id]
  # 선택지가 하나뿐이니 "로그인 방법 선택" 화면 없이 바로 우리 로그인서버로 리다이렉트
  auto_redirect_to_identity = true
  app_launcher_visible = false

  # [통일 관리 방식] risk_block_shared를 dev/marketing/hr와 동일하게 적용.
  # (path_cookie_attribute는 provider v4에 없어서, 아래 enable_path_cookie_attribute에서
  # Cloudflare API를 직접 호출해 6개 앱 전체에 자동으로 켬 - v5로 프로바이더 업그레이드 없이 처리)
  policies = [
    cloudflare_zero_trust_access_policy.risk_block_shared.id,
    cloudflare_zero_trust_access_policy.admin_gate_console.id,
  ]
}

# [자동화, 6개 앱 전체] provider(v4)가 path_cookie_attribute를 지원하지 않아서,
# Cloudflare REST API를 직접 호출해 이 필드만 켠다. GET으로 현재 설정 전체를 가져온 뒤
# path_cookie_attribute만 덮어써서 그대로 PUT하므로, Terraform이 관리하는 다른 필드
# (policies 등)는 건드리지 않는다. for_each로 6개 앱을 한 번의 apply로 전부 처리.
locals {
  path_cookie_target_apps = {
    portal        = cloudflare_zero_trust_access_application.portal.id
    dev           = cloudflare_zero_trust_access_application.dev.id
    marketing     = cloudflare_zero_trust_access_application.marketing.id
    hr            = cloudflare_zero_trust_access_application.hr.id
    admin_console = cloudflare_zero_trust_access_application.admin_console.id
    admin_api     = cloudflare_zero_trust_access_application.admin_api.id
  }
}

resource "null_resource" "enable_path_cookie_attribute" {
  for_each = local.path_cookie_target_apps

  triggers = {
    app_id = each.value
  }

  provisioner "local-exec" {
    interpreter = ["PowerShell", "-Command"]
    command     = <<-EOT
      $ErrorActionPreference = "Stop"
      $headers = @{
        "Authorization" = "Bearer ${var.cloudflare_api_token}"
        "Content-Type"  = "application/json"
      }
      $url = "https://api.cloudflare.com/client/v4/accounts/${var.cloudflare_account_id}/access/apps/${each.value}"

      $current = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
      if (-not $current.success) {
        Write-Error "[${each.key}] GET 실패: $($current.errors | ConvertTo-Json -Depth 10)"
      }

      $body = $current.result
      # 읽기 전용/응답 전용 필드는 PUT 바디에서 제거 (안 지우면 400 에러 날 수 있음)
      $body.PSObject.Properties.Remove('id')
      $body.PSObject.Properties.Remove('aud')
      $body.PSObject.Properties.Remove('created_at')
      $body.PSObject.Properties.Remove('updated_at')

      $body | Add-Member -NotePropertyName path_cookie_attribute -NotePropertyValue $true -Force

      $json = $body | ConvertTo-Json -Depth 20
      $result = Invoke-RestMethod -Uri $url -Headers $headers -Method Put -Body $json
      if (-not $result.success) {
        Write-Error "[${each.key}] PUT 실패: $($result.errors | ConvertTo-Json -Depth 10)"
      }
      Write-Host "[${each.key}] path_cookie_attribute 설정 완료: $($result.result.path_cookie_attribute)"
    EOT
  }
}

resource "cloudflare_zero_trust_access_policy" "admin_gate_console" {
  account_id = var.cloudflare_account_id
  name       = "Admin Console - Admins Only"
  decision   = "allow"

  include {
    group = [cloudflare_zero_trust_access_group.admins.id]
  }
}

resource "cloudflare_zero_trust_access_policy" "risk_block_shared" {
  account_id = var.cloudflare_account_id
  name       = "Global - Risk Block (External Evaluation)"
  decision   = "deny"

  include {
    external_evaluation {
      evaluate_url = "https://ztna-access-evaluator.xmcda.workers.dev"
      keys_url     = "https://ztna-access-evaluator.xmcda.workers.dev/keys"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "cloudflare_zero_trust_access_application" "admin_api" {
  account_id       = var.cloudflare_account_id
  name             = "ZT Admin API (DynamoDB 감사 로그)"
  # [실험] admin_console과 함께 admin 서브도메인으로 이동.
  # portal_app.py의 /admin 페이지가 fetch('/api/db-data?...')를 상대경로로 호출하므로,
  # /admin만 옮기고 이 API를 기존 도메인에 남겨두면 그 호출이 엉뚱한 곳으로 가서 깨짐.
  domain           = "admin.${var.domain_name}/api/db-data"
  type             = "self_hosted"
  session_duration = "24h"
  allowed_idps     = [cloudflare_zero_trust_access_identity_provider.login_server.id]
  auto_redirect_to_identity = true
  app_launcher_visible = false

  policies = [
    cloudflare_zero_trust_access_policy.risk_block_shared.id,
    cloudflare_zero_trust_access_policy.admin_gate_api.id,
  ]
}

resource "cloudflare_zero_trust_access_policy" "admin_gate_api" {
  account_id = var.cloudflare_account_id
  name       = "Admin API - Admins Only"
  decision   = "allow"

  include {
    group = [cloudflare_zero_trust_access_group.admins.id]
  }
}

# ==========================================
# 5. Cloudflare Tunnel 사전 구성
# ==========================================
resource "random_id" "tunnel_secret" {
  byte_length = 35
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "web_tunnel" {
  account_id = var.cloudflare_account_id
  name       = "zt-web-app-tunnel"
  secret     = random_id.tunnel_secret.b64_std
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "web_tunnel_config" {
  # [변경7] web_server가 이제 /etc/cloudflared/config.yml(로컬 파일)로 직접
  # ingress를 관리하므로, cloudflared는 더 이상 이 원격 설정을 기다리지 않음.
  # 이 리소스는 Cloudflare 대시보드 표시용/백업 목적으로만 유지 (원격 설정 전달
  # 실패로 인한 503 재발 방지가 이번 변경의 핵심).
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.id

  config {
    # auth.xmcda.store는 nginx를 거치지 않고 auth_server로 곧장 연결됨.
    # (nginx가 도메인 구분 없이 모든 경로를 app_server로 넘기던 구조 때문에, 예전엔
    # login.xmcda.store/admin으로 Access 보호를 완전히 우회할 수 있는 구멍이 있었음.
    # auth_server 자체엔 /admin 라우트가 코드에 없어서, 이제 경로가 달라도 원천 차단됨)
    ingress_rule {
      hostname = local.auth_domain
      service  = "http://${aws_instance.auth_server.private_ip}:8080"
    }
    ingress_rule {
      hostname = "admin.${var.domain_name}"
      service  = "http://localhost:80"
    }
    ingress_rule {
      hostname = var.domain_name
      service  = "http://localhost:80"
    }
    ingress_rule {
      service = "http_status:404"
    }
  }
}

resource "cloudflare_record" "auth_dns" {
  zone_id = var.cloudflare_zone_id
  name    = "auth"
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
}

resource "cloudflare_record" "web_app_dns" {
  zone_id = var.cloudflare_zone_id
  name    = var.domain_name
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
}

# [실험] admin_console/admin_api를 서브도메인으로 분리하면서 추가.
# 같은 터널(web_tunnel)을 그대로 쓰고, 실제 경로 분기는 EC2 쪽 cloudflared
# 로컬 config.yml(user_data_web_sh.tpl)의 hostname 규칙이 담당함.
resource "cloudflare_record" "admin_dns" {
  zone_id = var.cloudflare_zone_id
  name    = "admin"
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
}

# ==========================================
# 6. EC2 Web/App 티어 — compute.tf로 분리됨 (3-Tier 전환)
#    기존 단일 EC2(web_app)는 web_server(Web, nginx)와 app_server(App, Flask) 2대로 교체됨.
#    DB 티어(RDS)는 database.tf, VPC/서브넷/SG는 network.tf 참고.
# ==========================================