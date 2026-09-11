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
    scopes        = ["openid", "email"]
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
}

resource "cloudflare_zero_trust_access_policy" "portal_gate" {
  application_id = cloudflare_zero_trust_access_application.portal.id
  account_id     = var.cloudflare_account_id
  name           = "Portal - All Employees"
  decision       = "allow"
  precedence     = 1
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
}

resource "cloudflare_zero_trust_access_policy" "dev_gate" {
  application_id = cloudflare_zero_trust_access_application.dev.id
  account_id     = var.cloudflare_account_id
  name           = "Dev - Dev Team Only"
  decision       = "allow"
  precedence     = 1
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
}

resource "cloudflare_zero_trust_access_policy" "marketing_gate" {
  application_id = cloudflare_zero_trust_access_application.marketing.id
  account_id     = var.cloudflare_account_id
  name           = "Marketing - Marketing Team Only"
  decision       = "allow"
  precedence     = 1
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
}

resource "cloudflare_zero_trust_access_policy" "hr_gate" {
  application_id = cloudflare_zero_trust_access_application.hr.id
  account_id     = var.cloudflare_account_id
  name           = "HR - HR Team Only"
  decision       = "allow"
  precedence     = 1
  include {
    group = [cloudflare_zero_trust_access_group.hr_team.id]
  }
}

resource "cloudflare_zero_trust_access_application" "admin_console" {
  account_id       = var.cloudflare_account_id
  name             = "ZT Admin Console"
  domain           = "${var.domain_name}/admin"
  type             = "self_hosted"
  session_duration = "24h"
  # 이메일 OTP 선택지를 없애고, 이 앱은 우리 로그인서버(TOTP 2단계)로만 로그인 가능하게 제한
  allowed_idps     = [cloudflare_zero_trust_access_identity_provider.login_server.id]
  # 선택지가 하나뿐이니 "로그인 방법 선택" 화면 없이 바로 우리 로그인서버로 리다이렉트
  auto_redirect_to_identity = true
}

resource "cloudflare_zero_trust_access_policy" "admin_gate_console" {
  application_id = cloudflare_zero_trust_access_application.admin_console.id
  account_id     = var.cloudflare_account_id
  name           = "Admin Console - Admins Only"
  decision       = "allow"
  precedence     = 1

  include {
    group = [cloudflare_zero_trust_access_group.admins.id]
  }
  # External Evaluation(위험점수 게이트)은 Cloudflare Access의 Require 위치에서
  # 원인불명 오류로 항상 거부되는 현상이 확인되어 제거함. 위험점수 재확인은
  # app.py의 /admin 라우트가 로그인 시점/재접속 시 직접 담당하도록 이관.
}

# [v8, 방향 A] Require 대신 별도의 Deny 정책으로 External Evaluation 재시도.
# (Cloudflare Terraform Provider의 decision 값은 allow/deny/non_identity/bypass만
# 허용되며 "block"은 유효하지 않아 "deny"로 수정함 — Cloudflare 대시보드 UI 상의
# "Block" 액션과 동일한 의미)
# Access 자체 세션 캐싱(session_duration=24h) 때문에 로그인 이후 재접근 시
# evaluate_login_risk()가 아예 호출 안 되는 문제(/dev 등에서 실증됨)가, 이 Deny
# 정책까지는 캐싱과 무관하게 매번 재평가되는지 확인하기 위한 시도.
# index.js도 이 정책에 맞춰 판단을 뒤집어둠(위험할 때 success:true).
# 효과 없으면 이 정책은 제거하고 portal_app.py의 각 라우트/before_request에서
# 직접 Lambda를 호출하는 방향(B)으로 전환.
resource "cloudflare_zero_trust_access_policy" "admin_risk_block" {
  application_id = cloudflare_zero_trust_access_application.admin_console.id
  account_id     = var.cloudflare_account_id
  name           = "Admin Console - Risk Block"
  decision       = "deny"
  precedence     = 2

  include {
    external_evaluation {
      evaluate_url = "https://ztna-access-evaluator.xmcda.workers.dev"
      keys_url     = "https://ztna-access-evaluator.xmcda.workers.dev/keys"
    }
  }
}

resource "cloudflare_zero_trust_access_application" "admin_api" {
  account_id       = var.cloudflare_account_id
  name             = "ZT Admin API (DynamoDB 감사 로그)"
  domain           = "${var.domain_name}/api/db-data"
  type             = "self_hosted"
  session_duration = "24h"
  allowed_idps     = [cloudflare_zero_trust_access_identity_provider.login_server.id]
  auto_redirect_to_identity = true
}

resource "cloudflare_zero_trust_access_policy" "admin_gate_api" {
  application_id = cloudflare_zero_trust_access_application.admin_api.id
  account_id     = var.cloudflare_account_id
  name           = "Admin API - Admins Only"
  decision       = "allow"
  precedence     = 1

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

# ==========================================
# 6. EC2 Web/App 티어 — compute.tf로 분리됨 (3-Tier 전환)
#    기존 단일 EC2(web_app)는 web_server(Web, nginx)와 app_server(App, Flask) 2대로 교체됨.
#    DB 티어(RDS)는 database.tf, VPC/서브넷/SG는 network.tf 참고.
# ==========================================