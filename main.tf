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

resource "aws_lambda_function" "pdp_engine" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "risk-score-engine"
  role             = aws_iam_role.lambda_role.arn
  handler          = "risk_score_engine.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
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
resource "cloudflare_zero_trust_access_application" "admin_console" {
  account_id       = var.cloudflare_account_id
  name             = "ZT Admin Console"
  domain           = "${var.domain_name}/admin"
  type             = "self_hosted"
  session_duration = "24h"
}

resource "cloudflare_zero_trust_access_policy" "admin_gate_console" {
  application_id = cloudflare_zero_trust_access_application.admin_console.id
  account_id     = var.cloudflare_account_id
  name           = "Admin Console - Email OTP + Risk Score Gate"
  decision       = "allow"
  precedence     = 1

  include {
    email = var.admin_allowed_emails
  }

  require {
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
}

resource "cloudflare_zero_trust_access_policy" "admin_gate_api" {
  application_id = cloudflare_zero_trust_access_application.admin_api.id
  account_id     = var.cloudflare_account_id
  name           = "Admin API - Email OTP + Risk Score Gate"
  decision       = "allow"
  precedence     = 1

  include {
    email = var.admin_allowed_emails
  }

  require {
    external_evaluation {
      evaluate_url = "https://ztna-access-evaluator.xmcda.workers.dev"
      keys_url     = "https://ztna-access-evaluator.xmcda.workers.dev/keys"
    }
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
    ingress_rule {
      hostname = var.domain_name
      service  = "http://localhost:80"
    }
    ingress_rule {
      service = "http_status:404"
    }
  }
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