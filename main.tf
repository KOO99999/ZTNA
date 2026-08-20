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
# 1. AWS DynamoDB (Trust Score & Audit Log)
# ==========================================
resource "aws_dynamodb_table" "trust_score_log" {
  name         = "trust_score_log"
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
# 2. AWS Lambda PDP Engine
# ==========================================
resource "aws_iam_role" "lambda_role" {
  name = "trust_score_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
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
  source {
    content  = <<EOF
import json
import time

RISK_MATRIX = {
    "night_access": -10,
    "unknown_location": -20,
    "brute_force": -15,
    "threat_intel_match": -40,
    "waf_sqli": -50
}

def lambda_handler(event, context):
    try:
        body = json.loads(event.get('body', '{}'))
    except Exception:
        body = {}

    score = 100
    reasons = []

    for factor, penalty in RISK_MATRIX.items():
        if body.get(factor):
            score += penalty
            reasons.append(f"{factor} ({penalty})")

    # Interaction Rule (조합 규칙)
    if body.get("unknown_location") and body.get("waf_sqli"):
        score -= 15
        reasons.append("interaction_location_waf (-15)")

    score = max(score, 0)
    
    # Cloudflare External Evaluation 규격 호환 (Trust >= 80)
    allow_access = (score >= 80)

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "success": allow_access,
            "score": score,
            "reasons": reasons
        })
    }
EOF
    filename = "trust_score_engine.py"
  }
}

resource "aws_lambda_function" "pdp_engine" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "trust-score-engine"
  role             = aws_iam_role.lambda_role.arn
  handler          = "trust_score_engine.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
}

# ==========================================
# 3. AWS API Gateway (HTTP API)
# ==========================================
resource "aws_apigatewayv2_api" "pdp_api" {
  name          = "trust-score-pdp-api"
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
# 4. EC2 Web Server (Target App)
# ==========================================
# 서울 리전 최신 Ubuntu 22.04 LTS AMI 동적 조회
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical (Ubuntu 공식 소유자 ID)

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "web_sg" {
  name        = "zero_trust_web_sg"
  description = "Security group for ZT Web App (Outbound only for Cloudflare Tunnel)"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web_app" {
  ami               = data.aws_ami.ubuntu.id
  instance_type     = "t3.micro"
  availability_zone = "ap-northeast-2a" # <--- ap-northeast-2a로 고정하여 프리티어 문제 해결

  vpc_security_group_ids = [aws_security_group.web_sg.id]

  user_data = <<-EOF
              #!/bin/bash
              apt update -y
              apt install -y python3-pip
              pip3 install flask
              cat << 'APP' > /home/ubuntu/app.py
              from flask import Flask
              app = Flask(__name__)

              @app.route('/general')
              def general():
                  return "<h1>[General Tier] Access Granted (Threshold: 50)</h1>"

              @app.route('/profile')
              def profile():
                  return "<h1>[Profile Tier] Access Granted (Threshold: 70)</h1>"

              @app.route('/admin')
              def admin():
                  return "<h1>[Admin Tier] Access Granted (Threshold: 80)</h1>"

              if __name__ == '__main__':
                  app.run(host='0.0.0.0', port=8080)
              APP
              nohup python3 /home/ubuntu/app.py > /home/ubuntu/app.log 2>&1 &

              # --- Cloudflare Tunnel (cloudflared) 설치 및 실행 ---
              # 인바운드 포트를 열지 않고, EC2가 Cloudflare로 아웃바운드 연결만 맺어 터널을 만듦
              curl -L --output /tmp/cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
              dpkg -i /tmp/cloudflared.deb
              cloudflared service install ${cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.tunnel_token}
              EOF

  tags = {
    Name = "ZT-Target-WebApp"
  }
}

# ==========================================
# 5. Cloudflare Tunnel (도메인 <-> EC2 비공개 연결)
# ==========================================
# 터널 인증용 시크릿 (EC2와 Cloudflare Edge 간 연결에 사용)
resource "random_id" "tunnel_secret" {
  byte_length = 35
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "web_tunnel" {
  account_id = var.cloudflare_account_id
  name       = "zt-web-app-tunnel"
  secret     = random_id.tunnel_secret.b64_std
}

# 터널이 도메인 요청을 받았을 때, EC2 내부의 어느 포트로 보낼지 정의
resource "cloudflare_zero_trust_tunnel_cloudflared_config" "web_tunnel_config" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.id

  config {
    ingress_rule {
      hostname = var.domain_name
      service  = "http://localhost:8080"
    }
    # 위 hostname에 해당 안 되는 나머지 요청은 전부 404 처리 (필수 catch-all)
    ingress_rule {
      service = "http_status:404"
    }
  }
}

# 도메인(xmcda.store)을 터널로 연결하는 DNS 레코드 (public IP 없이 CNAME으로 연결됨)
resource "cloudflare_record" "web_app_dns" {
  zone_id = var.cloudflare_zone_id
  name    = var.domain_name
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1 # proxied=true일 때는 자동(TTL 무시됨)
}