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
# 3. AWS Lambda PDP Engine
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
import uuid
import boto3

dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-2')
table = dynamodb.Table('trust_score_log')

# v6: 5조(남궁영) 외부 분석 반영
#   - RISK_MATRIX를 behavioral(자동회복 허용)/security(MFA 재인증 전까지 회복불가) 그룹으로 분리
#   - device_fingerprint_mismatch 신호 추가 (세션 탈취/단말 변조 방어)
#   - 경계구간(80점 ±2)은 차단 대신 step_up_mfa_required 반환 -> 관리자 수동승인이 아닌
#     PEP(Cloudflare Access) 쪽에서 즉시 MFA 챌린지를 띄우도록 함. 관리자는 SOC_ALERT 로그만 수신
#   - FAIL_POLICY는 참고용 상수: Lambda 자체 장애 시엔 이 함수가 호출조차 안 되므로
#     실제 Fail-Open/Closed 판단은 PEP(Cloudflare Worker) 쪽에서 이 값을 참조해 구현해야 함
RISK_MATRIX = {
    # --- behavioral: 시간 경과로 자동 회복 가능 ---
    "night_access": {"penalty": -10, "group": "behavioral"},
    "unknown_location": {"penalty": -20, "group": "behavioral"},

    # --- security: 자동 회복 불가, security_mfa_passed=True 통과 시에만 리셋 ---
    "brute_force": {"penalty": -15, "group": "security"},
    "threat_intel_match": {"penalty": -40, "group": "security"},
    "waf_sqli": {"penalty": -50, "group": "security"},
    "device_fingerprint_mismatch": {"penalty": -40, "group": "security"},
}

COMBINATION_RULES = [
    (("unknown_location", "waf_sqli"), -15, "interaction_location_waf"),
    (("brute_force", "threat_intel_match"), -10, "interaction_bruteforce_threatintel"),
]

REQUIRED_SCORE = 80          # Admin Tier 임계값 (General Tier는 app.py에서 인증 자체를 요구 안 함)
STEP_UP_MARGIN = 5           # 75~80점 구간을 "경계구간"으로 간주
                              # (감점값이 전부 5의 배수라 마진도 5단위여야 실제로 도달 가능함 - v6.1 수정)

# 장애 시 정책 참고표 (실제 적용은 PEP/Cloudflare Worker에서 이 값을 조회해 구현)
FAIL_POLICY = {
    "general": "fail_open",
    "admin": "fail_closed",
}

def lambda_handler(event, context):
    print("Received event:", json.dumps(event))
    
    body = {}
    if "body" in event and event["body"]:
        try:
            body = json.loads(event["body"])
        except Exception:
            body = {}
    elif isinstance(event, dict):
        body = event

    score = 100
    reasons = []
    active_signals = []
    security_penalty_applied = False
    current_time = int(time.time())

    # 1. 위협 인덱스 감점 계산 (behavioral/security 구분)
    for factor, rule in RISK_MATRIX.items():
        if body.get(factor):
            score += rule["penalty"]
            reasons.append(f"{factor} ({rule['penalty']})")
            active_signals.append(factor)
            if rule["group"] == "security":
                security_penalty_applied = True

    # 2. 조합 규칙 감점
    for signals, penalty, label in COMBINATION_RULES:
        if all(s in active_signals for s in signals):
            score -= abs(penalty)
            reasons.append(f"{label} ({penalty})")

    # 3. History Decay — security 감점이 걸려있고 아직 MFA 재인증 전이면 decay 적용 안 함
    #    (자동 회복 악용/점수 세탁 방지, 5조 지적 반영)
    security_mfa_passed = bool(body.get("security_mfa_passed"))
    if not security_penalty_applied or security_mfa_passed:
        last_activity = body.get("last_activity_timestamp")
        if last_activity:
            try:
                inactivity_hours = int((current_time - int(last_activity)) / 3600)
                if inactivity_hours > 0:
                    decay_penalty = inactivity_hours * 5
                    score -= decay_penalty
                    reasons.append(f"history_decay_{inactivity_hours}h (-{decay_penalty})")
            except Exception as e:
                print("History decay calculation error:", str(e))

    score = max(score, 0)
    session_id = body.get("session_id", str(uuid.uuid4()))

    # 4. 보안 감점이 걸린 세션은 MFA 재인증 전까지 무조건 차단
    if security_penalty_applied and not security_mfa_passed:
        allow_access = False
        action = "block_until_mfa"
    # 5. 경계구간(REQUIRED_SCORE ± STEP_UP_MARGIN)은 즉시 차단 대신 Adaptive MFA 요구
    #    (관리자 수동검토 병목 해소, 5조 지적 반영 — 관리자는 아래 SOC_ALERT로 사후 인지)
    elif REQUIRED_SCORE - STEP_UP_MARGIN <= score < REQUIRED_SCORE:
        allow_access = False
        action = "step_up_mfa_required"
        print(f"[SOC_ALERT] identity={body.get('identity','unknown')} score={score} action={action}")
    else:
        allow_access = (score >= REQUIRED_SCORE)
        action = "allow" if allow_access else "block"

    # DynamoDB 감사가 기록
    try:
        table.put_item(
            Item={
                'session_id': session_id,
                'timestamp': current_time,
                'score': score,
                'reasons': reasons,
                'allow': allow_access,
                'action': action,
                'identity': body.get('identity', 'unknown')
            }
        )
    except Exception as e:
        print("DynamoDB logging failed:", str(e))

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "success": allow_access,
            "allow": allow_access,
            "score": score,
            "action": action,
            "reasons": reasons,
            "session_id": session_id
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
# 4. AWS API Gateway (HTTP API)
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
# 5. EC2 Web Server (Target App)
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
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = "t3.micro"
  availability_zone    = "ap-northeast-2a" # <--- ap-northeast-2a로 고정하여 프리티어 문제 해결
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

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
# 6. Cloudflare Tunnel (도메인 <-> EC2 비공개 연결)
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