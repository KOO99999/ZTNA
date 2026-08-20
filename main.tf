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
# 3. AWS Lambda PDP Engine (History Decay & DynamoDB 저장)
# ==========================================
resource "aws_iam_role" "lambda_role" {
  name_prefix = "trust-score-lambda-"

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
  name           = "Admin Console - Email OTP + Trust Score Gate"
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
  name           = "Admin API - Email OTP + Trust Score Gate"
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
      service  = "http://localhost:8080"
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
# 6. EC2 Web Server (Inactivity 타이머 스크립트 포함 UI)
# ==========================================
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

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
  name_prefix = "zero_trust_web_sg_"
  description = "Security group for ZT Web App"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_instance" "web_app" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = "t3.micro"
  availability_zone    = "ap-northeast-2a"
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  vpc_security_group_ids = [aws_security_group.web_sg.id]

  user_data_replace_on_change = true

  user_data = <<-EOF
              #!/bin/bash
              exec > /var/log/user-data.log 2>&1
              apt-get update -y
              apt-get install -y python3-pip
              pip3 install flask boto3

              cat << 'APP' > /home/ubuntu/app.py
              from flask import Flask, request, jsonify
              import boto3

              app = Flask(__name__)
              dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-2')
              table = dynamodb.Table('trust_score_log')

              def render_page(title, min_score, content_html, is_public=False):
                  user_email = request.headers.get('Cf-Access-Authenticated-User-Email')
                  
                  if is_public and not user_email:
                      user_status_html = "🌐 <strong>접속 상태:</strong> 게스트 (인증 불필요 오픈 서비스)"
                  else:
                      email_str = user_email if user_email else "인증 정보 없음"
                      user_status_html = f"🔑 <strong>인증된 관리자 계정:</strong> {email_str}<br>🛡️ <strong>요구 신뢰점수:</strong> {min_score}점 이상"

                  # Inactivity (무활동) 감지 타이머 스크립트 (15분 = 900초)
                  inactivity_script = """
                  <script>
                      let inactivityTimer;
                      const INACTIVITY_LIMIT = 15 * 60 * 1000; // 15분

                      function resetInactivityTimer() {
                          clearTimeout(inactivityTimer);
                          inactivityTimer = setTimeout(onInactivityTimeout, INACTIVITY_LIMIT);
                      }

                      function onInactivityTimeout() {
                          alert("⚠️ 장시간 사용자 활동이 없어 신뢰 점수가 차감되었습니다.\\n보안을 위해 다시 로그인해 주세요.");
                          window.location.href = "/cdn-cgi/access/logout";
                      }

                      window.onload = resetInactivityTimer;
                      document.onmousemove = resetInactivityTimer;
                      document.onkeypress = resetInactivityTimer;
                      document.onclick = resetInactivityTimer;
                      document.onscroll = resetInactivityTimer;
                  </script>
                  """ if not is_public else ""

                  return f"""
                  <!DOCTYPE html>
                  <html>
                  <head>
                      <meta charset="utf-8">
                      <title>{title}</title>
                      <style>
                          body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background-color: #f4f6f9; color: #333; }}
                          .card {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 650px; margin: 0 auto; }}
                          .badge {{ display: inline-block; padding: 6px 14px; background-color: #007bff; color: white; border-radius: 20px; font-size: 0.85em; font-weight: bold; }}
                          .badge-public {{ background-color: #28a745; }}
                          .user-info {{ background: #e9ecef; padding: 12px 18px; border-radius: 8px; margin-top: 15px; font-size: 0.9em; border-left: 4px solid #007bff; }}
                          button {{ background: #28a745; color: white; border: none; padding: 10px 18px; border-radius: 6px; cursor: pointer; font-size: 0.95em; margin-top: 15px; font-weight: bold; }}
                          button:hover {{ background: #218838; }}
                          pre {{ background: #1e1e1e; color: #4ec9b0; padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 0.9em; }}
                      </style>
                      {inactivity_script}
                  </head>
                  <body>
                      <div class="card">
                          <span class="badge {'badge-public' if is_public else ''}">{'Public Access Area' if is_public else 'Zero Trust Protected Area'}</span>
                          <h2>{title}</h2>
                          <div class="user-info">
                              {user_status_html}
                          </div>
                          <hr style="border: 0.5px solid #eee; margin: 20px 0;">
                          {content_html}
                      </div>
                  </body>
                  </html>
                  """

              @app.route('/')
              @app.route('/general')
              def general():
                  html = """
                  <p>누구나 무료로 이용할 수 있는 오픈 서비스 영역입니다.</p>
                  <ul>
                      <li>인증 절차 없이 즉시 접근 가능</li>
                      <li>서비스 기본 정보 및 공개 게시판 제공</li>
                  </ul>
                  <a href="/admin"><button style="background-color: #dc3545;">관리자 콘솔 바로가기 (이메일 OTP 인증 필요)</button></a>
                  """
                  return render_page("[Public Tier] 일반 대시보드", 0, html, is_public=True)

              @app.route('/admin')
              def admin():
                  html = """
                  <p><strong>⚠️ 관리자 전용 영역입니다. (이메일 OTP 인증 완료됨)</strong></p>
                  <p><small>💡 15분간 아무런 활동이 없으면 신뢰 점수 Decay 정책에 따라 자동 세션 만료 및 재인증이 유도됩니다.</small></p>
                  <button onclick="fetchData('admin_logs')" style="background-color: #dc3545;">DynamoDB 감사 로그 전체 조회</button>
                  <div id="result"></div>
                  <script>
                      function fetchData(datatype) {
                          document.getElementById('result').innerHTML = '<p>DynamoDB 테이블 스캔 중...</p>';
                          fetch('/api/db-data?type=' + datatype)
                              .then(res => res.json())
                              .then(data => {
                                  document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                              });
                      }
                  </script>
                  """
                  return render_page("[Admin Tier] 관리자 콘솔", 80, html, is_public=False)

              @app.route('/api/db-data')
              def get_db_data():
                  data_type = request.args.get('type')
                  user_email = request.headers.get('Cf-Access-Authenticated-User-Email')

                  if not user_email:
                      return jsonify({
                          "status": "Denied",
                          "message": "관리자 이메일 인증 헤더가 누락되어 DB 접근이 거부되었습니다."
                      }), 403

                  try:
                      if data_type == 'admin_logs':
                          response = table.scan(Limit=5)
                          logs = response.get('Items', [])
                          return jsonify({
                              "status": "Success",
                              "identity": user_email,
                              "db_table": "trust_score_log",
                              "fetched_logs_count": len(logs),
                              "logs": logs
                          })
                      else:
                          return jsonify({"status": "Error", "message": "유효하지 않은 데이터 요청입니다."}), 400
                  except Exception as e:
                      return jsonify({"status": "Error", "message": str(e)}), 500

              if __name__ == '__main__':
                  app.run(host='0.0.0.0', port=8080)
              APP

              nohup python3 /home/ubuntu/app.py > /home/ubuntu/app.log 2>&1 &

              curl -L --output /tmp/cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
              dpkg -i /tmp/cloudflared.deb
              cloudflared service install ${cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.tunnel_token}
              systemctl start cloudflared
              EOF

  tags = {
    Name = "ZT-Target-WebApp"
  }

  lifecycle {
    create_before_destroy = true
  }
}