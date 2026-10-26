# ==========================================
# 기기 순찰(device sweep): 세션 도중 기기 상태 변화를 잡아 세션을 끊는다
#
#  왜: Access는 세션을 새로 줄 때만 기기 정보를 넘긴다(get-identity도 로그인 시점 값 - 실측 확인).
#      세션 중 상태를 실시간으로 받는 Logpush는 Enterprise 기능이라, 엔진이 1분마다 Cloudflare 기기 상태 API
#      (DEX Fleet Status, 실측 약 2분 단위 갱신)를 조회하고, 정상 -> 나쁨으로 바뀐 기기 사용자의 Access 세션을 끊는다.
#      다시 들어오면 Access -> External Evaluation -> 엔진이 최신 상태로 판단한다(판단은 엔진 한 곳).
#  왜 별도 함수인가: 세션 끊기 토큰(쓰기 권한)을 인터넷에 열린 판단 함수(API Gateway)에 두지 않기 위해서다.
#      코드는 같은 risk_score_engine.py(판단 규칙 한 곳)이고 진입점만 다르다(device_sweep_handler).
#  사람이 할 일: Cloudflare에서 "Access: Organizations, Identity Providers, and Groups - Edit" 권한만 가진
#      토큰을 만들어 terraform.tfvars의 cloudflare_access_revoke_token에 넣는다(비워 두면 끊기만 건너뜀).
# ==========================================

# 기기별 최신 순찰 결과(정상/나쁨, 사유, 끊었는지). 하루 지나면 TTL로 정리.
resource "aws_dynamodb_table" "device_state" {
  name         = "device_state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "device_id"

  attribute {
    name = "device_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = {
    Environment = "ZeroTrust-Project"
  }
}

# 판단 함수(risk-score-engine)는 순찰 결과를 읽기만 한다.
resource "aws_iam_role_policy" "lambda_device_state_read" {
  name = "zt-lambda-device-state-read"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadDeviceState"
      Effect   = "Allow"
      Action   = ["dynamodb:GetItem"]
      Resource = [aws_dynamodb_table.device_state.arn]
    }]
  })
}

# 순찰 함수 전용 역할: 순찰 결과 읽기/쓰기 + 판정 로그 쓰기 + 실행 로그만
resource "aws_iam_role" "device_sweep_role" {
  name_prefix = "zt-device-sweep-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "device_sweep_logs" {
  role       = aws_iam_role.device_sweep_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "device_sweep_dynamodb" {
  name = "zt-device-sweep-dynamodb"
  role = aws_iam_role.device_sweep_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DeviceStateReadWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem"]
        Resource = [aws_dynamodb_table.device_state.arn]
      },
      {
        Sid      = "WriteRiskLog"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = [aws_dynamodb_table.risk_score_log.arn]
      }
    ]
  })
}

resource "aws_lambda_function" "device_sweep" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "zt-device-sweep"
  role             = aws_iam_role.device_sweep_role.arn
  handler          = "risk_score_engine.device_sweep_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  # 기기마다 API를 한 번씩 부르므로 판단 함수(기본 3초)보다 길게. 1분 일정보다 짧아야 겹치지 않는다.
  timeout = 50

  environment {
    variables = {
      CF_ACCOUNT_ID          = var.cloudflare_account_id
      CF_DEVICE_API_TOKEN    = var.cloudflare_device_read_token
      CF_ACCESS_REVOKE_TOKEN = var.cloudflare_access_revoke_token
      DEVICE_SIGNAL_MODE     = var.device_signal_mode
      DOMAIN_NAME            = var.domain_name
    }
  }

  depends_on = [aws_iam_role_policy_attachment.device_sweep_logs, aws_iam_role_policy.device_sweep_dynamodb]
}

# 1분마다 순찰(EventBridge 일정의 최소 단위). 반영 지연 = 기기 보고(실측 약 2분) + 순찰 간격(최대 1분) + 세션 끊기 전파.
resource "aws_cloudwatch_event_rule" "device_sweep" {
  name                = "zt-device-sweep-every-minute"
  schedule_expression = "rate(1 minute)"
}

resource "aws_cloudwatch_event_target" "device_sweep" {
  rule = aws_cloudwatch_event_rule.device_sweep.name
  arn  = aws_lambda_function.device_sweep.arn
}

resource "aws_lambda_permission" "device_sweep_events" {
  statement_id  = "AllowEventBridgeDeviceSweep"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.device_sweep.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.device_sweep.arn
}
