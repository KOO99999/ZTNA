# ==========================================
# [개인별 기준] 사용자별 접속 이력(시드 + 실제) -> night_access / unknown_location을 "그 사람의 평소"와 비교
#
#  login_history: identity(파티션) + ts(정렬, epoch 초)
#    - source=seed : apply 때 seed_loader Lambda가 seed/login_seed.json을 "지난 30일"로 옮겨 넣은 줄
#                    origin=rba(공개 RBA 데이터셋에서 뽑은 실제 사용자 패턴) 또는 synthetic(가정 패턴)
#    - source=real : 엔진이 정문(Access)/로그인 서버 판단을 통과한 실제 접속을 저장한 줄
#    - expires_at(TTL): 31일 뒤 자동 삭제(30일 창만 쓰므로)
#  엔진은 이 표를 사람별 Query(최근 30일)만 하고, 시드 적재 함수는 이 표에만 쓸 수 있다.
# ==========================================
resource "aws_dynamodb_table" "login_history" {
  name         = "login_history"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "identity"
  range_key    = "ts"

  attribute {
    name = "identity"
    type = "S"
  }

  attribute {
    name = "ts"
    type = "N"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = {
    Environment = "ZeroTrust-Project"
  }
}

# 판단 엔진: 이력 조회(Query) + 통과한 실제 접속 저장(PutItem)만
resource "aws_iam_role_policy" "lambda_login_history" {
  name = "zt-lambda-login-history"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "BaselineHistoryReadWrite"
      Effect   = "Allow"
      Action   = ["dynamodb:Query", "dynamodb:PutItem"]
      Resource = [aws_dynamodb_table.login_history.arn]
    }]
  })
}

# ---------- 시드 적재 함수(apply 때 한 번 실행) ----------
# 계정 이름(시드 파일의 칸) -> 실제 이메일. 관리자 이메일은 tfvars에만 있으므로 여기서 넘긴다(저장소의 시드 파일에는 이메일 없음).
# 비상 관리자(두 번째 관리자)는 평소 쓰지 않는 계정이라 시드를 넣지 않는다(이력 없음 -> 공통 규칙, 쓰면 바로 눈에 띔).
locals {
  seed_accounts = merge(
    { for e in concat(local.dev_team_emails, local.marketing_team_emails, local.hr_team_emails) : split("@", e)[0] => lower(e) },
    { admin = lower(var.admin_allowed_emails[0]) }
  )
  seed_file = "${path.module}/seed/login_seed.json"
}

data "archive_file" "seed_loader_zip" {
  type        = "zip"
  output_path = "${path.module}/seed_loader.zip"
  source {
    content  = file("${path.module}/seed_loader.py")
    filename = "seed_loader.py"
  }
  source {
    content  = file(local.seed_file)
    filename = "login_seed.json"
  }
}

resource "aws_iam_role" "seed_loader_role" {
  name_prefix = "zt-seed-loader-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "seed_loader_logs" {
  role       = aws_iam_role.seed_loader_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# 시드 적재 함수: login_history에 쓰기/지우기(기존 시드 교체)와 계정별 조회만
resource "aws_iam_role_policy" "seed_loader_dynamodb" {
  name = "zt-seed-loader-dynamodb"
  role = aws_iam_role.seed_loader_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "SeedHistoryWrite"
      Effect   = "Allow"
      Action   = ["dynamodb:Query", "dynamodb:BatchWriteItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
      Resource = [aws_dynamodb_table.login_history.arn]
    }]
  })
}

resource "aws_lambda_function" "seed_loader" {
  filename         = data.archive_file.seed_loader_zip.output_path
  function_name    = "zt-seed-loader"
  role             = aws_iam_role.seed_loader_role.arn
  handler          = "seed_loader.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.seed_loader_zip.output_base64sha256
  timeout          = 60

  environment {
    variables = {
      HISTORY_TABLE = aws_dynamodb_table.login_history.name
    }
  }

  depends_on = [aws_iam_role_policy_attachment.seed_loader_logs, aws_iam_role_policy.seed_loader_dynamodb]
}

# apply 때 한 번 호출. 시드 파일/계정 목록/테이블이 바뀌면 다시 호출된다(기존 시드 줄은 지우고 다시 넣음).
resource "aws_lambda_invocation" "seed_load" {
  function_name = aws_lambda_function.seed_loader.function_name
  input = jsonencode({
    accounts  = local.seed_accounts
    seed_hash = filesha256(local.seed_file)
  })
  triggers = {
    table_arn = aws_dynamodb_table.login_history.arn
    code_hash = data.archive_file.seed_loader_zip.output_base64sha256
    seed_hash = filesha256(local.seed_file)
    accounts  = sha256(jsonencode(local.seed_accounts))
  }
}
