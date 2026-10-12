# ==========================================
# User Risk 관리 (관리자 콘솔의 목록/해제)
#
#  portal_app.py(app 서버) --[AWS 권한으로 직접 호출]--> Lambda risk_admin --> user_risk 테이블 + 감사 기록
#
#  - API Gateway도 공유 비밀키도 없다(외부에 열린 주소가 없음). 호출 권한은 아래 app_role의 lambda:InvokeFunction 하나뿐이다.
#  - app 서버는 user_risk 테이블에 직접 쓸 권한이 없다. 해제는 반드시 이 함수(관리자 이메일 확인 + 자기 해제 금지 + 감사 기록)를 거친다.
# ==========================================
data "archive_file" "risk_admin_zip" {
  type        = "zip"
  output_path = "${path.module}/risk_admin.zip"
  source_file = "${path.module}/risk_admin.py"
}

resource "aws_iam_role" "risk_admin_role" {
  name_prefix = "risk-admin-lambda-"

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

resource "aws_iam_role_policy_attachment" "risk_admin_basic_execution" {
  role       = aws_iam_role.risk_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# risk_admin이 쓰는 DynamoDB 작업만: user_risk 목록(Scan)/해제(UpdateItem), 해제 기록(risk_score_log PutItem)
resource "aws_iam_role_policy" "risk_admin_dynamodb" {
  name = "zt-risk-admin-dynamodb-minimal"
  role = aws_iam_role.risk_admin_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "UserRiskListAndRelease"
        Effect   = "Allow"
        Action   = ["dynamodb:Scan", "dynamodb:UpdateItem"]
        Resource = [aws_dynamodb_table.user_risk.arn]
      },
      {
        Sid      = "WriteReleaseAudit"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = [aws_dynamodb_table.risk_score_log.arn]
      }
    ]
  })
}

resource "aws_lambda_function" "risk_admin" {
  filename         = data.archive_file.risk_admin_zip.output_path
  function_name    = "risk-admin"
  role             = aws_iam_role.risk_admin_role.arn
  handler          = "risk_admin.lambda_handler"
  runtime          = "python3.12"
  timeout          = 10
  source_code_hash = data.archive_file.risk_admin_zip.output_base64sha256

  environment {
    variables = {
      ADMIN_EMAILS = join(",", [for e in var.admin_allowed_emails : lower(e)])
    }
  }
}

# ==========================================
# app 서버(관리자 콘솔) 전용 EC2 역할
#  - SSM(접속), risk_score_log 읽기(감사 로그 화면), risk_admin 호출. 그 외 AWS 권한 없음.
#  - web/auth 서버는 계속 공용 역할(ec2_role, SSM만)을 쓴다.
# ==========================================
resource "aws_iam_role" "app_role" {
  name_prefix = "zt-app-role-"

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

resource "aws_iam_role_policy_attachment" "app_ssm" {
  role       = aws_iam_role.app_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "app_admin_console" {
  name = "zt-app-admin-console"
  role = aws_iam_role.app_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadAuditLog"
        Effect   = "Allow"
        Action   = ["dynamodb:Scan"]
        Resource = [aws_dynamodb_table.risk_score_log.arn]
      },
      {
        Sid      = "InvokeRiskAdminOnly"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = [aws_lambda_function.risk_admin.arn]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "app_profile" {
  name_prefix = "zt-app-profile-"
  role        = aws_iam_role.app_role.name

  lifecycle {
    create_before_destroy = true
  }
}
