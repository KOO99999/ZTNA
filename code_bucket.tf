# ==========================================
# 앱 코드 배포용 S3 버킷 (로그인 서버 코드, 웹 서버 판단 서비스 코드)
#
#  왜: 예전에는 auth_app.py를 user_data 안에 통째로 넣었다. EC2 user_data는 16KB 한도가 있고(AWS EC2 User Guide,
#      "User data is limited to 16 KB"), 압축해도 한도에 거의 닿아 기능을 더 넣을 수 없게 됐다.
#      실무에서는 user_data를 "받아서 설치하는 짧은 스크립트"로 두고, 코드(아티팩트)는 S3 같은 저장소에 올린 뒤
#      서버가 자기 IAM 역할로 내려받는 방식이 일반적이다. 이렇게 하면 user_data 크기가 코드 크기와 무관해지고,
#      코드가 EC2 콘솔의 user_data 화면에 그대로 보이지도 않는다.
#  보안: 공개 접근 전부 차단, 기본 암호화(SSE-S3), HTTPS가 아닌 요청 거부, 로그인 서버 역할은 자기 코드 파일만 읽기.
#  코드가 바뀌면: 파일 해시(md5)를 user_data에 넣어 두었으므로 user_data가 바뀌고, 서버가 새로 만들어진다
#                (user_data_replace_on_change = true, 예전과 같은 동작).
# ==========================================
# 버킷 이름은 계정 ID + 리전으로 정한다(전 세계에서 겹치지 않음). 무작위 값을 쓰면 처음 apply 때 이름이 "아직 모름"이 되고,
# 그 이름이 들어가는 인증 서버 user_data도 계획 단계에서 모르는 값이 되어 AWS provider가
# "Provider produced inconsistent final plan" 오류를 낸다(계획은 수정, 실행 중에는 교체로 바뀜).
# 계획 단계에서 알 수 있는 값만 user_data에 넣으면 이 오류가 생기지 않는다.
locals {
  code_bucket_name = "zt-app-code-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
}

resource "aws_s3_bucket" "app_code" {
  bucket = local.code_bucket_name
  # 매일 destroy/apply 하므로 안에 파일이 있어도 지울 수 있게 한다(코드는 Git에 있으므로 버킷은 언제든 다시 만들 수 있음).
  force_destroy = true

  tags = {
    Environment = "ZeroTrust-Project"
  }
}

resource "aws_s3_bucket_public_access_block" "app_code" {
  bucket                  = aws_s3_bucket.app_code.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app_code" {
  bucket = aws_s3_bucket.app_code.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# HTTPS가 아닌 요청은 거부(AWS S3 보안 모범 사례: aws:SecureTransport 조건)
resource "aws_s3_bucket_policy" "app_code_tls_only" {
  bucket = aws_s3_bucket.app_code.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.app_code.arn, "${aws_s3_bucket.app_code.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.app_code]
}

locals {
  # 로그인 서버가 내려받는 코드 파일(S3 키 -> 로컬 파일)
  auth_code_files = {
    "auth/auth_app.py" = "${path.module}/auth_app.py"
    "auth/zt_mtls.py"  = "${path.module}/zt_mtls.py"
  }
  # 웹 서버(판단 서비스)가 내려받는 코드 파일
  web_code_files = {
    "web/auth_gate.py" = "${path.module}/auth_gate.py"
    "web/zt_jwt.py"    = "${path.module}/zt_jwt.py"
    "web/zt_risk.py"   = "${path.module}/zt_risk.py"
    "web/zt_waf.py"    = "${path.module}/zt_waf.py"
  }
}

resource "aws_s3_object" "auth_code" {
  for_each = local.auth_code_files
  bucket   = aws_s3_bucket.app_code.id
  key      = each.key
  source   = each.value
  etag     = filemd5(each.value)

  depends_on = [aws_s3_bucket_server_side_encryption_configuration.app_code]
}

# 로그인 서버 역할: 자기 코드 파일만 읽기(버킷 목록 보기, 쓰기, 다른 파일 읽기 없음)
resource "aws_iam_role_policy" "auth_code_read" {
  name = "zt-auth-code-read"
  role = aws_iam_role.auth_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadOwnCode"
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = [for o in aws_s3_object.auth_code : "${aws_s3_bucket.app_code.arn}/${o.key}"]
    }]
  })
}

resource "aws_s3_object" "web_code" {
  for_each = local.web_code_files
  bucket   = aws_s3_bucket.app_code.id
  key      = each.key
  source   = each.value
  etag     = filemd5(each.value)

  depends_on = [aws_s3_bucket_server_side_encryption_configuration.app_code]
}

# 웹 서버 역할: 자기 코드 파일만 읽기(버킷 목록 보기, 쓰기, 다른 파일 읽기 없음)
resource "aws_iam_role_policy" "web_code_read" {
  name = "zt-web-code-read"
  role = aws_iam_role.ec2_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadOwnCode"
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = [for o in aws_s3_object.web_code : "${aws_s3_bucket.app_code.arn}/${o.key}"]
    }]
  })
}
