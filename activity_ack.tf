# ==========================================
# [내 보안 기록 - 본인 확인] 직원이 '확인이 필요한 활동'에 남긴 확인(본인 맞음 / 본인 아님)
#
#  activity_ack: identity(파티션) + ts(정렬, 확인한 활동의 시각)
#    - verdict: mine(본인 맞음 -> 홈 경고 닫기) / not_mine(본인 아님 -> 관제 신고, Discord 알림)
#    - 서버에 저장하는 이유: 브라우저(쿠키)에 두면 다른 기기나 InPrivate 창에서는 경고가 다시 뜬다(Google 계정 보안 알림도 계정 기준).
#    - expires_at(TTL): 경고를 띄우는 기간(7일)보다 하루 길게 보관 후 자동 삭제
#  포털(app 서버)은 이 표만 조회/저장할 수 있다. 본인 기록만 다루는 것은 portal_app.py가 지킨다(키 = 로그인 토큰의 이메일).
# ==========================================
resource "aws_dynamodb_table" "activity_ack" {
  name         = "activity_ack"
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

resource "aws_iam_role_policy" "app_activity_ack" {
  name = "zt-app-activity-ack"
  role = aws_iam_role.app_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "MyActivityAck"
      Effect   = "Allow"
      Action   = ["dynamodb:Query", "dynamodb:PutItem"]
      Resource = [aws_dynamodb_table.activity_ack.arn]
    }]
  })
}
