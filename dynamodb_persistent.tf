# ==========================================
# 영속 데이터 테이블 (서버/앱을 다시 만들어도 남겨야 하는 데이터)
#
# user_risk: 사용자별 "누적 위험 상태". 판단 엔진(risk_score_engine.py)이 소유하고 읽으며, 관리자가 risk_admin Lambda로만 해제한다.
#   - identity(파티션 키) + signal(정렬 키)  : 한 사용자에게 신호별로 한 줄. 같은 신호가 다시 걸려도 줄이 늘지 않는다.
#   - status: active(차단에 반영) / released(관리자가 해제, 기록은 남김)
#   - set_at / last_seen / source / released_by / released_at
# mfa_verified(짧게 유지되는 "최근 MFA 통과" 사실)와는 일부러 분리한다 - 합치면 재인증 만료와 함께 위험 상태가 사라질 수 있다.
#
# [나중에 분리하려면] 이 파일의 리소스만 별도 Terraform 구성으로 옮기고 `terraform state mv`로 상태를 이관하면 된다.
#   (risk_score_log / mfa_verified는 아직 main.tf에 있다 - 같은 방식으로 이 파일로 옮길 수 있다)
# ==========================================
resource "aws_dynamodb_table" "user_risk" {
  name         = "user_risk"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "identity"
  range_key    = "signal"

  attribute {
    name = "identity"
    type = "S"
  }

  attribute {
    name = "signal"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Environment = "ZeroTrust-Project"
  }
}
