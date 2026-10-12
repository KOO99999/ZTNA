# ==========================================
# 계정 자동 시딩 (auth 서버가 켜질 때 DB에 없는 계정을 만든다)
#
#  내 PC --[account/put_seed_credentials.py, AWS CLI]--> SSM Parameter Store(SecureString) <--[읽기만]-- auth 서버(IAM 역할)
#
#  - 이 파라미터는 일부러 Terraform이 만들지 않는다(리소스 없음). 매일 terraform destroy를 해도 값이 지워지지 않게 하기 위해서다.
#    처음 한 번 put_seed_credentials.py가 만들고(없으면 생성, 있으면 갱신), 그 뒤로는 destroy/apply와 무관하게 남는다.
#    Terraform은 이름(local.seed_param_name)과 ARN만 알고 읽기 권한만 준다. 값은 tfvars, user_data, state 어디에도 없다.
#  - 저장 형식과 읽는 코드: auth_app.py의 seed_accounts_from_ssm()
#  - 값이 아직 없으면 auth 서버는 [SEED_SKIPPED]를 로그에 남기고 계정 시딩만 건너뛴다(로그인 서버는 정상 시작).
#  - 지우려면 직접: aws ssm delete-parameter --name /zt/auth/seed_credentials
#  - 나중에 "영구 데이터 분리"(user_risk, RDS 등)를 할 때 이 파라미터도 그쪽 Terraform으로 옮기려면 `terraform import`로 가져오면 된다.
# ==========================================
locals {
  seed_param_name = "/zt/auth/seed_credentials"
  seed_param_arn  = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter${local.seed_param_name}"
}

data "aws_caller_identity" "current" {}

# SecureString 기본 암호화 키(AWS 관리형 aws/ssm). 복호화(kms:Decrypt) 권한을 역할 정책에 명시한다.
data "aws_kms_alias" "ssm" {
  name = "alias/aws/ssm"
}

# ==========================================
# auth 서버 전용 EC2 역할: SSM 접속 + 위 파라미터 하나 읽기. 그 외 AWS 권한 없음.
# ==========================================
resource "aws_iam_role" "auth_role" {
  name_prefix = "zt-auth-role-"

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

resource "aws_iam_role_policy_attachment" "auth_ssm" {
  role       = aws_iam_role.auth_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "auth_seed_read" {
  name = "zt-auth-seed-read"
  role = aws_iam_role.auth_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadSeedParameter"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = [local.seed_param_arn]
      },
      {
        Sid      = "DecryptViaSsmOnly"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [data.aws_kms_alias.ssm.target_key_arn]
        Condition = {
          StringEquals = { "kms:ViaService" = "ssm.${var.aws_region}.amazonaws.com" }
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "auth_profile" {
  name_prefix = "zt-auth-profile-"
  role        = aws_iam_role.auth_role.name

  lifecycle {
    create_before_destroy = true
  }
}
