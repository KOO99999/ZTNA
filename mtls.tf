# ==========================================
# Web -> WAS 구간 mTLS(상호 TLS): 프로젝트 전용 내부 CA와 인증서
#
#  웹 서버(nginx) --[클라이언트 인증서 web.zt.internal]--> 앱 서버(app.zt.internal:8080), 인증 서버(auth.zt.internal:8080)
#   - 양쪽 모두 같은 내부 CA가 발급한 인증서로 서로를 확인한다(서버는 클라이언트 인증서 필수, nginx는 서버 인증서 검증).
#   - 예전엔 평문 HTTP였고, 앱 서버는 보안그룹(보낸 쪽 IP)만으로 웹 서버를 믿었다.
#  인증서 이름은 실제 DNS가 아니라 이 구간에서만 쓰는 내부 이름이다(nginx proxy_ssl_name으로 확인할 이름을 지정).
#  사설 IP를 인증서에 넣지 않는 이유: 서버가 만들어진 뒤에야 IP가 정해져서, 인증서와 서버가 서로를 기다리는 순환이 생김.
#
#  전달: 인증서/개인키는 SSM Parameter Store(개인키는 SecureString)에 두고, 각 서버가 부팅 때 자기 IAM 역할로 자기 것만 읽는다.
#   user_data에 넣지 않는 이유: user_data는 16KB 한도가 있고(auth 서버가 이미 한도에 가까움) EC2 콘솔에서 내용을 볼 수 있다.
#  한계(보고서에 그대로 적을 것): 개인키는 Terraform state에도 남는다(state 파일은 비밀번호와 같은 수준으로 보관해야 함).
#   운영 환경이라면 AWS Private CA 같은 관리형 CA로 서버가 직접 발급받게 해 state에 키가 남지 않게 한다.
#  유효기간: 매일 destroy/apply로 새로 만들어지므로 30일로 짧게 둔다.
# ==========================================
locals {
  mtls_validity_hours = 720
  mtls_param_prefix   = "/zt/mtls"
  mtls_names = {
    app  = "app.zt.internal"
    auth = "auth.zt.internal"
    web  = "web.zt.internal"
  }
}

# --- 내부 CA ---
resource "tls_private_key" "zt_ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "zt_ca" {
  private_key_pem       = tls_private_key.zt_ca.private_key_pem
  is_ca_certificate     = true
  validity_period_hours = local.mtls_validity_hours
  # RFC 5280 식별자(SKI/AKI). 엄격하게 검증하는 클라이언트(예: Python 3.13 기본 설정)는 이 값이 없으면 인증서를 거부한다.
  set_subject_key_id   = true
  set_authority_key_id = true
  allowed_uses          = ["cert_signing", "crl_signing", "digital_signature"]

  subject {
    common_name  = "ZT Internal CA"
    organization = "ZT Project"
  }
}

# --- 서버 인증서(앱, 인증) + 클라이언트 인증서(웹) ---
resource "tls_private_key" "mtls" {
  for_each    = local.mtls_names
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "mtls" {
  for_each        = local.mtls_names
  private_key_pem = tls_private_key.mtls[each.key].private_key_pem
  dns_names       = [each.value]

  subject {
    common_name  = each.value
    organization = "ZT Project"
  }
}

resource "tls_locally_signed_cert" "mtls" {
  for_each              = local.mtls_names
  cert_request_pem      = tls_cert_request.mtls[each.key].cert_request_pem
  ca_private_key_pem    = tls_private_key.zt_ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.zt_ca.cert_pem
  validity_period_hours = local.mtls_validity_hours
  # SKI를 넣고, AKI(발급 CA의 SKI)는 CA에 SKI가 있으면 자동으로 들어간다.
  set_subject_key_id = true
  # 웹 서버 인증서는 "클라이언트로 접속하는 용도", 앱/인증 서버 인증서는 "서버 용도"로만 쓸 수 있게 용도를 나눈다.
  allowed_uses = each.key == "web" ? ["digital_signature", "client_auth"] : ["digital_signature", "server_auth"]
}

# --- SSM Parameter Store ---
resource "aws_ssm_parameter" "mtls_ca_cert" {
  name  = "${local.mtls_param_prefix}/ca_cert"
  type  = "String"
  value = tls_self_signed_cert.zt_ca.cert_pem
}

resource "aws_ssm_parameter" "mtls_cert" {
  for_each = local.mtls_names
  name     = "${local.mtls_param_prefix}/${each.key}_cert"
  type     = "String"
  value    = tls_locally_signed_cert.mtls[each.key].cert_pem
}

resource "aws_ssm_parameter" "mtls_key" {
  for_each = local.mtls_names
  name     = "${local.mtls_param_prefix}/${each.key}_key"
  type     = "SecureString"
  value    = tls_private_key.mtls[each.key].private_key_pem
}

# --- 각 서버 역할: 자기 인증서/키 + CA 인증서만 읽기 ---
locals {
  mtls_role_ids = {
    app  = aws_iam_role.app_role.id
    auth = aws_iam_role.auth_role.id
    web  = aws_iam_role.ec2_role.id
  }
}

resource "aws_iam_role_policy" "mtls_read" {
  for_each = local.mtls_role_ids
  name     = "zt-mtls-read-${each.key}"
  role     = each.value

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOwnMtlsMaterial"
        Effect = "Allow"
        Action = ["ssm:GetParameter"]
        Resource = [
          aws_ssm_parameter.mtls_ca_cert.arn,
          aws_ssm_parameter.mtls_cert[each.key].arn,
          aws_ssm_parameter.mtls_key[each.key].arn,
        ]
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
