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
    # Web->WAS mTLS용 내부 CA/인증서 발급(mtls.tf)
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
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
# 0-1. 부서별 이메일 목록 + 로그인서버 서브도메인
#   (2026-09: 로그인서버를 login.xmcda.store로 분리 - Access가 xmcda.store를 통째로
#   지켜도 로그인서버 자신은 보호 대상 밖에 있어 "자기 자신을 지키는 문제"가 원천 차단됨)
# ==========================================
locals {
  auth_domain = "auth.${var.domain_name}"

  # [서브도메인 분리] 보호 대상 앱 5개의 주소. 예전엔 dev/marketing/hr를 xmcda.store/dev 같은 경로로
  # 나눴는데, 같은 호스트의 경로 앱들은 (1) 로그인 순간 Access가 한꺼번에 평가하고(실측: /dev 하나만
  # 들어가도 /, /marketing, /hr까지 같은 1초 안에 평가됨) (2) Cloudflare 로그아웃 주소
  # (/cdn-cgi/access/logout)가 호스트 바로 아래에서만 동작해 /dev/cdn-cgi/... 는 로그아웃이 안 됐다
  # (실측: 404/302). 앱마다 호스트를 따로 두면 쿠키·평가·로그아웃이 앱 단위로 자연스럽게 나뉜다.
  # 이 표 하나에서 Access 앱 도메인, DNS, 터널, 로그인 서버(복귀 주소 허용/로그아웃 목록)가 모두 나온다.
  app_hosts = {
    portal    = var.domain_name
    dev       = "dev.${var.domain_name}"
    marketing = "marketing.${var.domain_name}"
    hr        = "hr.${var.domain_name}"
    admin     = "admin.${var.domain_name}"
  }
  app_hosts_env = join(",", [for k in ["portal", "dev", "marketing", "hr", "admin"] : local.app_hosts[k]])

  dev_team_emails       = ["employee01@xmcda.store", "employee02@xmcda.store", "employee03@xmcda.store", "employee04@xmcda.store"]
  marketing_team_emails = ["employee05@xmcda.store", "employee06@xmcda.store", "employee07@xmcda.store"]
  hr_team_emails        = ["employee08@xmcda.store", "employee09@xmcda.store"]
  all_employee_emails   = concat(local.dev_team_emails, local.marketing_team_emails, local.hr_team_emails, var.admin_allowed_emails)

  # [접근 권한 안내] 자원(앱 호스트)별로 열 수 있는 소속(department). 로그인 서버(auth_app.py)가 환경변수로 받아
  # /stepup에서 "소속이 달라서 막힌 것인지, 위험도 때문에 추가 인증이 필요한 것인지"를 구분하는 데 쓴다.
  # 키: 자원의 호스트("dev.xmcda.store" 등, 위 app_hosts). 값: 그 자원을 열 수 있는 소속 목록.
  # 포털(전 직원 공통)은 표에 없음 = 소속 제한 없음.
  # 소속은 DB accounts.department 값이며, 위 *_team_emails 목록과 같은 사람 구성으로 맞춰 둬야 한다
  # (Access 정책은 이메일 그룹으로 허용/차단하고, 이 표는 안내 화면만 고른다 - 두 곳이 어긋나면 안내가 틀릴 뿐 권한이 새지는 않음).
  path_departments = {
    (local.app_hosts.dev)       = ["dev"]
    (local.app_hosts.marketing) = ["marketing"]
    (local.app_hosts.hr)        = ["hr"]
    (local.app_hosts.admin)     = ["admin"]
  }
  path_permissions_env = join(";", [for path, depts in local.path_departments : "${path}=${join(",", depts)}"])

  # [계정 소속 자동 반영] 위 *_team_emails / admin_allowed_emails 목록에서 "이메일=소속;..." 문자열을 만든다.
  # 로그인 서버가 켜질 때 이 목록의 계정만 DB accounts.department를 맞춘다(목록에 없는 계정은 건드리지 않음).
  # 이메일 그룹(Access 정책)과 DB 소속이 같은 목록에서 나오므로 두 곳이 어긋나지 않는다.
  account_departments_env = join(";", concat(
    [for e in local.dev_team_emails : "${lower(e)}=dev"],
    [for e in local.marketing_team_emails : "${lower(e)}=marketing"],
    [for e in local.hr_team_emails : "${lower(e)}=hr"],
    [for e in var.admin_allowed_emails : "${lower(e)}=admin"],
  ))
}

# ==========================================
# 1. AWS DynamoDB (Risk Score & Audit Log)
# ==========================================
resource "aws_dynamodb_table" "risk_score_log" {
  name         = "risk_score_log"
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

# [step-up 재인증] "이 사용자가 최근에 MFA를 통과했다"는 사실만 담는 짧은 수명의 기록.
# User Risk(관리자가 풀어주는 누적 위험 상태, 미구현)와는 다른 층 - 이건 인증이 얼마나
# 최근인가만 나타냄. identity를 파티션 키로 써서 사용자별로 자동 분리되고, TTL로
# expires_at이 지난 항목은 AWS가 자동으로 정리한다(정리 시점은 수 분~수 시간 지연될
# 수 있음 - Lambda가 expires_at을 직접 비교해서 판단하므로 정리 지연이 보안에 영향 없음).
resource "aws_dynamodb_table" "mfa_verified" {
  name         = "mfa_verified"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "identity"

  attribute {
    name = "identity"
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

# [마지막 판단] 사용자+앱(호스트)별 가장 최근 판단(재인증 필요 / 차단 / 기기 때문에 차단)과 기기 사유.
# Access가 막으면 사용자는 로그인 서버의 /stepup으로 오는데, 그 페이지가 엔진에 이 기록을 물어서
# 재인증 화면과 차단 화면 중 하나를 고른다(판단은 엔진, 화면은 로그인 서버). 화면 선택용이라 10분이면 충분하고 TTL로 정리한다.
resource "aws_dynamodb_table" "access_decision" {
  name         = "access_decision"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "identity"
  range_key    = "resource_host"

  attribute {
    name = "identity"
    type = "S"
  }

  attribute {
    name = "resource_host"
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

# ==========================================
# 2. AWS IAM Role (EC2 공용: Session Manager 접속만)
#    예전에는 AmazonDynamoDBFullAccess(모든 테이블에 모든 작업)를 붙였다. 지금은 DynamoDB 권한이 전혀 없고,
#    관리자 콘솔을 돌리는 app 서버만 별도 역할(risk_admin.tf)로 필요한 작업만 갖는다.
#    (Lambda 판단 엔진은 또 다른 역할을 쓴다 - 아래 3번)
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

# [참고] 감사 로그 조회(risk_score_log Scan)는 관리자 콘솔을 돌리는 app 서버 전용 역할(risk_admin.tf의 app_role)로 옮겼다.
#   이 공용 역할은 web/auth/app가 함께 쓰므로 SSM(아래)만 갖는다 - web/auth 서버는 DynamoDB 권한이 필요 없다.

# EC2를 AWS 콘솔의 Session Manager로 SSH 없이 접속하기 위한 권한
# (부팅 스크립트 실패 원인 확인 등, 문제 해결 목적으로 추가)
resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
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
  name_prefix = "risk-score-lambda-"

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

# Lambda 판단 엔진이 실제로 쓰는 DynamoDB 작업만 허용한다 (예전에는 AmazonDynamoDBFullAccess).
#   risk_score_log : 판정 결과 기록(PutItem)
#   mfa_verified   : step-up 재인증 기록 저장(PutItem)과 조회(GetItem)
#   user_risk      : 사용자별 위험 상태 조회(Query)와 기록/갱신(UpdateItem). 해제(관리자)는 risk_admin Lambda만 한다.
#   access_decision: 사용자+앱별 마지막 판단 저장(PutItem)과 조회(GetItem) - /stepup 화면 선택용
resource "aws_iam_role_policy" "lambda_dynamodb" {
  name = "zt-lambda-dynamodb-minimal"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteRiskLog"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = [aws_dynamodb_table.risk_score_log.arn]
      },
      {
        Sid      = "MfaVerifiedReadWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:GetItem"]
        Resource = [aws_dynamodb_table.mfa_verified.arn]
      },
      {
        Sid      = "AccessDecisionReadWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:GetItem"]
        Resource = [aws_dynamodb_table.access_decision.arn]
      },
      {
        Sid      = "UserRiskReadAndFlag"
        Effect   = "Allow"
        Action   = ["dynamodb:Query", "dynamodb:UpdateItem"]
        Resource = [aws_dynamodb_table.user_risk.arn]
      }
    ]
  })
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda.zip"
  source_file = "${path.module}/risk_score_engine.py"
}

# /evaluate가 인증 없이 URL만 알면 호출 가능한 문제 보완용 공유 비밀키.
# HTTP API(v2)는 API Key/Usage Plan을 지원하지 않아, Lambda가 직접 헤더를 검증하는 방식으로 대체.
# (2026-09: random_password -> variable로 전환. terraform.tfvars에 값 고정, destroy해도 유지됨)

resource "aws_lambda_function" "pdp_engine" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "risk-score-engine"
  role             = aws_iam_role.lambda_role.arn
  handler          = "risk_score_engine.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      EVALUATE_SHARED_SECRET = var.evaluate_shared_secret
      # 자원 등급표(호스트 -> 등급)를 만들 때 쓰는 기준 도메인 (risk_score_engine.py RESOURCE_TIERS)
      DOMAIN_NAME = var.domain_name
      # [기기 신뢰] 필수 기기 검사 이름(device_posture.tf)과, 기기 등록 사용자 조회용 Cloudflare 읽기 전용 토큰
      DEVICE_POSTURE_RULE_NAME = cloudflare_zero_trust_device_posture_rule.windows_firewall.name
      CF_ACCOUNT_ID            = var.cloudflare_account_id
      CF_DEVICE_API_TOKEN      = var.cloudflare_device_read_token
      # 기기 신호 스위치: enforce(점수 반영) / report(로그에만 남김) / off(계산 안 함)
      DEVICE_SIGNAL_MODE = var.device_signal_mode
    }
  }
}

# ==========================================
# 4. AWS API Gateway (HTTP API)
# ==========================================
resource "aws_apigatewayv2_api" "pdp_api" {
  name          = "risk-score-pdp-api"
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
# 5-0. Cloudflare Access Identity Provider — 우리 로그인서버를 OIDC IdP로 등록
#   Access가 "이메일 OTP" 대신 우리 로그인서버(app.py의 /authorize, /token,
#   /.well-known/jwks.json)로 신원을 확인하도록 등록. client_id/client_secret은
#   /token이 검증하는 값과 반드시 동일해야 함(variables.tf에서 관리, ec2_app.tf가
#   같은 값을 Flask 환경변수로도 전달함).
#   Access는 /token이 돌려주는 id_token(JWT)의 클레임(email 등)을 certs_url(JWKS)로
#   서명 검증해서 직접 읽어옴 — /userinfo를 따로 호출하진 않음(OIDC 표준 동작).
# ==========================================
resource "cloudflare_zero_trust_access_identity_provider" "login_server" {
  account_id = var.cloudflare_account_id
  name       = "ZT Login Server"
  type       = "oidc"

  config {
    client_id     = var.oidc_client_id
    client_secret = var.oidc_client_secret
    auth_url      = "https://${local.auth_domain}/authorize"
    token_url     = "https://${local.auth_domain}/token"
    certs_url     = "https://${local.auth_domain}/.well-known/jwks.json"
    scopes        = ["openid", "email", "profile"]
  }
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
# ==========================================
# 5-0-1. Cloudflare Access Groups — 이메일을 재사용 가능한 이름표로 묶어둠
#   (개별 정책마다 이메일을 나열하지 않고, 그룹만 참조. 인원 변경 시 여기만 수정하면 됨)
# ==========================================
resource "cloudflare_zero_trust_access_group" "all_employees" {
  account_id = var.cloudflare_account_id
  name       = "전체 직원"
  include {
    email = local.all_employee_emails
  }
}

resource "cloudflare_zero_trust_access_group" "dev_team" {
  account_id = var.cloudflare_account_id
  name       = "개발팀"
  include {
    email = local.dev_team_emails
  }
}

resource "cloudflare_zero_trust_access_group" "marketing_team" {
  account_id = var.cloudflare_account_id
  name       = "마케팅팀"
  include {
    email = local.marketing_team_emails
  }
}

resource "cloudflare_zero_trust_access_group" "hr_team" {
  account_id = var.cloudflare_account_id
  name       = "인사팀"
  include {
    email = local.hr_team_emails
  }
}

resource "cloudflare_zero_trust_access_group" "admins" {
  account_id = var.cloudflare_account_id
  name       = "관리자"
  include {
    email = var.admin_allowed_emails
  }
}

# ==========================================
# 5-2. 포털 홈 + 부서별 애플리케이션 (전체 직원 / 개발팀 / 마케팅팀 / 인사팀)
# ==========================================
resource "cloudflare_zero_trust_access_application" "portal" {
  account_id                = var.cloudflare_account_id
  name                       = "ZT Portal (전사 공통)"
  domain                     = local.app_hosts.portal
  type                       = "self_hosted"
  # [확대] admin_console에서 검증 완료(§14) - 나머지 5개 앱에도 동일 적용
  session_duration           = "15m"
  custom_deny_url            = "https://auth.xmcda.store/stepup"
  allowed_idps               = [cloudflare_zero_trust_access_identity_provider.login_server.id]
  auto_redirect_to_identity  = true
  # [중복 평가 실험] Cloudflare 앱 런처(직원용 앱 목록 화면)에 표시하지 않음. 우리는 런처 대신 자체 포털을 쓴다.
  # 로그 패턴상 Access가 로그인할 때 "런처에 보이는 앱"을 전부 미리 평가하는 것으로 보여(런처에서 숨긴
  # admin만 직접 들어갈 때 1번 평가됨) admin과 같이 숨긴다. 문서로 확인한 동작이 아니라 실측 확인 대상.
  app_launcher_visible       = false

  # [통일 관리 방식 확장] 로그인 필수 + 세션 위험화 가능성은 다른 페이지와 동일해 risk_block_shared 추가.
  policies = [
    cloudflare_zero_trust_access_policy.risk_block_shared.id,
    cloudflare_zero_trust_access_policy.portal_gate.id,
  ]
}

resource "cloudflare_zero_trust_access_policy" "portal_gate" {
  account_id = var.cloudflare_account_id
  name       = "Portal - All Employees"
  decision   = "allow"
  include {
    group = [cloudflare_zero_trust_access_group.all_employees.id]
  }
}

resource "cloudflare_zero_trust_access_application" "dev" {
  account_id                = var.cloudflare_account_id
  name                       = "ZT Dev Team"
  domain                     = local.app_hosts.dev
  type                       = "self_hosted"
  session_duration           = "15m"
  custom_deny_url            = "https://auth.xmcda.store/stepup"
  allowed_idps               = [cloudflare_zero_trust_access_identity_provider.login_server.id]
  auto_redirect_to_identity  = true
  # [중복 평가 실험] Cloudflare 앱 런처(직원용 앱 목록 화면)에 표시하지 않음. 우리는 런처 대신 자체 포털을 쓴다.
  # 로그 패턴상 Access가 로그인할 때 "런처에 보이는 앱"을 전부 미리 평가하는 것으로 보여(런처에서 숨긴
  # admin만 직접 들어갈 때 1번 평가됨) admin과 같이 숨긴다. 문서로 확인한 동작이 아니라 실측 확인 대상.
  app_launcher_visible       = false

  # [통일 관리 방식 재시도] Deny(risk_block_shared)와 Allow(dev_gate) 둘 다 이 리스트 하나로만 관리함(관리 방식 섞음 방지).
  # 리스트 순서 = precedence (먼저 = Deny 먼저 평가)
  policies = [
    cloudflare_zero_trust_access_policy.block_non_members["dev"].id,
    cloudflare_zero_trust_access_policy.risk_block_shared.id,
    cloudflare_zero_trust_access_policy.dev_gate.id,
  ]
}

# [통일 관리 방식 재시도] application_id를 빼서 이것도 재사용형 정책으로 전환.
# precedence는 위 dev 앱의 policies 리스트 순서가 결정하며, 여기서 명시하면 중복 지정이 되므로 빼도 됨.
resource "cloudflare_zero_trust_access_policy" "dev_gate" {
  account_id = var.cloudflare_account_id
  name       = "Dev - Dev Team Only"
  decision   = "allow"
  include {
    group = [cloudflare_zero_trust_access_group.dev_team.id]
  }
}

resource "cloudflare_zero_trust_access_application" "marketing" {
  account_id                = var.cloudflare_account_id
  name                       = "ZT Marketing Team"
  domain                     = local.app_hosts.marketing
  type                       = "self_hosted"
  session_duration           = "15m"
  custom_deny_url            = "https://auth.xmcda.store/stepup"
  allowed_idps               = [cloudflare_zero_trust_access_identity_provider.login_server.id]
  auto_redirect_to_identity  = true
  # [중복 평가 실험] Cloudflare 앱 런처(직원용 앱 목록 화면)에 표시하지 않음. 우리는 런처 대신 자체 포털을 쓴다.
  # 로그 패턴상 Access가 로그인할 때 "런처에 보이는 앱"을 전부 미리 평가하는 것으로 보여(런처에서 숨긴
  # admin만 직접 들어갈 때 1번 평가됨) admin과 같이 숨긴다. 문서로 확인한 동작이 아니라 실측 확인 대상.
  app_launcher_visible       = false

  policies = [
    cloudflare_zero_trust_access_policy.block_non_members["marketing"].id,
    cloudflare_zero_trust_access_policy.risk_block_shared.id,
    cloudflare_zero_trust_access_policy.marketing_gate.id,
  ]
}

resource "cloudflare_zero_trust_access_policy" "marketing_gate" {
  account_id = var.cloudflare_account_id
  name       = "Marketing - Marketing Team Only"
  decision   = "allow"
  include {
    group = [cloudflare_zero_trust_access_group.marketing_team.id]
  }
}

resource "cloudflare_zero_trust_access_application" "hr" {
  account_id                = var.cloudflare_account_id
  name                       = "ZT HR Team"
  domain                     = local.app_hosts.hr
  type                       = "self_hosted"
  session_duration           = "15m"
  custom_deny_url            = "https://auth.xmcda.store/stepup"
  allowed_idps               = [cloudflare_zero_trust_access_identity_provider.login_server.id]
  auto_redirect_to_identity  = true
  # [중복 평가 실험] Cloudflare 앱 런처(직원용 앱 목록 화면)에 표시하지 않음. 우리는 런처 대신 자체 포털을 쓴다.
  # 로그 패턴상 Access가 로그인할 때 "런처에 보이는 앱"을 전부 미리 평가하는 것으로 보여(런처에서 숨긴
  # admin만 직접 들어갈 때 1번 평가됨) admin과 같이 숨긴다. 문서로 확인한 동작이 아니라 실측 확인 대상.
  app_launcher_visible       = false

  policies = [
    cloudflare_zero_trust_access_policy.block_non_members["hr"].id,
    cloudflare_zero_trust_access_policy.risk_block_shared.id,
    cloudflare_zero_trust_access_policy.hr_gate.id,
  ]
}

resource "cloudflare_zero_trust_access_policy" "hr_gate" {
  account_id = var.cloudflare_account_id
  name       = "HR - HR Team Only"
  decision   = "allow"
  include {
    group = [cloudflare_zero_trust_access_group.hr_team.id]
  }
}

# [소속 먼저 확인] 팀 앱마다 정책 순서를 ① 이 팀이 아니면 차단 → ② 위험도 차단(외부 평가) → ③ 팀 허용으로 둔다.
# Cloudflare 문서: Block/Allow 정책은 목록 위에서부터 검사하고 처음 걸린 정책에서 결정이 끝난다.
# 예전엔 위험도 차단이 맨 위라 다른 팀 직원도 위험도 평가(Lambda 호출)부터 받고 나서 소속에서 막혔다
# (로그엔 위험도 allow인데 화면은 "권한 없음"). 이제 다른 팀은 ①에서 끝나 평가가 일어나지 않는다.
# 허용(③)을 맨 위로 올리면 팀원이 위험도 검사 없이 통과하므로 순서를 바꾸면 안 된다.
# 막힌 사람은 지금처럼 custom_deny_url(/stepup)로 가서 "접근 권한 없음" 화면을 본다.
resource "cloudflare_zero_trust_access_policy" "block_non_members" {
  for_each = {
    dev       = cloudflare_zero_trust_access_group.dev_team.id
    marketing = cloudflare_zero_trust_access_group.marketing_team.id
    hr        = cloudflare_zero_trust_access_group.hr_team.id
    admin     = cloudflare_zero_trust_access_group.admins.id
  }

  account_id = var.cloudflare_account_id
  name       = "${each.key} - Block Non-Members"
  decision   = "deny"

  include {
    everyone = true
  }
  exclude {
    group = [each.value]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "cloudflare_zero_trust_access_application" "admin_console" {
  account_id       = var.cloudflare_account_id
  name             = "ZT Admin Console"
  # [실험] 경로 기반(xmcda.store/admin)에서 서브도메인 기반으로 변경.
  # 경로 기반 구조에서는 CF_AppSession이 도메인 전체(xmcda.store)로 공유돼,
  # /dev·/marketing처럼 임계값이 느슨한 형제 앱의 통과 판정이 /admin에도 새어들어와
  # 위험판단이 무력화되는 문제가 있었음(path_cookie_attribute로도 해결 안 됨).
  # 서브도메인은 브라우저 입장에서 완전히 다른 origin이라 이 문제가 구조적으로 발생하지 않음.
  domain           = local.app_hosts.admin
  type             = "self_hosted"
  # [수정] 24시간짜리 세션이 살아있는 동안은 재접속해도 /authorize(로그인서버)를
  # 아예 안 거쳐서, SSO 재사용 보안수정(brute_force면 강제 재로그인)이 실행될
  # 기회 자체가 없었음. Access가 세션 중에는 위험을 재평가하지 않는다는 한계
  # (§5-4, B 계층 미구현)를 근본적으로 없앨 방법은 없어서, 재평가 주기를 강제로
  # 자주 만드는 임시 조치로 짧게 줄임. 완전한 해결은 아니고, B 계층이 생기면
  # 그때 다시 조정 필요.
  session_duration = "15m"
  # 이메일 OTP 선택지를 없애고, 이 앱은 우리 로그인서버(TOTP 2단계)로만 로그인 가능하게 제한
  allowed_idps     = [cloudflare_zero_trust_access_identity_provider.login_server.id]
  # 선택지가 하나뿐이니 "로그인 방법 선택" 화면 없이 바로 우리 로그인서버로 리다이렉트
  auto_redirect_to_identity = true
  app_launcher_visible = false
  # [수정, 실접속 검증됨] 문서상으로는 External Evaluation이 "비신원 기반" 규칙으로
  # 분류돼 custom_non_identity_deny_url을 써야 할 것 같았으나, 실제로는 반영이 안 됐고
  # 대시보드에서 "Identity failure block page"를 Redirect URL로 바꾸니 정상 동작함을
  # 실접속으로 확인함. 왜 이렇게 분류되는지 문서로 확정된 근거는 없음 - 정직하게 실험
  # 결과만 반영.
  custom_deny_url = "https://auth.xmcda.store/stepup"

  # [통일 관리 방식] risk_block_shared를 dev/marketing/hr와 동일하게 적용.
  # (예전에 경로 앱끼리 쿠키를 나누려고 Cloudflare API로 path_cookie_attribute를 켜던
  # null_resource는 dev/marketing/hr를 서브도메인으로 옮기면서 필요 없어져 삭제함)
  policies = [
    cloudflare_zero_trust_access_policy.block_non_members["admin"].id,
    cloudflare_zero_trust_access_policy.risk_block_shared.id,
    cloudflare_zero_trust_access_policy.admin_gate_console.id,
  ]
}

resource "cloudflare_zero_trust_access_policy" "admin_gate_console" {
  account_id = var.cloudflare_account_id
  name       = "Admin Console - Admins Only"
  decision   = "allow"

  include {
    group = [cloudflare_zero_trust_access_group.admins.id]
  }
}

resource "cloudflare_zero_trust_access_policy" "risk_block_shared" {
  account_id = var.cloudflare_account_id
  name       = "Global - Risk Block (External Evaluation)"
  decision   = "deny"

  include {
    external_evaluation {
      evaluate_url = "https://ztna-access-evaluator.xmcda.workers.dev"
      keys_url     = "https://ztna-access-evaluator.xmcda.workers.dev/keys"
    }
  }

  lifecycle {
    create_before_destroy = true
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
  # [변경7] web_server가 이제 /etc/cloudflared/config.yml(로컬 파일)로 직접
  # ingress를 관리하므로, cloudflared는 더 이상 이 원격 설정을 기다리지 않음.
  # 이 리소스는 Cloudflare 대시보드 표시용/백업 목적으로만 유지 (원격 설정 전달
  # 실패로 인한 503 재발 방지가 이번 변경의 핵심).
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.id

  config {
    # auth.xmcda.store도 웹 서버 nginx를 거쳐 mTLS로 auth_server에 간다(Web->WAS mTLS).
    # nginx에는 auth 호스트 전용 server 블록이 따로 있고 그 블록은 auth_server로만 보낸다.
    # (예전엔 nginx가 도메인 구분 없이 모든 경로를 app_server로 넘기던 구조라 login 호스트로 Access 보호를
    # 우회할 수 있는 구멍이 있었음 - 호스트별 server 블록과 auth_server에 /admin 라우트가 없다는 점으로 막혀 있음)
    ingress_rule {
      hostname = local.auth_domain
      service  = "http://localhost:80"
    }
    ingress_rule {
      hostname = local.app_hosts.admin
      service  = "http://localhost:80"
    }
    ingress_rule {
      hostname = local.app_hosts.dev
      service  = "http://localhost:80"
    }
    ingress_rule {
      hostname = local.app_hosts.marketing
      service  = "http://localhost:80"
    }
    ingress_rule {
      hostname = local.app_hosts.hr
      service  = "http://localhost:80"
    }
    ingress_rule {
      hostname = var.domain_name
      service  = "http://localhost:80"
    }
    ingress_rule {
      service = "http_status:404"
    }
  }
}

resource "cloudflare_record" "auth_dns" {
  zone_id = var.cloudflare_zone_id
  name    = "auth"
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
}

resource "cloudflare_record" "web_app_dns" {
  zone_id = var.cloudflare_zone_id
  name    = var.domain_name
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
}

# [실험] admin_console을 서브도메인으로 분리하면서 추가.
# 같은 터널(web_tunnel)을 그대로 쓰고, 실제 경로 분기는 EC2 쪽 cloudflared
# 로컬 config.yml(user_data_web_sh.tpl)의 hostname 규칙이 담당함.
resource "cloudflare_record" "admin_dns" {
  zone_id = var.cloudflare_zone_id
  name    = "admin"
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
}

# [서브도메인 분리] dev/marketing/hr도 admin과 같은 방식(같은 터널, 같은 웹 서버). 1단계 서브도메인이라
# Cloudflare 무료 인증서(Universal SSL)가 그대로 적용된다(2단계 a.b.xmcda.store는 미적용이라 쓰지 않음).
resource "cloudflare_record" "team_app_dns" {
  for_each = toset(["dev", "marketing", "hr"])

  zone_id = var.cloudflare_zone_id
  name    = each.key
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
}

# ==========================================
# 6. EC2 Web/App 티어 — compute.tf로 분리됨 (3-Tier 전환)
#    기존 단일 EC2(web_app)는 web_server(Web, nginx)와 app_server(App, Flask) 2대로 교체됨.
#    DB 티어(RDS)는 database.tf, VPC/서브넷/SG는 network.tf 참고.
# ==========================================