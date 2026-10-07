variable "aws_region" {
  type    = string
  default = "ap-northeast-2"
}

variable "aws_profile" {
  type        = string
  description = "EC2를 생성할 AWS 계정의 CLI 프로필 이름 (aws configure --profile 로 등록한 이름)"
}

variable "cloudflare_api_token" {
  type      = string
  sensitive = true
}

# Worker(ztna-access-evaluator) 배포(wrangler deploy) 전용 토큰.
# cloudflare_api_token(Access 정책 관리용)과 용도를 분리해 최소 권한 원칙을 API 토큰
# 레벨까지 일관되게 적용 — 권한 범위: Account > Workers Scripts > Edit, User > User Details > Read
variable "cloudflare_workers_api_token" {
  type        = string
  sensitive   = true
  description = "Cloudflare Workers 배포 전용 API 토큰 (terraform.tfvars, git 미포함)"
}

variable "cloudflare_account_id" {
  type = string
}

variable "cloudflare_zone_id" {
  type = string
}

variable "domain_name" {
  type        = string
  description = "Example: app.yourdomain.com"
}

variable "admin_allowed_emails" {
  type        = list(string)
  description = "관리자 콘솔(/admin) 접근을 허용할 이메일 목록 (Cloudflare Access 이메일 OTP 로그인 대상)"
}

# Cloudflare Zero Trust 팀 도메인. portal_app.py가 이 도메인의 공개키(JWKS)로 Access JWT 서명을
# 검증하고, 토큰의 iss(발급자)가 https://<이 값> 인지도 확인함. 틀리면 모든 요청이 차단되므로 주의.
# Zero Trust 대시보드 > Settings > Custom Pages 등에서 보이는 "<이름>.cloudflareaccess.com" 전체를 넣음(https:// 제외).
variable "cloudflare_team_domain" {
  type        = string
  description = "Cloudflare Zero Trust 팀 도메인 (예: your-team.cloudflareaccess.com, https:// 제외)"

  validation {
    condition     = can(regex("^[a-z0-9-]+\\.cloudflareaccess\\.com$", var.cloudflare_team_domain))
    error_message = "cloudflare_team_domain은 'your-team.cloudflareaccess.com' 형식이어야 합니다(https:// 와 끝의 / 없이)."
  }
}

# Worker -> Lambda(/evaluate), Flask -> Lambda(/evaluate) 호출 인증용 공유 비밀키.
# random_password였다가 변수로 전환(2026-09 세션): terraform destroy를 해도 terraform.tfvars에
# 고정해둔 값이 유지되므로, destroy할 때마다 Worker에 wrangler secret put을 다시 할 필요가 없어짐.
# terraform.tfvars(git 미포함)에 openssl rand -hex 32 등으로 생성한 값을 한 번만 넣어두면 됨.
variable "evaluate_shared_secret" {
  type        = string
  sensitive   = true
  description = "/evaluate Lambda 호출 인증용 공유 비밀키 (terraform.tfvars에서 고정값 지정, git 미포함)"
}

# Cloudflare Access가 OIDC 클라이언트로서 /token을 호출할 때 자신을 증명하는 값.
# Access의 cloudflare_zero_trust_access_identity_provider 등록 설정에도 동일한 값을 넣어야 함
# (evaluate_shared_secret과 같은 이유로 처음부터 variable로 관리 — destroy해도 값 유지)
variable "oidc_client_id" {
  type        = string
  description = "Cloudflare Access가 /token 호출 시 사용할 client_id (terraform.tfvars 고정값)"
}

variable "oidc_client_secret" {
  type        = string
  sensitive   = true
  description = "Cloudflare Access가 /token 호출 시 사용할 client_secret (terraform.tfvars 고정값)"
}

# [임시 확인용] true로 두고 apply하면 portal_app.py에 /debug-headers 라우트가 켜져서, Cloudflare가
# 붙이는 헤더(CF-IPCountry 등)가 nginx를 거쳐 Flask까지 실제로 도착하는지 눈으로 확인할 수 있음.
# 확인이 끝나면 반드시 false(기본값)로 되돌려서 다시 apply할 것.
variable "debug_headers_route" {
  type        = bool
  default     = false
  description = "portal_app.py의 /debug-headers 임시 확인 라우트 활성화 여부 (확인 후 반드시 false)"
}
