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

# Worker -> Lambda(/evaluate), Flask -> Lambda(/evaluate) 호출 인증용 공유 비밀키.
# random_password였다가 변수로 전환(2026-09 세션): terraform destroy를 해도 terraform.tfvars에
# 고정해둔 값이 유지되므로, destroy할 때마다 Worker에 wrangler secret put을 다시 할 필요가 없어짐.
# terraform.tfvars(git 미포함)에 openssl rand -hex 32 등으로 생성한 값을 한 번만 넣어두면 됨.
variable "evaluate_shared_secret" {
  type        = string
  sensitive   = true
  description = "/evaluate Lambda 호출 인증용 공유 비밀키 (terraform.tfvars에서 고정값 지정, git 미포함)"
}
