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
