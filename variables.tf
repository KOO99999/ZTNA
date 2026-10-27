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

# [기기 신뢰] 위험도 엔진(Lambda)이 기기 ID로 "그 기기를 등록한 사용자"를 조회할 때 쓰는 Cloudflare API 토큰.
# 읽기 전용(Account > Zero Trust > Read)으로 따로 만든다. Terraform용 토큰(편집 권한)을 Lambda에 넣지 않기 위해서다(최소권한).
# 비워 두면 기기 주인 확인만 건너뛰고, 기기 상태(WARP 연결/방화벽) 신호는 그대로 동작한다.
variable "cloudflare_device_read_token" {
  type        = string
  sensitive   = true
  default     = ""
  description = "기기 등록 사용자 조회용 Cloudflare API 토큰 (Zero Trust Read 전용, terraform.tfvars)"
}

# 기기 신호 스위치. 다른 신호를 만들고 시험하는 동안은 report로 두면 기기 신호가 판단에 영향을 주지 않고
# 로그(risk_score_log의 reasons)에만 "report-only, +0"으로 남는다. 시연/최종 단계에서 enforce로 바꾼다.
# 바꾼 뒤 terraform apply 하면 Lambda 환경변수만 바뀐다(서버 재생성 없음).
variable "device_signal_mode" {
  type        = string
  default     = "report"
  description = "기기 신호 모드: enforce(점수 반영) / report(로그에만) / off(계산 안 함)"
  validation {
    condition     = contains(["enforce", "report", "off"], var.device_signal_mode)
    error_message = "device_signal_mode는 enforce, report, off 중 하나여야 합니다."
  }
}

# 기기 순찰이 상태가 나빠진 사용자의 Access 세션을 끊을 때 쓰는 토큰(device_sweep.tf).
# 권한은 Account > Access: Organizations, Identity Providers, and Groups > Edit 하나만 준다.
# 읽기 토큰(cloudflare_device_read_token)과 일부러 분리한다(쓰기 권한은 순찰 함수에만, 최소권한).
# 비워 두면 순찰은 상태만 기록하고 세션은 끊지 않는다.
variable "cloudflare_access_revoke_token" {
  type        = string
  sensitive   = true
  default     = ""
  description = "기기 상태가 나빠진 사용자의 Access 세션을 끊는 Cloudflare 토큰 (Access Organizations Edit 전용, terraform.tfvars)"
}

# WAF(ModSecurity) 동작 모드. On = 공격 요청을 막고 그 사람에게 위험을 건다.
# DetectionOnly = 막지 않고 웹 서버 로그에만 남긴다(오탐 확인용, 엔진에도 알리지 않음).
variable "waf_engine_mode" {
  type        = string
  default     = "On"
  description = "ModSecurity SecRuleEngine 값: On 또는 DetectionOnly"
  validation {
    condition     = contains(["On", "DetectionOnly"], var.waf_engine_mode)
    error_message = "waf_engine_mode는 On 또는 DetectionOnly여야 합니다."
  }
}

# [위협 IP] AbuseIPDB API 키(무료 계정, 하루 1,000회 조회). 비워 두면 위협 IP 신호를 계산하지 않는다.
variable "abuseipdb_api_key" {
  type        = string
  sensitive   = true
  default     = ""
  description = "AbuseIPDB API 키 (terraform.tfvars)"
}

# AbuseIPDB 위험 점수(abuseConfidenceScore, 0~100)가 이 값 이상이면 threat_intel_match.
# AbuseIPDB 문서는 기준값을 정해 주지 않는다(점수를 판단 근거로 쓰라고만 권장) - 50은 팀 판단 값.
variable "threat_intel_min_score" {
  type        = number
  default     = 50
  description = "threat_intel_match 기준 점수 (1~100)"
  validation {
    condition     = var.threat_intel_min_score >= 1 && var.threat_intel_min_score <= 100
    error_message = "threat_intel_min_score는 1~100 사이여야 합니다."
  }
}

# 세션 바인딩 스위치. 세션 도중 로그인한 나라(Access 토큰 country)와 지금 나라가 다르면 쿠키 탈취로 의심한다.
# 오탐 위험이 있어 상용 제품도 기록 모드와 적용 모드를 나눈다(Okta Session protection: Monitoring/Enforced).
#   report = 로그(risk_score_log reasons)에만 남김(기본값) / enforce = 다시 로그인 요구 / off = 계산 안 함
variable "session_binding_mode" {
  type        = string
  default     = "report"
  description = "세션 바인딩 모드: enforce / report / off"
  validation {
    condition     = contains(["enforce", "report", "off"], var.session_binding_mode)
    error_message = "session_binding_mode는 enforce, report, off 중 하나여야 합니다."
  }
}

# [이동 속도] MaxMind GeoLite 웹 조회(geolite.info, 무료 하루 1,000회) 인증 정보: 계정 ID + 라이선스 키 (terraform.tfvars)
variable "maxmind_account_id" {
  type        = string
  sensitive   = true
  default     = ""
  description = "MaxMind 계정 ID (비우면 이동 속도 신호를 계산하지 않음)"
}

variable "maxmind_license_key" {
  type        = string
  sensitive   = true
  default     = ""
  description = "MaxMind 라이선스 키 (terraform.tfvars)"
}

# 불가능한 이동(geo_velocity)을 점수에 반영할지: enforce / report(로그에만, 기본값) / off(조회도 안 함)
variable "geo_velocity_mode" {
  type        = string
  default     = "report"
  description = "이동 속도 신호 모드: enforce / report / off"
  validation {
    condition     = contains(["enforce", "report", "off"], var.geo_velocity_mode)
    error_message = "geo_velocity_mode는 enforce, report, off 중 하나여야 합니다."
  }
}

# [관제] ELK 관제 서버를 만들지(기본 false: 큰 서버라 시험/데모 날만 켬). 켜고 끄면 웹/인증/앱 서버도 다시 만들어진다(Filebeat 설치 여부).
variable "enable_elk" {
  type        = bool
  default     = false
  description = "관제 콘솔(Elasticsearch/Logstash/Kibana/ElastAlert2) 생성 여부"
}

# Elasticsearch(힙 2GB) + Logstash(1GB) + Kibana(약 1GB)가 함께 돌아 8GB가 필요하다.
# 2025-07-15 이후 만든 AWS 계정의 무료 플랜은 "프리 티어 대상" 유형만 띄울 수 있다(EC2 User Guide: Track your Free Tier usage).
# 그 목록 중 8GB인 유형이 m7i-flex.large(2 vCPU, 8GiB)다. 무료가 아니라 크레딧에서 차감된다(서울 약 $0.12/시간).
variable "elk_instance_type" {
  type        = string
  default     = "m7i-flex.large"
  description = "관제 서버 인스턴스 유형"
}

# Discord 채널 웹훅 주소(채널 설정 > 연동 > 웹후크). 이 주소만 알면 누구나 채널에 글을 쓸 수 있어 비밀로 다룬다.
variable "discord_webhook_url" {
  type        = string
  sensitive   = true
  default     = ""
  description = "ElastAlert2 알림을 보낼 Discord 웹훅 주소 (terraform.tfvars)"
  validation {
    condition     = var.discord_webhook_url == "" || can(regex("^https://(discord\\.com|discordapp\\.com)/api/webhooks/", var.discord_webhook_url))
    error_message = "discord_webhook_url은 https://discord.com/api/webhooks/... 형식이어야 합니다."
  }
}
