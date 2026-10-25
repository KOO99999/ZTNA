# ==========================================
# 기기 신뢰(device posture): WARP(Cloudflare One Client) 기기 검사 + 기기 등록 허용 정책
#
#  왜: 회사 직원용 제로트러스트에서 "회사가 관리하는 건강한 기기인가"는 기기 안의 에이전트가 검사하는 게
#      실무 표준이다(웹사이트는 브라우저 밖의 방화벽/디스크 암호화 상태를 볼 수 없음). 그래서 검사 장치는
#      직접 만들지 않고 Cloudflare 제품 기능을 구성하고, 그 결과를 위험도 엔진의 신호로 받는 것을 목표로 한다
#      (탐지/검사는 검증된 도구, 판단은 엔진 한 곳).
#  실측 확인(2026-10-24): Access가 External Evaluation 신원 정보에 devicePosture(검사 결과)와 device_id를 담아
#             Worker로 보낸다. Worker는 그대로 엔진에 넘기고, 엔진(risk_score_engine.py derive_device_signals)이
#             device_unmanaged / device_posture_failed / device_owner_mismatch 신호로 판단한다.
#  사람이 할 일: 시연 PC에 Cloudflare One Client(WARP) 설치 -> 팀 이름(cloudflare_team_domain의 앞부분)으로 등록.
#             설치/등록은 Terraform으로 할 수 없다.
#  참고: 계정에 원래 보이는 "WARP", "Gateway" 검사는 Terraform이 만들거나 지우지 않는다.
# ==========================================

# --- 기기 검사 규칙: Windows 방화벽이 켜져 있어야 통과 ---
# 출처: Cloudflare 문서 "Firewall" posture check(Windows/macOS만 지원), provider 리소스 cloudflare_zero_trust_device_posture_rule
resource "cloudflare_zero_trust_device_posture_rule" "windows_firewall" {
  account_id  = var.cloudflare_account_id
  name        = "ZT - Windows Firewall On"
  type        = "firewall"
  description = "Windows 방화벽이 켜져 있어야 통과 (ZT 프로젝트 기기 신뢰 신호)"
  # 클라이언트가 이 주기로 검사해서 결과를 보낸다. 결과는 expiration이 지나면 무효(검사가 멈춘 기기를 계속 믿지 않음).
  # Cloudflare 제약: expiration은 schedule보다 최소 15분 길어야 한다(API 오류 2116로 확인) -> 5분 + 15분 = 20분.
  schedule   = "5m"
  expiration = "20m"

  match {
    platform = "windows"
  }

  input {
    enabled = true
  }
}

# --- 기기 등록 허용 정책: 우리 직원만, 우리 로그인 서버(비밀번호+TOTP)로 인증해야 WARP를 팀에 등록할 수 있다 ---
# Cloudflare에서 "Device enrollment permissions"는 type = "warp"인 Access 앱으로 관리된다.
# 정책은 포털과 같은 "전체 직원" 허용 정책을 재사용한다.
# 주의: 계정에 이미 WARP 등록 앱이 손으로 만들어져 있으면 생성이 충돌할 수 있다(그 경우 terraform import로 가져온다).
resource "cloudflare_zero_trust_access_application" "warp_enrollment" {
  account_id                = var.cloudflare_account_id
  name                      = "ZT - WARP Device Enrollment"
  type                      = "warp"
  session_duration          = "24h"
  allowed_idps              = [cloudflare_zero_trust_access_identity_provider.login_server.id]
  auto_redirect_to_identity = true
  app_launcher_visible      = false

  policies = [
    cloudflare_zero_trust_access_policy.portal_gate.id,
  ]
}
