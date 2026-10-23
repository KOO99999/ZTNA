# ==========================================
# 11. Portal 티어 EC2 — Flask (포털/부서 페이지/관리자 콘솔)
#    로그인 로직은 auth_server(ec2_auth.tf)로 분리됨 - 이 서버는 DB 연결이 필요 없음
#    [JWT 검증] Cloudflare Access 서명 토큰 검증용 팀 도메인/AUD를 환경변수로 받음
#    위험도 판단(Lambda 호출)은 web 서버 앞단(nginx auth_request -> auth_gate.py)이 하므로, 이 서버는
#    Lambda 주소도 공유비밀키도 받지 않는다(침해돼도 비밀키가 나가지 않게)
#    코드는 portal_app.py 외부 파일에서 관리, main.tf/compute.tf는 참조만 함
# ==========================================
resource "aws_instance" "app_server" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = "t3.micro"
  subnet_id            = aws_subnet.app_subnet.id
  iam_instance_profile = aws_iam_instance_profile.app_profile.name

  # [IMDSv2 강제] 서버 안에서 임시 IAM 키를 가져올 때 토큰(세션)을 먼저 받아야 하게 한다.
  # v1은 주소만 알면 누구나 키를 가져갈 수 있어, 앱이 속아서 대신 요청해 주는 SSRF에 키가 유출될 수 있다.
  # (AWS 권장: EC2 User Guide "Use IMDSv2"). hop_limit 1 = 서버 밖(컨테이너 등)으로 토큰이 넘어가지 않게 함.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  vpc_security_group_ids = [aws_security_group.app_sg.id]

  user_data_replace_on_change = true

  user_data_base64 = base64gzip(templatefile("${path.module}/templates/user_data_app.sh.tpl", {
    app_code    = file("${path.module}/portal_app.py")
    zt_jwt_code = file("${path.module}/zt_jwt.py")

    auth_domain   = local.auth_domain
    debug_headers = var.debug_headers_route ? "1" : "0"

    # [관리자 콘솔] 관리자 이메일(앱에서 한 번 더 확인)과 위험 상태 해제 Lambda 이름. 앱은 이 함수를 AWS 권한으로 직접 호출한다.
    admin_emails        = join(",", [for e in var.admin_allowed_emails : lower(e)])
    risk_admin_function = aws_lambda_function.risk_admin.function_name
    # 포털 홈 "내 업무 앱" 목록용 계정 소속 표(main.tf locals, 로그인 서버와 같은 값). 링크 표시용이며 권한이 아니다.
    account_departments = local.account_departments_env
    # [Web->WAS mTLS] 부팅 때 SSM에서 받을 인증서(mtls.tf)와, 받아 줄 클라이언트(웹 서버) 인증서 이름
    zt_mtls_code        = file("${path.module}/zt_mtls.py")
    aws_region          = var.aws_region
    mtls_role           = "app"
    mtls_param_prefix   = local.mtls_param_prefix
    mtls_allowed_client = local.mtls_names.web

    # [JWT 서명 검증] portal_app.py가 Cf-Access-Jwt-Assertion의 서명/발급자/aud/만료를 검증함.
    # aud는 이 서버로 요청을 보내는 Access 앱 6개의 AUD 태그(쉼표 구분). 앱이 재생성되어 AUD가
    # 바뀌면 이 값이 바뀌면서 app_server도 자동으로 교체됨.
    cf_team_domain = var.cloudflare_team_domain
    cf_access_auds = join(",", [
      cloudflare_zero_trust_access_application.portal.aud,
      cloudflare_zero_trust_access_application.dev.aud,
      cloudflare_zero_trust_access_application.marketing.aud,
      cloudflare_zero_trust_access_application.hr.aud,
      cloudflare_zero_trust_access_application.admin_console.aud,
    ])
  }))

  tags = {
    Name = "ZT-Portal-Server"
  }

  # 부팅 스크립트가 SSM에서 인증서를 읽으므로, 파라미터와 읽기 권한이 먼저 만들어져 있어야 한다.
  depends_on = [aws_ssm_parameter.mtls_key, aws_ssm_parameter.mtls_cert, aws_ssm_parameter.mtls_ca_cert, aws_iam_role_policy.mtls_read]

  lifecycle {
    create_before_destroy = true
  }
}
