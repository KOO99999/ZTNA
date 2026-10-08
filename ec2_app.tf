# ==========================================
# 11. Portal 티어 EC2 — Flask (포털/부서 페이지/관리자 콘솔)
#    로그인 로직은 auth_server(ec2_auth.tf)로 분리됨 - 이 서버는 DB 연결이 필요 없음
#    [JWT 검증] Cloudflare Access 서명 토큰 검증용 팀 도메인/AUD를 환경변수로 받음
#    [B 계층] 세션 중 위험도 재확인을 위해 Lambda(PDP) 호출용 URL/비밀키를 환경변수로 받음
#    코드는 portal_app.py 외부 파일에서 관리, main.tf/compute.tf는 참조만 함
# ==========================================
resource "aws_instance" "app_server" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = "t3.micro"
  subnet_id            = aws_subnet.app_subnet.id
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  vpc_security_group_ids = [aws_security_group.app_sg.id]

  user_data_replace_on_change = true

  user_data_base64 = base64gzip(templatefile("${path.module}/templates/user_data_app.sh.tpl", {
    app_code    = file("${path.module}/portal_app.py")
    zt_jwt_code  = file("${path.module}/zt_jwt.py")
    zt_risk_code = file("${path.module}/zt_risk.py")

    # [B 계층] portal_app.py가 세션 중 위험도 재확인을 위해 Lambda(PDP)를 직접 호출함.
    # auth_server(ec2_auth.tf)에 넘기는 값과 동일한 방식/동일한 값.
    pdp_evaluate_url       = "${aws_apigatewayv2_stage.pdp_stage.invoke_url}evaluate"
    evaluate_shared_secret = var.evaluate_shared_secret
    auth_domain            = local.auth_domain
    debug_headers          = var.debug_headers_route ? "1" : "0"

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
      cloudflare_zero_trust_access_application.admin_api.aud,
    ])
  }))

  tags = {
    Name = "ZT-Portal-Server"
  }

  lifecycle {
    create_before_destroy = true
  }
}
