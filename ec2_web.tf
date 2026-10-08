# ==========================================
# 12. Web 티어 EC2 — nginx(리버스프록시) + cloudflared(터널) + 판단 서비스(auth_gate.py)
#    인터넷과 직접 마주하는 유일한 계층. nginx가 앱에 넘기기 전에 판단 서비스에 먼저 묻는다(auth_request).
# ==========================================
resource "aws_instance" "web_server" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = "t3.micro"
  subnet_id            = aws_subnet.web_subnet.id
  availability_zone    = "ap-northeast-2a"
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  vpc_security_group_ids = [aws_security_group.web_sg.id]

  user_data_replace_on_change = true

  # 판단 서비스 코드(파일 3개)가 들어가 user_data가 커져서 gzip 압축으로 전달함
  # (EC2 user_data 한도 16KB는 압축된 크기 기준 - app_server와 같은 방식).
  user_data_base64 = base64gzip(templatefile("${path.module}/templates/user_data_web.sh.tpl", {
    app_private_ip = aws_instance.app_server.private_ip
    tunnel_token   = cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.tunnel_token
    # 아래 4개는 cloudflared가 원격(Cloudflare 대시보드)에 설정을 물어보지 않고
    # 로컬 config.yml만으로 즉시 라우팅하도록 전달하는 값 (503 재발 방지, 변경7 참고)
    tunnel_id       = cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.id
    auth_domain     = local.auth_domain
    auth_private_ip = aws_instance.auth_server.private_ip
    domain_name     = var.domain_name

    # [판단 서비스] nginx auth_request가 요청마다 묻는 auth_gate.py (nginx 옆에서 실행)
    # app_server(ec2_app.tf)에 넘기는 값과 같은 방식/같은 값 + 같은 모듈(zt_jwt.py, zt_risk.py)
    auth_gate_code         = file("${path.module}/auth_gate.py")
    zt_jwt_code            = file("${path.module}/zt_jwt.py")
    zt_risk_code           = file("${path.module}/zt_risk.py")
    pdp_evaluate_url       = "${aws_apigatewayv2_stage.pdp_stage.invoke_url}evaluate"
    evaluate_shared_secret = var.evaluate_shared_secret
    cf_team_domain         = var.cloudflare_team_domain
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
    Name = "ZT-Web-Server"
  }

  lifecycle {
    create_before_destroy = true
  }
}
