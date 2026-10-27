# ==========================================
# 12. Web 티어 EC2 — nginx(리버스프록시) + cloudflared(터널) + 판단 서비스(auth_gate.py)
#    인터넷과 직접 마주하는 유일한 계층. nginx가 앱에 넘기기 전에 판단 서비스에 먼저 묻는다(auth_request).
# ==========================================
resource "aws_instance" "web_server" {
  # ModSecurity nginx 모듈 패키지 때문에 웹 서버만 Ubuntu 24.04(network.tf ubuntu_noble)
  ami                  = data.aws_ami.ubuntu_noble.id
  instance_type        = "t3.micro"
  subnet_id            = aws_subnet.web_subnet.id
  availability_zone    = "ap-northeast-2a"
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  # [IMDSv2 강제] 서버 안에서 임시 IAM 키를 가져올 때 토큰(세션)을 먼저 받아야 하게 한다.
  # v1은 주소만 알면 누구나 키를 가져갈 수 있어, 앱이 속아서 대신 요청해 주는 SSRF에 키가 유출될 수 있다.
  # (AWS 권장: EC2 User Guide "Use IMDSv2"). hop_limit 1 = 서버 밖(컨테이너 등)으로 토큰이 넘어가지 않게 함.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

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
    # [Web->WAS mTLS] 부팅 때 SSM에서 받을 클라이언트 인증서(mtls.tf)
    aws_region        = var.aws_region
    mtls_param_prefix = local.mtls_param_prefix

    # [판단 서비스] nginx auth_request가 요청마다 묻는 auth_gate.py와 모듈(zt_jwt, zt_risk, zt_waf)은
    # user_data에 넣지 않고 S3에서 받는다(code_bucket.tf, 16KB 한도). 계획 단계에서 알 수 있는 값만 넣는다.
    code_bucket      = local.code_bucket_name
    web_code_version = md5(join(",", [for k in sort(keys(local.web_code_files)) : filemd5(local.web_code_files[k])]))
    # [WAF] 동작 모드, CRS 버전(커밋 해시로 고정)
    waf_engine_mode = var.waf_engine_mode
    crs_version     = "v3.3.9"
    crs_commit      = "29240641f78ddb535313eec2a322a89e6520b7e5"
    pdp_evaluate_url       = "${aws_apigatewayv2_stage.pdp_stage.invoke_url}evaluate"
    evaluate_shared_secret = var.evaluate_shared_secret
    cf_team_domain         = var.cloudflare_team_domain
    cf_access_auds = join(",", [
      cloudflare_zero_trust_access_application.portal.aud,
      cloudflare_zero_trust_access_application.dev.aud,
      cloudflare_zero_trust_access_application.marketing.aud,
      cloudflare_zero_trust_access_application.hr.aud,
      cloudflare_zero_trust_access_application.admin_console.aud,
    ])
    # [관제] Filebeat 설치 스크립트(elk.tf, enable_elk=false면 빈 문자열)
    filebeat_setup = local.filebeat_setup.web
  }))

  tags = {
    Name = "ZT-Web-Server"
  }

  # 부팅 스크립트가 SSM에서 인증서를 읽으므로, 파라미터와 읽기 권한이 먼저 만들어져 있어야 한다.
  # 코드는 S3에서 받으므로 코드 파일과 읽기 권한도 먼저 있어야 한다.
  depends_on = [aws_ssm_parameter.mtls_key, aws_ssm_parameter.mtls_cert, aws_ssm_parameter.mtls_ca_cert, aws_iam_role_policy.mtls_read,
  aws_s3_object.web_code, aws_iam_role_policy.web_code_read, aws_ssm_parameter.elk_cert, aws_ssm_parameter.elk_key, aws_iam_role_policy.elk_beats_read]

  lifecycle {
    create_before_destroy = true

    # user_data 설정 방식을 user_data -> user_data_base64로 바꾼 첫 apply에서 Terraform이 이 서버를
    # 교체하지 않고 제자리 수정(in-place)으로 계획해, 새 부팅 스크립트(판단 서비스/nginx)가 실행되지
    # 않는 문제가 있었음. 또 app_server가 교체되면 사설 IP가 바뀌므로 nginx/cloudflared 설정도
    # 새로 만들어야 함. app_server가 교체될 때 web_server도 항상 같이 교체되게 묶어 둠.
    # auth_server도 마찬가지: 아래 cloudflared 로컬 config.yml에 auth 서버의 사설 IP가 적혀 있어서, auth_server가 교체되는데
    # web_server가 제자리 수정(user_data만 바뀌고 부팅 스크립트는 다시 실행되지 않음)으로 계획되면 auth.xmcda.store가 옛 IP로
    # 가서 로그인이 멈춘다(2026-10-12 plan에서 발견). 그래서 auth_server 교체 때도 같이 교체되게 묶는다.
    replace_triggered_by = [aws_instance.app_server, aws_instance.auth_server]
  }
}
