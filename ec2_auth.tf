# ==========================================
# 13. Auth 티어 EC2 — Flask 로그인서버 전용
#    /authorize, /token, /userinfo, /.well-known/jwks.json, /logout만 존재.
#    /admin 등 다른 라우트가 코드 자체에 없어서, 실수로 auth.xmcda.store로
#    관리자 페이지에 접근하려 해도 물리적으로 불가능함 (nginx 설정 실수에 의존하지 않음)
# ==========================================
resource "aws_instance" "auth_server" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = "t3.micro"
  subnet_id            = aws_subnet.app_subnet.id
  iam_instance_profile = aws_iam_instance_profile.auth_profile.name

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

  user_data_base64 = base64gzip(templatefile("${path.module}/templates/user_data_auth.sh.tpl", {
    # 앱 코드는 user_data에 넣지 않고 S3에서 받는다(code_bucket.tf, user_data 16KB 한도).
    # 코드 버전(해시)을 넣어 두면 코드가 바뀔 때 user_data가 바뀌어 서버가 새로 만들어진다.
    code_bucket       = aws_s3_bucket.app_code.id
    auth_code_version = md5(join(",", [for k in sort(keys(local.auth_code_files)) : aws_s3_object.auth_code[k].etag]))
    db_host     = aws_db_instance.login_db.address
    db_name     = aws_db_instance.login_db.db_name
    # 앱 서비스가 쓰는 DB 계정 = 앱 전용 계정(행 읽기/쓰기만). 마스터 계정은 부팅 단계(bootstrap)에서만 쓴다.
    app_db_user     = "zt_auth_app"
    app_db_password = random_password.db_app_password.result
    # 앱 계정이 접속할 수 있는 위치 = 앱 서브넷(MySQL 'IP/넷마스크' 형식, 예: 10.0.2.0/255.255.255.0)
    app_db_host = "${cidrhost(aws_subnet.app_subnet.cidr_block, 0)}/${cidrnetmask(aws_subnet.app_subnet.cidr_block)}"
    master_db_user     = aws_db_instance.login_db.username
    master_db_password = random_password.db_master_password.result

    pdp_evaluate_url        = "${aws_apigatewayv2_stage.pdp_stage.invoke_url}evaluate"
    evaluate_shared_secret  = var.evaluate_shared_secret
    domain_name             = local.auth_domain
    oidc_client_id          = var.oidc_client_id
    oidc_client_secret      = var.oidc_client_secret

    # 자원(앱 호스트)별로 열 수 있는 소속 표(main.tf locals). /stepup이 "권한 없음" 안내 화면을 고를 때만 쓰며,
    # 접근 허용/차단을 정하는 값이 아니다(실제 차단은 Access 정책과 앞단 판단 서비스가 함).
    path_permissions = local.path_permissions_env
    # 보호 대상 앱 호스트 목록(main.tf locals.app_hosts). 복귀 주소 허용 목록과 로그아웃할 앱 목록으로 쓴다.
    app_hosts = local.app_hosts_env
    # 서버 시작 때 DB 소속(accounts.department)을 맞추는 목록(main.tf locals). 컬럼이 없으면 같이 추가한다.
    account_departments = local.account_departments_env
    # 서버 시작 때 이 SSM 파라미터(SecureString, Terraform 밖에서 관리)에서 계정 정보를 읽어 DB에 없는 계정을 만든다(auth_seed.tf).
    seed_param_name = local.seed_param_name
    # [Web->WAS mTLS] 부팅 때 SSM에서 받을 인증서(mtls.tf)와, 받아 줄 클라이언트(웹 서버) 인증서 이름
    mtls_role           = "auth"
    mtls_param_prefix   = local.mtls_param_prefix
    mtls_allowed_client = local.mtls_names.web
    aws_region      = var.aws_region
  }))

  tags = {
    Name = "ZT-Auth-Server"
  }

  # 부팅 스크립트가 SSM에서 인증서를 읽으므로, 파라미터와 읽기 권한이 먼저 만들어져 있어야 한다.
  # 코드는 S3에서 받으므로 코드 파일과 읽기 권한도 먼저 있어야 한다.
  depends_on = [aws_ssm_parameter.mtls_key, aws_ssm_parameter.mtls_cert, aws_ssm_parameter.mtls_ca_cert, aws_iam_role_policy.mtls_read,
  aws_s3_object.auth_code, aws_iam_role_policy.auth_code_read]

  lifecycle {
    create_before_destroy = true
  }
}
