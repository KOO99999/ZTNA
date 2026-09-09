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
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  vpc_security_group_ids = [aws_security_group.app_sg.id]

  user_data_replace_on_change = true

  user_data_base64 = base64gzip(templatefile("${path.module}/templates/user_data_auth.sh.tpl", {
    app_code    = file("${path.module}/auth_app.py")
    db_host     = aws_db_instance.login_db.address
    db_name     = aws_db_instance.login_db.db_name
    db_user     = aws_db_instance.login_db.username
    db_password = random_password.db_master_password.result

    pdp_evaluate_url        = "${aws_apigatewayv2_stage.pdp_stage.invoke_url}evaluate"
    evaluate_shared_secret  = var.evaluate_shared_secret
    domain_name             = local.auth_domain
    oidc_client_id          = var.oidc_client_id
    oidc_client_secret      = var.oidc_client_secret
  }))

  tags = {
    Name = "ZT-Auth-Server"
  }

  lifecycle {
    create_before_destroy = true
  }
}
