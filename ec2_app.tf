# ==========================================
# 11. App 티어 EC2 — Flask (로그인서버 로직 포함 예정)
#    코드는 app.py 외부 파일에서 관리, main.tf/compute.tf는 참조만 함 (Lambda와 동일 원칙)
# ==========================================
resource "aws_instance" "app_server" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = "t3.micro"
  subnet_id            = aws_subnet.app_subnet.id
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  vpc_security_group_ids = [aws_security_group.app_sg.id]

  user_data_replace_on_change = true

  # AWS EC2 user_data는 16,384바이트 제한이 있는데, app.py가 커지면서(로그인서버 라우트
  # 추가 등) 이 한도를 넘어서게 됨. base64gzip()으로 압축해서 넘기면 cloud-init이 부팅 시
  # 자동으로 압축을 풀어 실행함 — 앞으로 코드가 더 늘어나도 여유가 생기는 표준적인 해결법.
  # (user_data와 user_data_base64는 동시에 쓸 수 없어 user_data_base64로 전환)
  user_data_base64 = base64gzip(templatefile("${path.module}/templates/user_data_app.sh.tpl", {
    app_code    = file("${path.module}/app.py")
    db_host     = aws_db_instance.login_db.address
    db_name     = aws_db_instance.login_db.db_name
    db_user     = aws_db_instance.login_db.username
    db_password = random_password.db_master_password.result
    # /authorize가 로그인 시도 자체의 위험도를 Lambda에 직접 물어볼 때 필요한 값
    # (Worker를 거치지 않고 직접 호출 — 기존 /evaluate 공유 비밀키 인증 그대로 재사용)
    pdp_evaluate_url        = "${aws_apigatewayv2_stage.pdp_stage.invoke_url}evaluate"
    evaluate_shared_secret  = random_password.evaluate_shared_secret.result
    domain_name             = var.domain_name
  }))

  tags = {
    Name = "ZT-App-Server"
  }

  lifecycle {
    create_before_destroy = true
  }
}
