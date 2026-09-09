# ==========================================
# 11. Portal 티어 EC2 — Flask (포털/부서 페이지/관리자 콘솔)
#    로그인 로직은 auth_server(ec2_auth.tf)로 분리됨 - 이 서버는 DB 연결이 필요 없음
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
    app_code = file("${path.module}/portal_app.py")
  }))

  tags = {
    Name = "ZT-Portal-Server"
  }

  lifecycle {
    create_before_destroy = true
  }
}
