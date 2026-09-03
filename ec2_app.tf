# ==========================================
# 11. App 티어 EC2 — Flask (로그인서버 로직 포함 예정)
#    코드는 app.py 외부 파일에서 관리, main.tf/compute.tf는 참조만 함 (Lambda와 동일 원칙)
# ==========================================
resource "aws_instance" "app_server" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = "t3.micro"
  subnet_id             = aws_subnet.app_subnet.id
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  vpc_security_group_ids = [aws_security_group.app_sg.id]

  user_data_replace_on_change = true

  user_data = templatefile("${path.module}/templates/user_data_app.sh.tpl", {
    app_code    = file("${path.module}/app.py")
    db_host     = aws_db_instance.login_db.address
    db_name     = aws_db_instance.login_db.db_name
    db_user     = aws_db_instance.login_db.username
    db_password = random_password.db_master_password.result
  })

  tags = {
    Name = "ZT-App-Server"
  }

  lifecycle {
    create_before_destroy = true
  }
}
