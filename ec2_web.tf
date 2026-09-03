# ==========================================
# 12. Web 티어 EC2 — nginx(리버스프록시) + cloudflared(터널)
#    인터넷과 직접 마주하는 유일한 계층. App 티어 민감 로직은 여기 없음.
# ==========================================
resource "aws_instance" "web_server" {
  ami               = data.aws_ami.ubuntu.id
  instance_type     = "t3.micro"
  subnet_id         = aws_subnet.web_subnet.id
  availability_zone = "ap-northeast-2a"

  vpc_security_group_ids = [aws_security_group.web_sg.id]

  user_data_replace_on_change = true

  user_data = templatefile("${path.module}/templates/user_data_web.sh.tpl", {
    app_private_ip = aws_instance.app_server.private_ip
    tunnel_token   = cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.tunnel_token
  })

  tags = {
    Name = "ZT-Web-Server"
  }

  lifecycle {
    create_before_destroy = true
  }
}
