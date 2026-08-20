# ==========================================
# 0. Provider 및 기본 설정
# ==========================================
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# ==========================================
# 1. AWS DynamoDB (Trust Score & Audit Log)
# ==========================================
resource "aws_dynamodb_table" "trust_score_log" {
  name         = "trust_score_log"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"
  range_key    = "timestamp"

  attribute {
    name = "session_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "N"
  }

  tags = {
    Environment = "ZeroTrust-Project"
  }
}

# ==========================================
# ==========================================
# 2. EC2 Web Server (Target App)
# ==========================================
# 서울 리전 최신 Ubuntu 22.04 LTS AMI 동적 조회
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical (Ubuntu 공식 소유자 ID)

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "web_sg" {
  name        = "zero_trust_web_sg"
  description = "Security group for ZT Web App (Outbound only for Cloudflare Tunnel)"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web_app" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.web_sg.id]

  user_data = <<-EOF
              #!/bin/bash
              apt update -y
              apt install -y python3-pip
              pip3 install flask
              cat << 'APP' > /home/ubuntu/app.py
              from flask import Flask
              app = Flask(__name__)

              @app.route('/general')
              def general():
                  return "<h1>[General Tier] Access Granted (Threshold: 50)</h1>"

              @app.route('/profile')
              def profile():
                  return "<h1>[Profile Tier] Access Granted (Threshold: 70)</h1>"

              @app.route('/admin')
              def admin():
                  return "<h1>[Admin Tier] Access Granted (Threshold: 80)</h1>"

              if __name__ == '__main__':
                  app.run(host='0.0.0.0', port=8080)
              APP
              nohup python3 /home/ubuntu/app.py > /home/ubuntu/app.log 2>&1 &
              EOF

  tags = {
    Name = "ZT-Target-WebApp"
  }
}