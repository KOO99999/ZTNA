# main.tf (v1.0)
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-northeast-2"
}

# 웹 서버용 보안 그룹
resource "aws_security_group" "web_sg" {
  name        = "ztna-web-sg"
  description = "Security Group for ZTNA Target App"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EC2 인스턴스 (하드코딩된 AMI)
resource "aws_instance" "web_app" {
  ami                    = "ami-0c9c93b21703632ef" # 하드코딩된 AMI ID
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web_sg.id]

  tags = {
    Name = "ZTNA-Target-WebServer"
  }
}