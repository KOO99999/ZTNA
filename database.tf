# ==========================================
# 9. DB 티어 — RDS MySQL (로그인서버 사용자 계정 데이터)
#    담는 데이터: 계정(email, password_hash), totp_secret, totp_enabled,
#    backup_codes(해시), 로그인 실패기록(brute_force 슬라이딩 윈도우용), role
#    ※ RDS로 우선 시작 — 추후 EC2 직접 설치(MySQL)로 전환 가능 (mysqldump로 이관)
# ==========================================
resource "aws_db_subnet_group" "login_db_subnet_group" {
  name       = "zt-login-db-subnet-group"
  subnet_ids = [aws_subnet.db_subnet_a.id, aws_subnet.db_subnet_c.id]

  tags = {
    Name = "ZT-LoginDB-SubnetGroup"
  }
}

resource "random_password" "db_master_password" {
  length  = 24
  special = false # RDS 마스터 비밀번호 특수문자 제약 회피용
}

resource "aws_db_instance" "login_db" {
  identifier     = "zt-login-db"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  storage_type       = "gp2"

  db_name  = "login_server"
  username = "zt_admin"
  password = random_password.db_master_password.result

  db_subnet_group_name   = aws_db_subnet_group.login_db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  publicly_accessible     = false

  skip_final_snapshot = true # 8주 프로젝트 범위: 운영환경이라면 false + 스냅샷 정책 필요

  tags = {
    Name = "ZT-Login-DB"
  }
}

# 마스터 비밀번호는 state 파일에 평문으로 남으므로, 팀 내부적으로만 공유하고
# git에는 절대 커밋하지 말 것 (terraform.tfstate는 .gitignore 확인 필수)
output "login_db_endpoint" {
  value       = aws_db_instance.login_db.endpoint
  description = "App 티어 Flask가 접속할 RDS 엔드포인트"
}
