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

# [WAS->DB TLS 강제] 암호화되지 않은 접속은 DB 서버가 거부한다(오류 3159).
# AWS 문서: require_secure_transport를 DB 파라미터 그룹에서 ON으로 바꾸면 되고 재부팅은 필요 없다.
resource "aws_db_parameter_group" "login_db_params" {
  name_prefix = "zt-login-db-"
  family      = "mysql8.0"
  description = "ZT login DB: require TLS for all connections"

  parameter {
    name  = "require_secure_transport"
    value = "ON"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# [DB 최소권한] 앱(로그인 서버) 전용 DB 계정 비밀번호. 계정은 auth 서버 부팅 스크립트가 마스터 계정으로 만든다
# (auth_app.py ensure_app_db_user: 행 읽기/쓰기만, REQUIRE SSL, 앱 서브넷에서만 접속).
resource "random_password" "db_app_password" {
  length  = 32
  special = false
}

resource "aws_db_instance" "login_db" {
  identifier     = "zt-login-db"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  storage_type      = "gp2"

  db_name  = "login_server"
  username = "zt_admin"
  password = random_password.db_master_password.result

  db_subnet_group_name   = aws_db_subnet_group.login_db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  parameter_group_name   = aws_db_parameter_group.login_db_params.name
  publicly_accessible    = false

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
