# ==========================================
# 7. 전용 VPC + 3-Tier 서브넷 (Web / App / DB)
# ==========================================
resource "aws_vpc" "zt_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "ZT-VPC"
  }
}

resource "aws_internet_gateway" "zt_igw" {
  vpc_id = aws_vpc.zt_vpc.id

  tags = {
    Name = "ZT-IGW"
  }
}

# --- Web 티어 서브넷 (퍼블릭: cloudflared가 Cloudflare로 아웃바운드 연결) ---
resource "aws_subnet" "web_subnet" {
  vpc_id                  = aws_vpc.zt_vpc.id
  cidr_block               = "10.0.1.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = true

  tags = {
    Name = "ZT-Web-Subnet"
  }
}

# --- App 티어 서브넷 (퍼블릭: Lambda API Gateway 호출을 위한 아웃바운드 필요.
#     NAT Gateway 비용을 피하기 위한 8주 프로젝트 단순화. 인바운드는 SG로 web_sg만 허용) ---
resource "aws_subnet" "app_subnet" {
  vpc_id                  = aws_vpc.zt_vpc.id
  cidr_block               = "10.0.2.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = true

  tags = {
    Name = "ZT-App-Subnet"
  }
}

# --- DB 티어 서브넷 (프라이빗: 인터넷 라우트 없음. RDS는 최소 2개 AZ 서브넷 필요) ---
resource "aws_subnet" "db_subnet_a" {
  vpc_id            = aws_vpc.zt_vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "ap-northeast-2a"

  tags = {
    Name = "ZT-DB-Subnet-A"
  }
}

resource "aws_subnet" "db_subnet_c" {
  vpc_id            = aws_vpc.zt_vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "ap-northeast-2c"

  tags = {
    Name = "ZT-DB-Subnet-C"
  }
}

# --- 라우팅: Web/App만 인터넷 게이트웨이로 나갈 수 있음 ---
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.zt_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.zt_igw.id
  }

  tags = {
    Name = "ZT-Public-RT"
  }
}

resource "aws_route_table_association" "web_assoc" {
  subnet_id      = aws_subnet.web_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "app_assoc" {
  subnet_id      = aws_subnet.app_subnet.id
  route_table_id = aws_route_table.public_rt.id
}
# db_subnet_a / db_subnet_c는 기본 라우트 테이블(인터넷 라우트 없음) 그대로 사용 → 프라이빗 유지

# ==========================================
# 8. Security Group — 계층 간 통신 제한
# ==========================================

# Web 티어: 인바운드는 필요 없음 (Cloudflare Tunnel이 EC2 → Cloudflare로 아웃바운드 연결만 함).
#           App 티어(8080)로만 나갈 수 있게 egress 제한.
resource "aws_security_group" "web_sg" {
  name_prefix = "zt-web-sg-"
  description = "Web tier: cloudflared 아웃바운드 전용, App 티어로만 egress"
  vpc_id      = aws_vpc.zt_vpc.id

  egress {
    description = "Outbound HTTPS for Cloudflare and package install"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Outbound HTTP for apt package install"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "ZT-Web-SG"
  }
}

# App 티어: 인바운드는 오직 Web 티어(SG 참조)에서만 8080 허용.
#           DB 티어(3306)와 인터넷(Lambda 호출, apt)로만 egress.
resource "aws_security_group" "app_sg" {
  name_prefix = "zt-app-sg-"
  description = "App tier: Web 티어에서만 인바운드, DB 티어/인터넷으로만 egress"
  vpc_id      = aws_vpc.zt_vpc.id

  egress {
    description = "Outbound HTTPS for Lambda API Gateway and package install"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Outbound HTTP for apt package install"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "ZT-App-SG"
  }
}

# DB 티어: 인바운드는 오직 App 티어(SG 참조)에서만 3306 허용. Web 티어는 SG 규칙 자체가
#          없어 원천적으로 DB에 접근 불가 — 이게 3-Tier 격리의 핵심.
resource "aws_security_group" "db_sg" {
  name_prefix = "zt-db-sg-"
  description = "DB tier: App 티어에서만 인바운드 허용, Web 티어는 접근 불가"
  vpc_id      = aws_vpc.zt_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "ZT-DB-SG"
  }
}

# ==========================================
# 8-1. SG 간 참조 규칙 (별도 리소스로 분리 — 인라인으로 넣으면 web_sg/app_sg/db_sg가
#      서로를 참조하며 순환 참조 에러(Cycle)가 발생하므로, SG 본체는 서로 모르는 채로
#      먼저 만들고 이 규칙들이 나중에 둘을 이어줌)
# ==========================================
resource "aws_vpc_security_group_egress_rule" "web_to_app" {
  security_group_id           = aws_security_group.web_sg.id
  referenced_security_group_id = aws_security_group.app_sg.id
  description                 = "Allow proxy to App tier Flask on 8080"
  from_port                   = 8080
  to_port                     = 8080
  ip_protocol                 = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "app_from_web" {
  security_group_id           = aws_security_group.app_sg.id
  referenced_security_group_id = aws_security_group.web_sg.id
  description                 = "Allow Flask 8080 access from Web tier only"
  from_port                   = 8080
  to_port                     = 8080
  ip_protocol                 = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "app_to_db" {
  security_group_id           = aws_security_group.app_sg.id
  referenced_security_group_id = aws_security_group.db_sg.id
  description                 = "Allow access to DB tier MySQL on 3306"
  from_port                   = 3306
  to_port                     = 3306
  ip_protocol                 = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id           = aws_security_group.db_sg.id
  referenced_security_group_id = aws_security_group.app_sg.id
  description                 = "Allow MySQL 3306 access from App tier only"
  from_port                   = 3306
  to_port                     = 3306
  ip_protocol                 = "tcp"
}

# ==========================================
# 10. EC2 AMI (공용)
# ==========================================
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}
