provider "aws" {
  region = "us-east-1"
}

#########################
# S3 - 다양한 보안 누락
#########################

resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "insecure-dev-bucket"
  acl    = "public-read"  # 🚨 CRITICAL: 퍼블릭 접근 허용

  versioning {
    enabled = false       # ⚠️ MEDIUM: 버전 관리 비활성화
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"  # ⚠️ HIGH: CMK 미사용
      }
    }
  }

  tags = {
    Owner = "dev"
  }
}

# 🚨 CRITICAL: 퍼블릭 접근 차단 설정 누락
# aws_s3_bucket_public_access_block 리소스 없음

##############################
# Security Group - 오픈된 포트
##############################

resource "aws_security_group" "open_sg" {
  name        = "open-sg"
  description = "Allow all traffic from anywhere"
  vpc_id      = "vpc-xxxxxxxx"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # 🚨 CRITICAL: SSH 포트 전체 공개
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ⚠️ HIGH: HTTP 전체 공개
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # ⚠️ MEDIUM: 모든 outbound 허용
  }

  # ❗ LOW: 보안 그룹 규칙 description 없음
}

#########################
# IAM - 과도한 권한 부여
#########################

resource "aws_iam_policy" "too_much_power" {
  name = "allow-everything"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = "*",          # 🚨 CRITICAL: 전체 권한 허용
        Effect   = "Allow",
        Resource = "*"           # 🚨 CRITICAL: 모든 리소스
      }
    ]
  })
}

  