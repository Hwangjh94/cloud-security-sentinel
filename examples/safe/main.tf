provider "aws" {
  region = "us-east-1"
}

resource "aws_kms_key" "s3_cmk" {
  description         = "Customer managed key for S3 encryption"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "secure_bucket" {
  bucket = "secure-app-storage-bucket"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.s3_cmk.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }

  logging {
    target_bucket = "my-logging-bucket" # 이 버킷은 따로 정의 필요
    target_prefix = "s3-access-logs/"
  }

  tags = {
    Environment = "production"
    Secure      = "true"
  }
}

resource "aws_s3_bucket_public_access_block" "secure_bucket_block" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "web_sg" {
  name        = "web-sg"
  description = "Allow HTTPS only"
  vpc_id      = "vpc-xxxxxxxx"

  ingress {
    description = "Allow HTTPS from internal subnet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "Allow outbound only to internal subnet"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }

  tags = {
    Name = "secure-sg"
  }
}     

    
        