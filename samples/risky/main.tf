terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
provider "aws" {
  region = "ap-south-1"
}
resource "aws_security_group" "demo" {
  name        = "demo-open-ssh"
  description = "Risky demo security group"
  ingress {
    from_port   = 22
    to_port     = 22
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
resource "aws_s3_bucket" "demo" {
  bucket = "cloudleak-guard-demo-bucket-change-this-name"
}
resource "aws_instance" "demo" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "m8.24xlarge"
}
