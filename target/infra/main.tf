# AutoTriage sample target -- INTENTIONALLY INSECURE Terraform (test fixture).
# DO NOT DEPLOY. Planted: public S3 ACL (CWE-732), no SSE (CWE-311), open SSH (CWE-284).

resource "aws_s3_bucket" "data" {
  bucket = "autotriage-sample-data-bucket"
  acl    = "public-read"
}

# Separate ACL resource form (also world-readable) -- VULN CWE-732.
resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

# Security group opening SSH (port 22) to the entire internet -- VULN CWE-284.
resource "aws_security_group" "ssh" {
  name = "autotriage-ssh"

  ingress {
    # Open to the entire internet:
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
  }
}
