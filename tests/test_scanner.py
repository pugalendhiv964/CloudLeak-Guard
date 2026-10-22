import unittest
from scanner import _custom_scan

class ScannerTests(unittest.TestCase):
    def scan(self, text):
        return _custom_scan(text, "main.tf")

    def test_public_ssh_detected(self):
        text = """
resource "aws_security_group" "bad" {
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        self.assertIn("CLG001", [x["rule_id"] for x in self.scan(text)])

    def test_does_not_mix_rules(self):
        text = """
resource "aws_security_group" "ok" {
  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["203.0.113.5/32"]
  }
}
"""
        self.assertNotIn("CLG001", [x["rule_id"] for x in self.scan(text)])

    def test_large_instance_only(self):
        text = """
resource "aws_instance" "big" { instance_type = "m8.24xlarge" }
resource "aws_instance" "small" { instance_type = "t3.small" }
"""
        results = [x for x in self.scan(text) if x["rule_id"] == "CLG004"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["resource"], "aws_instance.big")

    def test_tags_checked_per_resource(self):
        text = """
resource "aws_instance" "tagged" {
 tags = { Environment = "test", Owner = "team" }
}
resource "aws_instance" "untagged" { instance_type = "t3.small" }
"""
        results = [x for x in self.scan(text) if x["rule_id"] == "CLG003"]
        self.assertEqual([x["resource"] for x in results], ["aws_instance.untagged"])

    def test_separate_s3_encryption_reference(self):
        text = """
resource "aws_s3_bucket" "data" { bucket = "example-data-bucket" }
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
 bucket = aws_s3_bucket.data.id
 rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}
"""
        results = [x for x in self.scan(text) if x["rule_id"] == "CLG002"]
        self.assertEqual(results, [])

if __name__ == "__main__":
    unittest.main()
