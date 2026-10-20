import tempfile
import unittest
from pathlib import Path
from scanner import custom_scan
from report_generator import compare_findings

class ScannerTests(unittest.TestCase):
    def test_risky_sample_detects_open_ssh_and_missing_tags(self):
        root = Path(__file__).resolve().parents[1] / "samples" / "risky"
        _, findings = custom_scan(root)
        rule_ids = {f["rule_id"] for f in findings}
        self.assertIn("CLG-AWS-SSH-OPEN", rule_ids)
        self.assertIn("CLG-TAGS-REQUIRED", rule_ids)

    def test_safe_sample_has_no_open_ssh(self):
        root = Path(__file__).resolve().parents[1] / "samples" / "safe"
        _, findings = custom_scan(root)
        self.assertNotIn("CLG-AWS-SSH-OPEN", {f["rule_id"] for f in findings})

    def test_compare_reports(self):
        before = [{"rule_id":"R1","file":"main.tf","title":"Issue"}]
        after = [{"rule_id":"R2","file":"main.tf","title":"New issue"}]
        result = compare_findings(before, after)
        self.assertEqual(len(result["resolved"]), 1)
        self.assertEqual(len(result["introduced"]), 1)

if __name__ == "__main__":
    unittest.main()
