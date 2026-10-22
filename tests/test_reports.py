import unittest
from report_generator import build_report, compare_reports, report_to_html, report_to_json

class ReportTests(unittest.TestCase):
    def finding(self, rule="CLG001"):
        return {"rule_id": rule, "title": "Example", "severity": "High", "file": "main.tf",
                "resource": "aws_security_group.demo", "message": "Example",
                "recommendation": "Review", "source": "CloudLeak Guard"}

    def test_summary_and_metadata(self):
        report = build_report([self.finding()], {"files_scanned": 1}, "test")
        self.assertEqual(report["summary"]["total"], 1)
        self.assertIn("generated_at", report)

    def test_old_list_report_supported(self):
        result = compare_reports([self.finding()], build_report([self.finding()], {}, "test"))
        self.assertEqual(len(result["remaining"]), 1)

    def test_introduced_and_resolved(self):
        result = compare_reports(build_report([self.finding("OLD")]), build_report([self.finding("NEW")]))
        self.assertEqual(len(result["resolved"]), 1)
        self.assertEqual(len(result["introduced"]), 1)

    def test_html_escapes_content(self):
        report = build_report([{**self.finding(), "title": "<script>alert(1)</script>"}])
        self.assertNotIn("<script>alert(1)</script>", report_to_html(report))
        self.assertIn("&lt;script&gt;", report_to_html(report))

    def test_json_export(self):
        self.assertIn('"report_version": 1', report_to_json(build_report([self.finding()])))

if __name__ == "__main__":
    unittest.main()
