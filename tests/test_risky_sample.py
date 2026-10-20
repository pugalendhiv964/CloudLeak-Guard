
import shutil
import subprocess
import unittest


class RiskyTerraformSampleTest(unittest.TestCase):

    def test_checkov_detects_risky_configuration(self):
        checkov_executable = shutil.which("checkov")

        self.assertIsNotNone(
            checkov_executable,
            "Checkov is not installed or is not available on PATH.",
        )

        result = subprocess.run(
            [
                checkov_executable,
                "-d",
                "samples/risky",
                "--framework",
                "terraform",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        output = result.stdout + result.stderr

        self.assertTrue(
            "Check: CKV_" in output or "FAILED" in output,
            "Checkov did not report any failed security checks.\n" + output,
        )


if __name__ == "__main__":
    unittest.main()
