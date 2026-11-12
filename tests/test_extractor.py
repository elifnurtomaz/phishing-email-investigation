
import csv
import subprocess
import sys
import unittest

from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
SCRIPT = PROJECT_DIR / "scripts" / "extract_iocs.py"

FIXTURE = (
    PROJECT_DIR
    / "tests"
    / "fixtures"
    / "synthetic-email-01.eml"
)

REPORTS_DIR = PROJECT_DIR / "reports"


def run_extractor(email_file):
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            email_file
        ],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True
    )


def read_report(filename):
    report_path = REPORTS_DIR / filename

    with report_path.open(
        "r",
        newline="",
        encoding="utf-8-sig"
    ) as file:
        return list(csv.DictReader(file))


class TestEmailIOCExtractor(unittest.TestCase):

    def test_synthetic_email_extraction(self):

        result = run_extractor(
            "tests/fixtures/synthetic-email-01.eml"
        )

        self.assertEqual(result.returncode, 0)

        records = read_report(
            "synthetic-email-01_ioc_extraction.csv"
        )

        self.assertEqual(len(records), 10)

    def test_expected_indicators(self):

        run_extractor(
            "tests/fixtures/synthetic-email-01.eml"
        )

        records = read_report(
            "synthetic-email-01_ioc_extraction.csv"
        )

        indicators = {
            (
                record["Indicator_Type"],
                record["Indicator_Value_Defanged"]
            )
            for record in records
        }

        expected = {
            ("Email Address", "alerts@sender[.]example"),
            ("Email Address", "analyst@example[.]net"),
            ("Email Address", "bounce@sender[.]example"),
            ("Domain", "sender[.]example"),
            ("Domain", "example[.]net"),
            ("URL", "hxxps://login[.]example[.]com/account"),
            ("Hostname", "login[.]example[.]com"),
            ("URL", "hxxps://images[.]example[.]net/logo.png"),
            ("Hostname", "images[.]example[.]net"),
            ("IPv4", "192.0.2.10")
        }

        self.assertTrue(expected.issubset(indicators))

    def test_html_attribute_identification(self):

        run_extractor(
            "tests/fixtures/synthetic-email-01.eml"
        )

        records = read_report(
            "synthetic-email-01_ioc_extraction.csv"
        )

        url_locations = {
            record["Indicator_Value_Defanged"]:
            record["Evidence_Location"]
            for record in records
            if record["Indicator_Type"] == "URL"
        }

        self.assertEqual(
            url_locations["hxxps://login[.]example[.]com/account"],
            "HTML href attribute"
        )

        self.assertEqual(
            url_locations["hxxps://images[.]example[.]net/logo.png"],
            "HTML src attribute"
        )

    def test_unique_indicators(self):

        run_extractor(
            "tests/fixtures/synthetic-email-01.eml"
        )

        records = read_report(
            "synthetic-email-01_ioc_extraction.csv"
        )

        unique_indicators = {
            (
                record["Indicator_Type"],
                record["Indicator_Value_Defanged"]
            )
            for record in records
        }

        self.assertEqual(
            len(records),
            len(unique_indicators)
        )

    def test_missing_email_file(self):

        result = run_extractor(
            "samples/nonexistent.eml"
        )

        self.assertNotEqual(result.returncode, 0)

        self.assertIn(
            "Email file not found",
            result.stderr
        )


if __name__ == "__main__":
    unittest.main()
