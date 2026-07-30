import csv
import io
import re
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import psreadline


class EventlogsDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (REPO_ROOT / "csv" / "Eventlogs.csv").open(
                newline="", encoding="utf-8") as handle:
            cls.rows = list(csv.DictReader(handle))
        cls.rules = {row["id"]: row for row in cls.rows}

    def test_event_log_clear_covers_security_and_system_logs(self):
        rule = self.rules["win_eventlog_clear"]
        self.assertEqual(
            rule["eventlog"],
            "{Security.evtx,System.evtx}")
        self.assertEqual(rule["eventid"], "^(104|1102)$")

    def test_tcp_socket_rule_id_is_stable(self):
        self.assertIn("win_powershell_tcpsocket", self.rules)
        self.assertNotIn("win_powershell_tcpsocket^(4103|4104)$", self.rules)

    def test_psreadline_selection_uses_eventlog_column(self):
        lookup = psreadline.build_powershell_lookup_table(
            REPO_ROOT / "csv" / "Eventlogs.csv")
        selected = list(csv.DictReader(io.StringIO(lookup)))
        selected_ids = {row["id"] for row in selected}

        self.assertEqual(len(selected), 16)
        self.assertNotIn("win_sus_service", selected_ids)
        self.assertNotIn("win_powershell_large_b64", selected_ids)
        self.assertIn("win_powershell_encoded_command", selected_ids)

    def test_encoded_command_requires_base64_payload(self):
        rule = re.compile(
            self.rules["win_powershell_encoded_command"]["rule"],
            re.IGNORECASE)
        payload = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="

        for command in (
                f"powershell.exe -e {payload}",
                f"powershell.exe -enc {payload}",
                f"powershell.exe -EncodedCommand '{payload}'"):
            with self.subTest(command=command):
                self.assertRegex(command, rule)

        for command in (
                "Get-Content -Encoding UTF8 file.txt",
                "ForEach-Object -End { Write-Host done }",
                "powershell.exe -enc not-base64"):
            with self.subTest(command=command):
                self.assertNotRegex(command, rule)

    def test_base64_api_rule_does_not_match_encoding_parameter(self):
        rule = re.compile(
            self.rules["win_powershell_base64"]["rule"],
            re.IGNORECASE)
        self.assertRegex("[Convert]::FromBase64String($value)", rule)
        self.assertRegex("[convert]::frombase64string($value)", rule)
        self.assertNotRegex("Set-Content -Encoding UTF8 output.txt", rule)

    def test_csv_has_no_inline_case_insensitive_flags(self):
        self.assertEqual(len(self.rows), 27)
        for row in self.rows:
            for field in ("eventid", "rule", "ignore"):
                with self.subTest(rule=row["id"], field=field):
                    self.assertNotIn("(?i)", row[field])


if __name__ == "__main__":
    unittest.main()
