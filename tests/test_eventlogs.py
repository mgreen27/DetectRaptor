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

        self.assertEqual(len(selected), 17)
        self.assertNotIn("win_sus_service", selected_ids)
        self.assertIn("win_powershell_encoded_command", selected_ids)

    def test_encoded_command_requires_base64_payload(self):
        rule = re.compile(self.rules["win_powershell_encoded_command"]["rule"])
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
        rule = re.compile(self.rules["win_powershell_base64"]["rule"])
        self.assertRegex("[Convert]::FromBase64String($value)", rule)
        self.assertNotRegex("Set-Content -Encoding UTF8 output.txt", rule)

    def test_large_base64_requires_decode_context(self):
        rule = re.compile(self.rules["win_powershell_large_b64"]["rule"])
        payload = (
            "UABvAHcAZQByAFMAaABlAGwAbAAgAEQAZQB0AGUAYwB0AFIAYQ"
            "BwAHQAbwByAA==")

        self.assertRegex(
            f"[Convert]::FromBase64String('{payload}')",
            rule)
        self.assertNotRegex(f"# {payload}", rule)
        self.assertNotRegex(
            "C:/Python/site-packages/"
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV",
            rule)


if __name__ == "__main__":
    unittest.main()
