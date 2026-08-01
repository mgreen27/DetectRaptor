import csv
import re
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import build_mft_replay_coverage
import replay_mft


class MFTReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = replay_mft.read_csv(
            REPO_ROOT / "csv" / "MFT.csv")
        cls.cases = replay_mft.read_csv(
            REPO_ROOT / "tests" / "fixtures" / "mft_replay.csv")
        cls.expected = replay_mft.read_csv(
            REPO_ROOT / "tests" / "fixtures" / "mft_expected.csv")
        cls.matches = replay_mft.replay(cls.rules, cls.cases)

    def test_manual_replay_expectations(self):
        self.assertEqual(
            [], replay_mft.validate_case_inventory(
                self.cases, self.expected))
        self.assertEqual(
            [], replay_mft.validate_expected(
                self.matches, self.expected))

        summary = replay_mft.summarize(self.cases, self.matches)
        self.assertEqual(summary["Cases"], 22)
        self.assertEqual(summary["RuleMatches"], 20)
        self.assertEqual(summary["MultiMatchCases"], 2)

    def test_replay_inventory_rejects_missing_and_duplicate_cases(self):
        cases = self.cases + [dict(self.cases[0])]
        expected = self.expected[1:]
        issues = replay_mft.validate_case_inventory(cases, expected)

        self.assertTrue(
            any("Duplicate replay CaseIDs" in issue for issue in issues))
        self.assertTrue(
            any("Replay cases without expectations" in issue
                for issue in issues))

    def test_committed_rule_coverage_is_current(self):
        generated = build_mft_replay_coverage.build_coverage(
            self.rules)
        with (
                REPO_ROOT / "csv" / "MFT_Replay_Coverage.csv"
        ).open(newline="", encoding="utf-8") as handle:
            committed = list(csv.DictReader(handle))

        self.assertEqual(committed, generated)
        self.assertEqual(len(generated), len(self.rules))
        self.assertTrue(
            all(row["Verified"] == "True" for row in generated))

        covered = {row["RuleID"] for row in generated}
        high_confidence = {
            row["RuleID"] for row in self.rules
            if row["Confidence"] == "High"
        }
        self.assertTrue(high_confidence <= covered)

    def test_replay_comparison_reports_added_and_removed_matches(self):
        reduced_rules = [
            rule for rule in self.rules
            if rule["RuleID"] != "DR-MFT-MASQ-002"
        ]
        reduced = replay_mft.replay(reduced_rules, self.cases)

        comparison = replay_mft.compare_matches(self.matches, reduced)

        added = {
            (row["CaseID"], row["RuleID"])
            for row in comparison if row["Change"] == "Added"
        }
        self.assertIn(("MFT-004", "DR-MFT-MASQ-002"), added)

        reverse_comparison = replay_mft.compare_matches(
            reduced, self.matches)
        removed = {
            (row["CaseID"], row["RuleID"])
            for row in reverse_comparison if row["Change"] == "Removed"
        }
        self.assertIn(("MFT-004", "DR-MFT-MASQ-002"), removed)

    def test_fixture_paths_use_only_synthetic_or_standard_users(self):
        allowed_users = {"analyst", "public"}
        for case in self.cases:
            match = re.search(
                r"\\Users\\([^\\]+)", case["OSPath"], re.IGNORECASE)
            if match:
                self.assertIn(match.group(1).casefold(), allowed_users)


if __name__ == "__main__":
    unittest.main()
