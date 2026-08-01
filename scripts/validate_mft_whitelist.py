#!/usr/bin/env python3
"""Validate path-aware MFT and Amcache whitelist policies."""

import argparse
import csv
import datetime
import re
from pathlib import Path

from validate_mft import ALLOWED_SCOPES, _split_top_level_alternatives


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES = REPO_ROOT / "csv" / "MFT.csv"
DEFAULT_WHITELISTS = REPO_ROOT / "csv" / "MFT_Whitelist.csv"

EXPECTED_FIELDS = (
    "WhitelistID",
    "RuleID",
    "Artifact",
    "FilenameRegex",
    "PathRegex",
    "Disposition",
    "Reason",
    "Source",
    "ReviewDate",
)
REQUIRED_FIELDS = EXPECTED_FIELDS
ALLOWED_ARTIFACTS = {"MFT", "Amcache"}
ALLOWED_DISPOSITIONS = {"Suppress"}
WHITELIST_ID_PATTERN = re.compile(r"^DR-MFT-WL-\d{3}$")
RULE_ID_PATTERN = re.compile(
    r"^DR-MFT-[A-Z][A-Z0-9]{2,5}-\d{3}$")
GLOBAL_REGEXES = {".", ".*", "^.*$", "(?:.*)"}


def read_csv(path):
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def _scope_supports_artifact(scope, artifact):
    if scope not in ALLOWED_SCOPES:
        return False
    return scope == "Both" or scope == artifact


def validate_path_pattern(pattern):
    """Return issues for a path policy that is too broad to suppress safely."""
    issues = []
    for alternative in _split_top_level_alternatives(pattern):
        if not alternative.endswith("$"):
            issues.append(
                f"path alternative is not end anchored: {alternative!r}")
        if not (
                alternative.startswith("\\\\")
                or alternative.startswith("^[A-Za-z]:\\\\")):
            issues.append(
                f"path alternative lacks an explicit root: {alternative!r}")
        if alternative.count("\\\\") < 2:
            issues.append(
                f"path alternative lacks a specific directory and "
                f"basename: {alternative!r}")
    return issues


def validate_whitelist(whitelist_path, rules_path=DEFAULT_RULES):
    """Return validation issues for an MFT whitelist CSV."""
    whitelist_path = Path(whitelist_path)
    rules_path = Path(rules_path)
    issues = []

    rules = {row["RuleID"]: row for row in read_csv(rules_path)}
    with whitelist_path.open(
            newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != EXPECTED_FIELDS:
            return [
                "line 1: unexpected whitelist CSV header; expected "
                + ",".join(EXPECTED_FIELDS)
            ]

        seen_ids = {}
        seen_keys = {}
        for line_number, row in enumerate(reader, start=2):
            if None in row or any(value is None for value in row.values()):
                issues.append(
                    f"line {line_number}: row does not contain exactly "
                    f"{len(EXPECTED_FIELDS)} columns")
                continue

            for field in REQUIRED_FIELDS:
                if not row[field].strip():
                    issues.append(
                        f"line {line_number}: required field {field} is empty")

            whitelist_id = row["WhitelistID"].strip()
            if not WHITELIST_ID_PATTERN.fullmatch(whitelist_id):
                issues.append(
                    f"line {line_number}: invalid WhitelistID "
                    f"{whitelist_id!r}")
            elif whitelist_id in seen_ids:
                issues.append(
                    f"line {line_number}: duplicate WhitelistID "
                    f"{whitelist_id!r}; first used on line "
                    f"{seen_ids[whitelist_id]}")
            else:
                seen_ids[whitelist_id] = line_number

            rule_id = row["RuleID"].strip()
            if not RULE_ID_PATTERN.fullmatch(rule_id):
                issues.append(
                    f"line {line_number}: invalid RuleID {rule_id!r}")
            elif rule_id not in rules:
                issues.append(
                    f"line {line_number}: unknown RuleID {rule_id!r}")

            artifact = row["Artifact"]
            if artifact not in ALLOWED_ARTIFACTS:
                issues.append(
                    f"line {line_number}: invalid Artifact {artifact!r}")
            elif rule_id in rules and not _scope_supports_artifact(
                    rules[rule_id]["Scope"], artifact):
                issues.append(
                    f"line {line_number}: RuleID {rule_id!r} with Scope "
                    f"{rules[rule_id]['Scope']!r} does not support "
                    f"Artifact {artifact!r}")

            policy_key = (rule_id, artifact)
            if policy_key in seen_keys:
                issues.append(
                    f"line {line_number}: duplicate RuleID and Artifact "
                    f"policy {policy_key!r}; combine paths into one policy")
            else:
                seen_keys[policy_key] = line_number

            if row["Disposition"] not in ALLOWED_DISPOSITIONS:
                issues.append(
                    f"line {line_number}: invalid Disposition "
                    f"{row['Disposition']!r}")

            for field in ("FilenameRegex", "PathRegex"):
                pattern = row[field].strip()
                if pattern in GLOBAL_REGEXES:
                    issues.append(
                        f"line {line_number}: {field} is overly broad")
                    continue
                try:
                    re.compile(pattern, re.IGNORECASE)
                except re.error as error:
                    issues.append(
                        f"line {line_number}: invalid {field}: {error}")

            if not (
                    row["FilenameRegex"].startswith("^")
                    and row["FilenameRegex"].endswith("$")):
                issues.append(
                    f"line {line_number}: FilenameRegex must be anchored")
            if "\\" not in row["PathRegex"]:
                issues.append(
                    f"line {line_number}: PathRegex must contain a path "
                    "separator")
            for path_issue in validate_path_pattern(row["PathRegex"]):
                issues.append(
                    f"line {line_number}: PathRegex {path_issue}")

            try:
                review_date = datetime.date.fromisoformat(
                    row["ReviewDate"])
                if review_date < datetime.date.today():
                    issues.append(
                        f"line {line_number}: ReviewDate has expired")
            except ValueError:
                issues.append(
                    f"line {line_number}: ReviewDate must use YYYY-MM-DD")

    return issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "whitelist_path", nargs="?", type=Path,
        default=DEFAULT_WHITELISTS)
    parser.add_argument(
        "--rules", type=Path, default=DEFAULT_RULES)
    args = parser.parse_args()

    issues = validate_whitelist(args.whitelist_path, args.rules)
    if issues:
        for issue in issues:
            print(issue)
        return 1

    print(
        "MFT whitelist validation passed: "
        f"{args.whitelist_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
