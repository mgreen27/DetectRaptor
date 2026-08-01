#!/usr/bin/env python3
"""Replay MFT/Amcache rules against sanitized CSV cases."""

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES = REPO_ROOT / "csv" / "MFT.csv"
DEFAULT_WHITELISTS = REPO_ROOT / "csv" / "MFT_Whitelist.csv"
DEFAULT_INPUT = REPO_ROOT / "tests" / "fixtures" / "mft_replay.csv"
DEFAULT_EXPECTED = REPO_ROOT / "tests" / "fixtures" / "mft_expected.csv"

MATCH_FIELDS = (
    "CaseID", "Artifact", "EntryType", "FileName", "OSPath",
    "RuleID", "Detection", "Category", "Technique", "Confidence",
    "Criticality", "Source", "SourceID", "Disposition", "WhitelistID",
    "WhitelistReason", "WhitelistSource", "WhitelistReviewDate",
)
COMPARISON_FIELDS = (
    "CaseID", "RuleID", "Change", "CurrentDetection", "BaselineDetection",
)


def read_csv(path):
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def split_rule_ids(value):
    return {
        item.strip() for item in value.split("|") if item.strip()}


def validate_case_inventory(cases, expected_rows):
    case_ids = [row["CaseID"] for row in cases]
    expected_ids = [row["CaseID"] for row in expected_rows]
    issues = []

    duplicate_cases = sorted(
        case_id for case_id, count in Counter(case_ids).items()
        if count > 1
    )
    duplicate_expected = sorted(
        case_id for case_id, count in Counter(expected_ids).items()
        if count > 1
    )
    missing_expected = sorted(set(case_ids) - set(expected_ids))
    unknown_expected = sorted(set(expected_ids) - set(case_ids))

    if duplicate_cases:
        issues.append(f"Duplicate replay CaseIDs: {duplicate_cases}")
    if duplicate_expected:
        issues.append(
            f"Duplicate expected-result CaseIDs: {duplicate_expected}")
    if missing_expected:
        issues.append(
            f"Replay cases without expectations: {missing_expected}")
    if unknown_expected:
        issues.append(
            f"Expectations without replay cases: {unknown_expected}")
    return issues


def rule_applies_to_artifact(rule, artifact):
    if artifact == "MFT":
        return rule["Scope"] in {"MFT", "Both"}
    if artifact == "Amcache":
        return (
            rule["Scope"] in {"Amcache", "Both"}
            and rule["EntryType"] != "Directory"
        )
    raise ValueError(f"Unsupported artifact {artifact!r}")


def rule_matches_case(rule, case):
    artifact = case["Artifact"]
    if not rule_applies_to_artifact(rule, artifact):
        return False

    if artifact == "MFT":
        entry_type = case["EntryType"]
        if (rule["EntryType"] != "Any"
                and rule["EntryType"] != entry_type):
            return False

    if not re.search(
            rule["KeywordRegex"], case["FileName"], re.IGNORECASE):
        return False
    if not re.search(rule["PathRegex"], case["OSPath"], re.IGNORECASE):
        return False
    if (rule["IgnoreRegex"]
            and re.search(
                rule["IgnoreRegex"], case["OSPath"], re.IGNORECASE)):
        return False
    return True


def replay(rules, cases):
    matches = []
    for case in cases:
        for rule in rules:
            if not rule_matches_case(rule, case):
                continue
            matches.append({
                "CaseID": case["CaseID"],
                "Artifact": case["Artifact"],
                "EntryType": case["EntryType"],
                "FileName": case["FileName"],
                "OSPath": case["OSPath"],
                "RuleID": rule["RuleID"],
                "Detection": rule["Detection"],
                "Category": rule["Category"],
                "Technique": rule["Technique"],
                "Confidence": rule["Confidence"],
                "Criticality": rule["Criticality"],
                "Source": rule["Source"],
                "SourceID": rule["SourceID"],
            })
    return matches


def whitelist_matches(match, whitelist):
    return (
        whitelist["Disposition"] == "Suppress"
        and whitelist["RuleID"] == match["RuleID"]
        and whitelist["Artifact"] == match["Artifact"]
        and re.search(
            whitelist["FilenameRegex"],
            match["FileName"],
            re.IGNORECASE)
        and re.search(
            whitelist["PathRegex"],
            match["OSPath"],
            re.IGNORECASE)
    )


def apply_whitelists(matches, whitelists):
    """Return retained and suppressed matches with whitelist metadata."""
    policies = {
        (row["RuleID"], row["Artifact"]): row
        for row in whitelists
    }
    retained = []
    suppressed = []

    for match in matches:
        output = dict(match)
        whitelist = policies.get(
            (match["RuleID"], match["Artifact"]))
        if whitelist and whitelist_matches(match, whitelist):
            output.update({
                "Disposition": "Suppressed",
                "WhitelistID": whitelist["WhitelistID"],
                "WhitelistReason": whitelist["Reason"],
                "WhitelistSource": whitelist["Source"],
                "WhitelistReviewDate": whitelist["ReviewDate"],
            })
            suppressed.append(output)
        else:
            output.update({
                "Disposition": "Retained",
                "WhitelistID": "",
                "WhitelistReason": "",
                "WhitelistSource": "",
                "WhitelistReviewDate": "",
            })
            retained.append(output)
    return retained, suppressed


def validate_expected(matches, expected_rows):
    actual = {}
    for match in matches:
        actual.setdefault(match["CaseID"], set()).add(match["RuleID"])

    issues = []
    for row in expected_rows:
        case_id = row["CaseID"]
        matched = actual.get(case_id, set())
        required = split_rule_ids(row["RequiredRuleIDs"])
        forbidden = split_rule_ids(row["ForbiddenRuleIDs"])

        missing = sorted(required - matched)
        unexpected = sorted(forbidden & matched)
        if missing:
            issues.append(
                f"{case_id}: missing required RuleIDs {missing}")
        if unexpected:
            issues.append(
                f"{case_id}: matched forbidden RuleIDs {unexpected}")
        if row["ExactMatch"] == "True" and matched != required:
            issues.append(
                f"{case_id}: expected exactly {sorted(required)}, "
                f"matched {sorted(matched)}")
    return issues


def summarize(cases, matches):
    counts = Counter(match["CaseID"] for match in matches)
    file_counts = Counter(
        (match["CaseID"], match["Artifact"], match["OSPath"])
        for match in matches)
    path_counts = Counter(
        (match["Artifact"], match["OSPath"]) for match in matches)
    return {
        "Cases": len(cases),
        "MatchedCases": len(counts),
        "UnmatchedCases": len(cases) - len(counts),
        "RuleMatches": len(matches),
        "MultiMatchCases": sum(total > 1 for total in counts.values()),
        "UniqueFiles": len(file_counts),
        "MultiMatchFiles": sum(
            total > 1 for total in file_counts.values()),
        "UniquePaths": len(path_counts),
        "MultiMatchPaths": sum(
            total > 1 for total in path_counts.values()),
        "UniqueRuleIDs": len({match["RuleID"] for match in matches}),
    }


def compare_matches(current, baseline):
    current_keys = {
        (row["CaseID"], row["RuleID"]): row for row in current}
    baseline_keys = {
        (row["CaseID"], row["RuleID"]): row for row in baseline}

    comparison = []
    for key in sorted(current_keys.keys() | baseline_keys.keys()):
        current_row = current_keys.get(key)
        baseline_row = baseline_keys.get(key)
        if current_row and baseline_row:
            change = "Unchanged"
        elif current_row:
            change = "Added"
        else:
            change = "Removed"
        comparison.append({
            "CaseID": key[0],
            "RuleID": key[1],
            "Change": change,
            "CurrentDetection": (
                current_row["Detection"] if current_row else ""),
            "BaselineDetection": (
                baseline_row["Detection"] if baseline_row else ""),
        })
    return comparison


def write_csv(path, fieldnames, rows):
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--expected", type=Path, default=DEFAULT_EXPECTED)
    parser.add_argument(
        "--whitelists", type=Path, default=DEFAULT_WHITELISTS)
    parser.add_argument(
        "--disable-whitelist", action="store_true",
        help="Report raw rule matches without whitelist suppression.")
    parser.add_argument("--baseline-rules", type=Path)
    parser.add_argument("--matches-out", type=Path)
    parser.add_argument("--suppressed-out", type=Path)
    parser.add_argument("--comparison-out", type=Path)
    parser.add_argument("--summary-out", type=Path)
    parser.add_argument(
        "--check", action="store_true",
        help="Return non-zero when expected results are not satisfied.")
    args = parser.parse_args()

    rules = read_csv(args.rules)
    cases = read_csv(args.input)
    raw_matches = replay(rules, cases)
    if args.disable_whitelist:
        matches, suppressed = apply_whitelists(raw_matches, [])
    else:
        matches, suppressed = apply_whitelists(
            raw_matches, read_csv(args.whitelists))
    expected_rows = read_csv(args.expected)
    issues = validate_case_inventory(cases, expected_rows)
    issues.extend(validate_expected(matches, expected_rows))
    summary = summarize(cases, matches)
    summary.update({
        "RawRuleMatches": len(raw_matches),
        "RetainedRuleMatches": len(matches),
        "SuppressedMatches": len(suppressed),
        "SuppressedCases": len({
            row["CaseID"] for row in suppressed}),
        "WhitelistIDs": len({
            row["WhitelistID"] for row in suppressed}),
    })

    if args.matches_out:
        write_csv(args.matches_out, MATCH_FIELDS, matches)
    if args.suppressed_out:
        write_csv(args.suppressed_out, MATCH_FIELDS, suppressed)
    if args.summary_out:
        args.summary_out.write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if args.baseline_rules:
        baseline_raw = replay(read_csv(args.baseline_rules), cases)
        if args.disable_whitelist:
            baseline, _ = apply_whitelists(baseline_raw, [])
        else:
            baseline, _ = apply_whitelists(
                baseline_raw, read_csv(args.whitelists))
        comparison = compare_matches(matches, baseline)
        if args.comparison_out:
            write_csv(
                args.comparison_out, COMPARISON_FIELDS, comparison)
        summary["AddedMatches"] = sum(
            row["Change"] == "Added" for row in comparison)
        summary["RemovedMatches"] = sum(
            row["Change"] == "Removed" for row in comparison)

    print(json.dumps(summary, sort_keys=True))
    for issue in issues:
        print(issue)
    if args.check and issues:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
