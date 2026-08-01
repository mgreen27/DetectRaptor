#!/usr/bin/env python3
"""Normalize confidence, ATT&CK, severity, and scope metadata for MFT rules."""

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

from assign_mft_metadata import FIELDS
from validate_mft import validate_mft_csv


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MFT = REPO_ROOT / "csv" / "MFT.csv"
DEFAULT_REPORT = REPO_ROOT / "csv" / "MFT_Metadata_Summary.csv"

TECHNIQUE_BY_RULE = {
    "DR-MFT-TOOL-003": "T1562.001",
    "DR-MFT-TOOL-006": "T1021",
    "DR-MFT-TOOL-008": "T1562.001",
    "DR-MFT-TOOL-009": "T1090",
    "DR-MFT-TOOL-010": "T1110.003",
    "DR-MFT-TOOL-015": "T1110.002",
    "DR-MFT-TOOL-018": "T1110.002",
    "DR-MFT-TOOL-022": "T1110.002",
    "DR-MFT-TOOL-039": "T1003",
    "DR-MFT-CRED-001": "T1003",
    "DR-MFT-CRED-002": "T1003.001",
    "DR-MFT-CRED-003": "T1003",
    "DR-MFT-CRED-005": "T1187",
    "DR-MFT-CRED-006": "T1003",
    "DR-MFT-EVA-001": "T1562.001",
    "DR-MFT-EVA-002": "T1562.001",
    "DR-MFT-EVA-003": "T1562.001",
    "DR-MFT-IMPA-001": "T1486",
    "DR-MFT-DISC-001": "T1046",
    "DR-MFT-DISC-002": "T1046",
    "DR-MFT-DISC-003": "T1482",
    "DR-MFT-DISC-004": "T1046",
    "DR-MFT-EXEC-001": "T1569.002",
    "DR-MFT-EXEC-003": "T1548.002",
    "DR-MFT-EXEC-004": "T1569.002",
    "DR-MFT-VPN-001": "T1090",
    "DR-MFT-MASQ-001": "T1036.005",
    "DR-MFT-MASQ-002": "T1036.007",
    "DR-MFT-CRED-007": "T1003.003",
    "DR-MFT-PERS-001": "T1547.001",
    "DR-MFT-PERS-002": "T1547.001",
    "DR-MFT-SFILE-001": "T1036",
}


def confidence_for(row):
    if row["Confidence"] != "Unreviewed":
        return row["Confidence"]
    keyword = row["KeywordRegex"]
    if (keyword.startswith("^")
            and keyword.endswith("$")
            and ".*" not in keyword):
        return "High"
    return "Medium"


def normalize(rows):
    normalized = []
    for original in rows:
        row = dict(original)
        row["Confidence"] = confidence_for(row)

        if row["Category"] == "Remote Access Software":
            row["Criticality"] = "Medium"
            row["Technique"] = (
                "T1219.002"
                if "Quick Assist" in row["Detection"]
                else "T1219"
            )
        elif row["RuleID"] in TECHNIQUE_BY_RULE:
            row["Technique"] = TECHNIQUE_BY_RULE[row["RuleID"]]

        if row["EntryType"] == "Directory":
            row["Scope"] = "MFT"
        normalized.append(row)
    return normalized


def summary_rows(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["Category"]].append(row)

    output = []
    for category, category_rows in sorted(grouped.items()):
        confidence = Counter(row["Confidence"] for row in category_rows)
        criticality = Counter(row["Criticality"] for row in category_rows)
        scope = Counter(row["Scope"] for row in category_rows)
        output.append({
            "Category": category,
            "Rules": len(category_rows),
            "ConfidenceHigh": confidence["High"],
            "ConfidenceMedium": confidence["Medium"],
            "ConfidenceLow": confidence["Low"],
            "CriticalityHigh": criticality["High"],
            "CriticalityMedium": criticality["Medium"],
            "CriticalityLow": criticality["Low"],
            "ScopeMFT": scope["MFT"],
            "ScopeAmcache": scope["Amcache"],
            "ScopeBoth": scope["Both"],
            "TechniqueMapped": sum(
                bool(row["Technique"]) for row in category_rows),
        })
    return output


def normalize_files(mft_path, report_path):
    with Path(mft_path).open(
            newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    rows = normalize(rows)
    with Path(mft_path).open(
            "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    report_fields = (
        "Category", "Rules",
        "ConfidenceHigh", "ConfidenceMedium", "ConfidenceLow",
        "CriticalityHigh", "CriticalityMedium", "CriticalityLow",
        "ScopeMFT", "ScopeAmcache", "ScopeBoth", "TechniqueMapped",
    )
    with Path(report_path).open(
            "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=report_fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(summary_rows(rows))

    issues = validate_mft_csv(mft_path)
    if issues:
        raise ValueError("\n".join(issues))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mft", type=Path, default=DEFAULT_MFT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    rows = normalize_files(args.mft, args.report)
    print(f"Normalized {len(rows)} MFT rules: {args.mft}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
