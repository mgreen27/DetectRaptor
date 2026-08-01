#!/usr/bin/env python3
"""Assign stable IDs and baseline metadata to MFT detection rules."""

import argparse
import csv
import io
import re
from collections import defaultdict
from pathlib import Path


LEGACY_FIELDS = (
    "Detection",
    "KeywordRegex",
    "PathRegex",
    "IgnoreRegex",
    "Reference",
    "Criticality",
    "Scope",
    "EntryType",
)

FIELDS = (
    "RuleID",
    "Detection",
    "Category",
    "Technique",
    "Confidence",
    "KeywordRegex",
    "PathRegex",
    "IgnoreRegex",
    "Reference",
    "Criticality",
    "Scope",
    "EntryType",
    "Source",
    "SourceID",
)

RULE_ID_RE = re.compile(
    r"^DR-MFT-(?P<code>[A-Z][A-Z0-9]{2,5})-(?P<number>\d{3})$")
LOLRMM_SOURCE_RE = re.compile(
    r"lolrmm\.io/tools/(?P<source_id>[a-z0-9_.-]+)", re.IGNORECASE)


REVIEWED_CONFIDENCE = {
    "Archive Utilities - Amcache": "High",
    "Archive Utilities - User or Public Staging": "High",
    "Archive Utilities - Windows Temporary Staging": "High",
    "Credential Access Tool - ProcDump": "High",
    "Data Transfer - FileZilla": "High",
    "Enumeration Tool - Network Scanner (NS) Tool": "High",
    "Enumeration Tool - Network and AD Scanner": "High",
    "Enumeration Tool - BloodHound": "High",
    "Enumeration Tool - Nmap and Everything": "High",
    "RMM - Microsoft Quick Assist Execution": "High",
    "RMM - Microsoft Quick Assist Unusual Path": "High",
    "RMM - Product Directory": "High",
    "VPN": "High",
    "Masquerading - Windows Binary Name in AppData": "High",
    "Masquerading - Double Extension Payload": "High",
    "Credential Access - NTDS Database in User Profile": "High",
    "Suspicious AppData Hexadecimal Payload": "Medium",
    "Suspicious AppData GUID Directory Payload": "Medium",
    "Suspicious Location - Uncommon AppData Folder": "High",
    "Persistence - User Startup Executable or Script": "High",
    "Persistence - User Startup Shortcut": "Medium",
    "Suspicious Location - Recycle Bin Executable or Script": "High",
    "Suspicious One Letter Filename": "Medium",
    "Suspicious Location - Public Executable or Script": "High",
    "Suspicious Location - Public Archive Installer or Dump": "Medium",
    "Suspicious Location - Local Temp Executable or Script": "High",
    "Suspicious Location - Local Temp Archive Installer or Dump": "Medium",
    "Suspicious Location - AppData Root Executable or Script": "High",
    "Suspicious Location - AppData Root Archive or Installer": "Medium",
    "Suspicious Location - ProgramData Root Executable or Script": "High",
    "Suspicious Location - ProgramData Root Archive Installer or Dump": (
        "Medium"
    ),
    "Suspicious Location - PerfLogs Executable or Script": "High",
    "Suspicious Location - PerfLogs Archive Installer or Dump": "Medium",
}


def classify_detection(detection):
    """Return the stable ID code and analyst-facing category."""
    classifications = (
        (("RMM -", "RMM _", "Remote Access -"),
         ("RMM", "Remote Access Software")),
        (("Archive Utilities",), ("ARCH", "Archive Utility")),
        (("Attacker Tool -", "Hack Tool -", "Mimikatz Tools"),
         ("TOOL", "Attacker Tool")),
        (("BAU Cloud Data Transfer", "Data Transfer"),
         ("XFER", "Data Transfer")),
        (("Credential Theft", "Credential Access"),
         ("CRED", "Credential Access")),
        (("Crytominers",), ("CRYP", "Cryptomining")),
        (("Defence Evasion", "EDR Evasion"),
         ("EVA", "Defence Evasion")),
        (("Encryption",), ("IMPA", "Impact")),
        (("Enumeration Tool",), ("DISC", "Discovery")),
        (("Execution",), ("EXEC", "Execution")),
        (("Privilege Escalation",), ("PRIV", "Privilege Escalation")),
        (("Pirating Software",), ("POL", "Policy Violation")),
        (("Developer Utility",), ("DEV", "Developer Utility")),
        (("VPN",), ("VPN", "Network Tunnelling")),
        (("Masquerading",), ("MASQ", "Masquerading")),
        (("Persistence",), ("PERS", "Persistence")),
        (("Suspicious Location", "Suspicious AppData"),
         ("SLOC", "Suspicious Location")),
        (("Suspicious One Letter Filename",),
         ("SFILE", "Suspicious Filename")),
        (("Web Browsing History",), ("WEB", "Web History")),
    )

    for prefixes, result in classifications:
        if detection.startswith(prefixes):
            return result
    return "GEN", "Other"


def technique_for(detection, category_code):
    """Return only mappings that are unambiguous at filename-rule level."""
    exact_mappings = {
        "Credential Access Tool - ProcDump": "T1003.001",
        "Credential Access - NTDS Database in User Profile": "T1003.003",
        "Encryption": "T1486",
        "Masquerading - Windows Binary Name in AppData": "T1036.005",
        "Masquerading - Double Extension Payload": "T1036.007",
        "Persistence - User Startup Executable or Script": "T1547.001",
        "Persistence - User Startup Shortcut": "T1547.001",
        "RMM - Microsoft Quick Assist Execution": "T1219.002",
        "RMM - Microsoft Quick Assist Unusual Path": "T1219.002",
        "Suspicious One Letter Filename": "T1036",
    }
    if detection in exact_mappings:
        return exact_mappings[detection]
    return ""


def source_for(reference):
    """Return source and optional upstream source identifier."""
    match = LOLRMM_SOURCE_RE.search(reference)
    if match:
        return "LOLRMM", match.group("source_id").lower()
    if reference.strip().casefold() == "internal":
        return "InfoGuard Internal", ""
    return "DetectRaptor Curated", ""


def serialize_rows(rows):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output, fieldnames=FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def assign_metadata(rows):
    """Populate missing metadata while preserving existing stable values."""
    next_numbers = defaultdict(int)
    for row in rows:
        match = RULE_ID_RE.fullmatch(row.get("RuleID", "").strip())
        if match:
            next_numbers[match.group("code")] = max(
                next_numbers[match.group("code")],
                int(match.group("number")),
            )

    migrated = []
    for row in rows:
        detection = row.get("Detection", "").strip()
        category_code, category = classify_detection(detection)
        source, source_id = source_for(row.get("Reference", ""))

        normalized = {field: row.get(field, "") for field in FIELDS}
        if not normalized["RuleID"]:
            next_numbers[category_code] += 1
            if next_numbers[category_code] > 999:
                raise ValueError(
                    f"Rule ID namespace DR-MFT-{category_code} is exhausted")
            normalized["RuleID"] = (
                f"DR-MFT-{category_code}-{next_numbers[category_code]:03d}")
        normalized["Category"] = normalized["Category"] or category
        normalized["Technique"] = (
            normalized["Technique"]
            or technique_for(detection, category_code)
        )
        normalized["Confidence"] = (
            normalized["Confidence"]
            or REVIEWED_CONFIDENCE.get(detection, "Unreviewed")
        )
        normalized["Source"] = normalized["Source"] or source
        normalized["SourceID"] = normalized["SourceID"] or source_id
        migrated.append(normalized)

    return migrated


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "csv_path",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "csv" / "MFT.csv",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the CSV requires metadata assignment or normalization.",
    )
    args = parser.parse_args()

    current_text = args.csv_path.read_text(encoding="utf-8-sig")
    reader = csv.DictReader(io.StringIO(current_text))
    fields = tuple(reader.fieldnames or ())
    if fields not in (LEGACY_FIELDS, FIELDS):
        raise SystemExit(
            "Unsupported MFT CSV header: " + ",".join(fields))

    updated_text = serialize_rows(assign_metadata(list(reader)))
    if args.check:
        if current_text != updated_text:
            print(f"MFT metadata update required: {args.csv_path}")
            return 1
        print(f"MFT metadata is current: {args.csv_path}")
        return 0

    args.csv_path.write_text(updated_text, encoding="utf-8")
    print(f"Assigned MFT metadata: {args.csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
