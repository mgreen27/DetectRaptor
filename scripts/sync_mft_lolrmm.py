#!/usr/bin/env python3
"""Generate MFT/Amcache RMM rules from the checked-in LOLRMM dataset."""

import argparse
import csv
import re
from collections import OrderedDict
from pathlib import Path

from assign_mft_metadata import FIELDS
from validate_mft import _split_top_level_alternatives, validate_mft_csv


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MFT = REPO_ROOT / "csv" / "MFT.csv"
DEFAULT_LOLRMM = REPO_ROOT / "csv" / "lolrmm.csv"
DEFAULT_OVERRIDES = REPO_ROOT / "csv" / "MFT_RMM_Overrides.csv"
DEFAULT_IDS = REPO_ROOT / "csv" / "MFT_RMM_IDs.csv"
DEFAULT_REPORT = REPO_ROOT / "csv" / "MFT_RMM_Coverage.csv"

WINDOWS_EXTENSION_RE = re.compile(
    r"\\?\.(?:exe|msi|dll|sys|bat|cmd|ps1|psm1|vbs|vbe|js|jse|"
    r"wsf|hta|scr|cpl|com)(?:\\?\$|\$|\)|$)",
    re.IGNORECASE,
)
DLL_EXTENSION_RE = re.compile(
    r"\\?\.dll(?:\\?\$|\$)$", re.IGNORECASE)
RULE_ID_RE = re.compile(r"^DR-MFT-RMM-(\d{3})$")
SOURCE_ID_ALIASES = {
    "lite_manager": "litemanager",
    "quick_assist": "microsoft_quick_assist",
    "remoteutilities": "remote_utilities",
    "ultra_vnc": "ultravnc",
}


def read_csv(path):
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def write_csv(path, fieldnames, rows):
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def source_id(row):
    item = row["LolRMMLink"].rstrip("/").rsplit("/", 1)[-1].lower()
    return SOURCE_ID_ALIASES.get(item, item)


def _filename_pattern(alternative):
    pattern = alternative.strip()
    if not pattern:
        return None
    if "/" in pattern and "\\\\" not in pattern:
        return None
    if "\\\\" in pattern:
        pattern = pattern.rsplit("\\\\", 1)[-1]
    pattern = pattern.strip()
    if not WINDOWS_EXTENSION_RE.search(pattern):
        return None
    if re.search(r"(^|\^)\.\*\\?\.(exe|dll|msi|sys)", pattern, re.I):
        return None

    stem = re.sub(
        r"\\?\.(exe|msi|dll|sys|bat|cmd|ps1|psm1|vbs|vbe|js|jse|"
        r"wsf|hta|scr|cpl|com).*$",
        "",
        pattern,
        flags=re.IGNORECASE,
    )
    literal = re.sub(r"[^A-Za-z0-9]+", "", stem)
    if len(literal) < 3:
        return None

    if not pattern.startswith("^"):
        pattern = "^" + pattern
    if not pattern.endswith("$"):
        pattern += "$"
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None
    return pattern


def _product_tokens(name, item):
    ignored = {
        "agent", "client", "control", "desktop", "management",
        "monitor", "remote", "rmm", "server", "service", "software",
        "tool",
    }
    tokens = set()
    for value in (name, item):
        value = re.sub(r"\.io$", "", value.casefold())
        normalized = re.sub(r"[^a-z0-9]+", "", value)
        if len(normalized) >= 4:
            tokens.add(normalized)
        for token in re.split(r"[^a-z0-9]+", value):
            if len(token) >= 4 and token not in ignored:
                tokens.add(token)
    return {token for token in tokens if len(token) >= 4}


def _specific_product_dll(pattern, name, item):
    if not DLL_EXTENSION_RE.search(pattern):
        return True
    stem = DLL_EXTENSION_RE.sub("", pattern)
    normalized_stem = re.sub(r"[^a-z0-9]+", "", stem.casefold())
    return any(
        token in normalized_stem
        for token in _product_tokens(name, item)
    )


def filename_patterns(path_regex, name="", item=""):
    patterns = OrderedDict()
    filtered = OrderedDict()
    for alternative in _split_top_level_alternatives(path_regex):
        pattern = _filename_pattern(alternative)
        if pattern:
            target = (
                patterns if _specific_product_dll(pattern, name, item)
                else filtered
            )
            target.setdefault(pattern.casefold(), pattern)
    return list(patterns.values()), list(filtered.values())


def load_registry(path, existing_rows):
    registry = {}
    if Path(path).exists():
        for row in read_csv(path):
            registry[row["SourceID"]] = row["RuleID"]
    for row in existing_rows:
        if (row["Category"] == "Remote Access Software"
                and row["Source"] == "LOLRMM"
                and row["SourceID"]
                and RULE_ID_RE.fullmatch(row["RuleID"])):
            registry.setdefault(row["SourceID"], row["RuleID"])
    return registry


def allocate_rule_ids(registry, source_ids, existing_rows):
    highest = 0
    for rule_id in [
            *registry.values(),
            *(row["RuleID"] for row in existing_rows)]:
        match = RULE_ID_RE.fullmatch(rule_id)
        if match:
            highest = max(highest, int(match.group(1)))

    for item in sorted(source_ids):
        if item not in registry:
            highest += 1
            if highest > 999:
                raise ValueError("DR-MFT-RMM RuleID namespace exhausted")
            registry[item] = f"DR-MFT-RMM-{highest:03d}"
    return registry


def build_generated_rules(lolrmm_rows, registry):
    grouped = OrderedDict()
    for row in lolrmm_rows:
        item = source_id(row)
        group = grouped.setdefault(item, {
            "Name": row["Name"],
            "LolRMMLink": row["LolRMMLink"],
            "SourceRows": 0,
            "Patterns": OrderedDict(),
            "FilteredPatterns": OrderedDict(),
        })
        group["SourceRows"] += 1
        accepted, filtered = filename_patterns(
            row["PathRegex"], row["Name"], item)
        for pattern in accepted:
            group["Patterns"].setdefault(pattern.casefold(), pattern)
        for pattern in filtered:
            group["FilteredPatterns"].setdefault(
                pattern.casefold(), pattern)

    generated = []
    report = []
    for item, group in sorted(
            grouped.items(), key=lambda value: value[1]["Name"].casefold()):
        patterns = list(group["Patterns"].values())
        filtered_patterns = list(group["FilteredPatterns"].values())
        if not patterns:
            report.append({
                "SourceID": item,
                "Name": group["Name"],
                "Status": "Excluded",
                "RuleID": registry.get(item, ""),
                "FilenamePatternCount": "0",
                "FilenameRegex": "",
                "FilteredFilenameRegex": "|".join(filtered_patterns),
                "Reason": (
                    "No safe Windows filename indicator"
                    if not filtered_patterns
                    else "Only non-specific DLL filename indicators"),
                "SourceRows": str(group["SourceRows"]),
            })
            continue

        rule_id = registry[item]
        keyword_regex = "|".join(patterns)
        confidence = (
            "High" if ".*" not in keyword_regex else "Medium")
        generated.append({
            "RuleID": rule_id,
            "Detection": f"RMM - {group['Name']}",
            "Category": "Remote Access Software",
            "Technique": "",
            "Confidence": confidence,
            "KeywordRegex": keyword_regex,
            "PathRegex": ".",
            "IgnoreRegex": "",
            "Reference": group["LolRMMLink"],
            "Criticality": "Medium",
            "Scope": "Both",
            "EntryType": "File",
            "Source": "LOLRMM",
            "SourceID": item,
        })
        report.append({
            "SourceID": item,
            "Name": group["Name"],
            "Status": "Generated",
            "RuleID": rule_id,
            "FilenamePatternCount": str(len(patterns)),
            "FilenameRegex": keyword_regex,
            "FilteredFilenameRegex": "|".join(filtered_patterns),
            "Reason": (
                "Filtered non-specific DLL filename indicators"
                if filtered_patterns else ""),
            "SourceRows": str(group["SourceRows"]),
        })
    return generated, report


def sync(mft_path, lolrmm_path, overrides_path, ids_path, report_path):
    current_rows = read_csv(mft_path)
    lolrmm_rows = read_csv(lolrmm_path)
    overrides = read_csv(overrides_path)
    registry = load_registry(ids_path, current_rows)

    grouped_source_ids = {source_id(row) for row in lolrmm_rows}
    registry = allocate_rule_ids(
        registry, grouped_source_ids, current_rows)
    generated, report = build_generated_rules(lolrmm_rows, registry)
    override_source_ids = {
        row["SourceID"] for row in overrides if row["SourceID"]}
    generated = [
        row for row in generated
        if row["SourceID"] not in override_source_ids
    ]
    report = [
        row for row in report
        if row["SourceID"] not in override_source_ids
    ]

    non_rmm = [
        row for row in current_rows
        if row["Category"] != "Remote Access Software"
    ]
    output_rows = non_rmm + generated + overrides
    write_csv(mft_path, FIELDS, output_rows)

    write_csv(ids_path, ("SourceID", "RuleID"), (
        {"SourceID": item, "RuleID": rule_id}
        for item, rule_id in sorted(registry.items())
    ))
    for row in overrides:
        report.append({
            "SourceID": row["SourceID"],
            "Name": row["Detection"],
            "Status": "Override",
            "RuleID": row["RuleID"],
            "FilenamePatternCount": "",
            "FilenameRegex": row["KeywordRegex"],
            "FilteredFilenameRegex": "",
            "Reason": row["Reference"],
            "SourceRows": "",
        })
    write_csv(report_path, (
        "SourceID", "Name", "Status", "RuleID", "FilenamePatternCount",
        "FilenameRegex", "FilteredFilenameRegex", "Reason", "SourceRows",
    ), report)

    issues = validate_mft_csv(mft_path)
    if issues:
        raise ValueError("Generated MFT CSV is invalid:\n" + "\n".join(issues))
    return generated, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mft", type=Path, default=DEFAULT_MFT)
    parser.add_argument("--lolrmm", type=Path, default=DEFAULT_LOLRMM)
    parser.add_argument("--overrides", type=Path, default=DEFAULT_OVERRIDES)
    parser.add_argument("--ids", type=Path, default=DEFAULT_IDS)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    generated, report = sync(
        args.mft, args.lolrmm, args.overrides, args.ids, args.report)
    statuses = {}
    for row in report:
        statuses[row["Status"]] = statuses.get(row["Status"], 0) + 1
    print(
        f"Generated {len(generated)} RMM rules; coverage: {statuses}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
