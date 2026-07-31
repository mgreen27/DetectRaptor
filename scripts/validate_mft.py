#!/usr/bin/env python3
"""Validate the curated MFT detection CSV before artifact generation."""

import argparse
import csv
import re
from pathlib import Path


EXPECTED_FIELDS = (
    "Detection",
    "KeywordRegex",
    "PathRegex",
    "IgnoreRegex",
    "Reference",
    "Criticality",
)
REQUIRED_FIELDS = ("Detection", "KeywordRegex", "PathRegex", "Criticality")
REGEX_FIELDS = ("KeywordRegex", "PathRegex", "IgnoreRegex")
ALLOWED_CRITICALITIES = {"Critical", "High", "Medium", "Low"}
GLOBAL_IGNORE_PATTERNS = {".", ".*", "^.*$", "(?:.*)"}


def _parenthesized_contents(pattern):
    stack = []
    escaped = False
    in_character_class = False

    for index, character in enumerate(pattern):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == "[" and not in_character_class:
            in_character_class = True
            continue
        if character == "]" and in_character_class:
            in_character_class = False
            continue
        if in_character_class:
            continue
        if character == "(":
            stack.append(index)
        elif character == ")" and stack:
            start = stack.pop()
            yield pattern[start + 1:index]


def _split_top_level_alternatives(pattern):
    alternatives = []
    start = 0
    depth = 0
    escaped = False
    in_character_class = False

    for index, character in enumerate(pattern):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == "[" and not in_character_class:
            in_character_class = True
            continue
        if character == "]" and in_character_class:
            in_character_class = False
            continue
        if in_character_class:
            continue
        if character == "(":
            depth += 1
        elif character == ")" and depth:
            depth -= 1
        elif character == "|" and depth == 0:
            alternatives.append(pattern[start:index])
            start = index + 1

    alternatives.append(pattern[start:])
    return alternatives


def _validate_alternatives(pattern, line_number, field, issues):
    expressions = [pattern, *_parenthesized_contents(pattern)]

    for expression in expressions:
        alternatives = _split_top_level_alternatives(expression)
        if len(alternatives) < 2:
            continue

        seen = {}
        for alternative in alternatives:
            stripped = alternative.strip()
            if alternative != stripped:
                issues.append(
                    f"line {line_number}: {field} contains whitespace "
                    f"around alternative {alternative!r}")

            normalized = stripped.casefold()
            if normalized and normalized in seen:
                issues.append(
                    f"line {line_number}: {field} contains duplicate "
                    f"case-insensitive alternatives {seen[normalized]!r} "
                    f"and {stripped!r}")
            elif normalized:
                seen[normalized] = stripped


def validate_mft_csv(csv_path):
    """Return validation issues for an MFT CSV."""
    csv_path = Path(csv_path)
    issues = []

    with csv_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != EXPECTED_FIELDS:
            return [
                "line 1: unexpected CSV header; expected "
                + ",".join(EXPECTED_FIELDS)
            ]

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

            if row["Criticality"] not in ALLOWED_CRITICALITIES:
                issues.append(
                    f"line {line_number}: invalid Criticality "
                    f"{row['Criticality']!r}")

            if row["IgnoreRegex"].strip() in GLOBAL_IGNORE_PATTERNS:
                issues.append(
                    f"line {line_number}: IgnoreRegex suppresses all "
                    "detections")

            for field in REGEX_FIELDS:
                pattern = row[field]
                if not pattern:
                    continue
                try:
                    re.compile(pattern, re.IGNORECASE)
                except re.error as error:
                    issues.append(
                        f"line {line_number}: invalid {field}: {error}")
                    continue
                _validate_alternatives(
                    pattern, line_number, field, issues)

    return issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "csv_path",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "csv" / "MFT.csv",
    )
    args = parser.parse_args()

    issues = validate_mft_csv(args.csv_path)
    if issues:
        for issue in issues:
            print(issue)
        return 1

    print(f"MFT CSV validation passed: {args.csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
