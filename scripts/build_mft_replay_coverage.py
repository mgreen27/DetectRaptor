#!/usr/bin/env python3
"""Build deterministic synthetic positive coverage for every MFT CSV rule."""

import argparse
import csv
import re
from pathlib import Path

import replay_mft

try:
    from re import _constants as CONSTANTS
    from re import _parser as PARSER
except ImportError:  # Python 3.10 compatibility
    import sre_constants as CONSTANTS
    import sre_parse as PARSER


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES = REPO_ROOT / "csv" / "MFT.csv"
DEFAULT_OUTPUT = REPO_ROOT / "csv" / "MFT_Replay_Coverage.csv"

REPEAT_OPERATIONS = (
    CONSTANTS.MAX_REPEAT,
    CONSTANTS.MIN_REPEAT,
    *(
        (CONSTANTS.POSSESSIVE_REPEAT,)
        if hasattr(CONSTANTS, "POSSESSIVE_REPEAT")
        else ()
    ),
)

FIELDS = (
    "RuleID", "CaseID", "Artifact", "EntryType", "FileName", "OSPath",
    "Verified", "AdditionalRuleIDs",
)


def _category_witness(category):
    return {
        CONSTANTS.CATEGORY_DIGIT: "0",
        CONSTANTS.CATEGORY_NOT_DIGIT: "A",
        CONSTANTS.CATEGORY_SPACE: " ",
        CONSTANTS.CATEGORY_NOT_SPACE: "A",
        CONSTANTS.CATEGORY_WORD: "A",
        CONSTANTS.CATEGORY_NOT_WORD: "-",
        CONSTANTS.CATEGORY_LINEBREAK: "\n",
        CONSTANTS.CATEGORY_NOT_LINEBREAK: "A",
    }.get(category, "A")


def _character_class_witness(items):
    negated = False
    excluded = set()
    for operation, argument in items:
        if operation is CONSTANTS.NEGATE:
            negated = True
        elif operation is CONSTANTS.LITERAL:
            if negated:
                excluded.add(chr(argument))
            else:
                return chr(argument)
        elif operation is CONSTANTS.RANGE:
            return chr(argument[0])
        elif operation is CONSTANTS.CATEGORY:
            return _category_witness(argument)
    if negated:
        for candidate in "A0_-z":
            if candidate not in excluded:
                return candidate
    return "A"


def _build_witness(sequence, groups):
    output = ""
    for operation, argument in sequence:
        if operation is CONSTANTS.LITERAL:
            output += chr(argument)
        elif operation is CONSTANTS.NOT_LITERAL:
            output += "A" if argument != ord("A") else "B"
        elif operation is CONSTANTS.ANY:
            output += "A"
        elif operation is CONSTANTS.IN:
            output += _character_class_witness(argument)
        elif operation is CONSTANTS.BRANCH:
            output += _build_witness(argument[1][0], groups)
        elif operation is CONSTANTS.SUBPATTERN:
            value = _build_witness(argument[-1], groups)
            output += value
            if argument[0]:
                groups[argument[0]] = value
        elif operation in REPEAT_OPERATIONS:
            output += (
                _build_witness(argument[2], groups) * argument[0])
        elif operation is CONSTANTS.CATEGORY:
            output += _category_witness(argument)
        elif operation is CONSTANTS.GROUPREF:
            output += groups.get(argument, "A")
        elif operation in (
                CONSTANTS.AT,
                CONSTANTS.ASSERT,
                CONSTANTS.ASSERT_NOT):
            continue
        else:
            raise ValueError(
                f"Unsupported regex operation {operation!r}")
    return output


def regex_witness(pattern):
    """Return a deterministic string matched by the supplied Python regex."""
    value = _build_witness(PARSER.parse(pattern, 0), {})
    if not re.search(pattern, value, re.IGNORECASE):
        raise ValueError(
            f"Unable to generate witness for regex {pattern!r}")
    return value


def path_witness(rule, filename):
    if rule["PathRegex"] == ".":
        return rf"C:\Replay\{filename}"

    witness = regex_witness(rule["PathRegex"])
    candidates = [witness]
    if witness.startswith("\\"):
        candidates.insert(0, "C:" + witness)
    elif not re.match(r"^[A-Za-z]:\\", witness):
        candidates.insert(0, rf"C:\Replay\{witness}")

    for candidate in candidates:
        if not re.search(
                rule["PathRegex"], candidate, re.IGNORECASE):
            continue
        if (rule["IgnoreRegex"]
                and re.search(
                    rule["IgnoreRegex"], candidate, re.IGNORECASE)):
            continue
        return candidate
    raise ValueError(
        f"Unable to create non-ignored path for {rule['RuleID']}")


def build_coverage(rules):
    output = []
    for rule in rules:
        artifact = "Amcache" if rule["Scope"] == "Amcache" else "MFT"
        entry_type = (
            "File" if rule["EntryType"] == "Any"
            else rule["EntryType"])
        filename = regex_witness(rule["KeywordRegex"])
        case = {
            "CaseID": f"COVERAGE-{rule['RuleID']}",
            "Artifact": artifact,
            "EntryType": entry_type,
            "FileName": filename,
            "OSPath": path_witness(rule, filename),
            "Description": "Synthetic positive rule coverage",
        }
        matches = replay_mft.replay(rules, [case])
        matched_ids = [row["RuleID"] for row in matches]
        output.append({
            "RuleID": rule["RuleID"],
            "CaseID": case["CaseID"],
            "Artifact": artifact,
            "EntryType": entry_type,
            "FileName": filename,
            "OSPath": case["OSPath"],
            "Verified": str(rule["RuleID"] in matched_ids),
            "AdditionalRuleIDs": "|".join(
                item for item in matched_ids if item != rule["RuleID"]),
        })
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    rules = replay_mft.read_csv(args.rules)
    coverage = build_coverage(rules)
    replay_mft.write_csv(args.output, FIELDS, coverage)
    failed = [row for row in coverage if row["Verified"] != "True"]
    print(
        f"Generated {len(coverage)} replay coverage rows; "
        f"failed={len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
