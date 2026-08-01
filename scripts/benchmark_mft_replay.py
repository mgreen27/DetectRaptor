#!/usr/bin/env python3
"""Benchmark MFT replay and report match-expansion metrics."""

import argparse
import json
import statistics
import time
from pathlib import Path

import build_mft_replay_coverage
import replay_mft


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES = REPO_ROOT / "csv" / "MFT.csv"
DEFAULT_WHITELISTS = REPO_ROOT / "csv" / "MFT_Whitelist.csv"
DEFAULT_INPUT = REPO_ROOT / "tests" / "fixtures" / "mft_replay.csv"


def synthetic_cases(rules):
    return [
        {
            "CaseID": row["CaseID"],
            "Artifact": row["Artifact"],
            "EntryType": row["EntryType"],
            "FileName": row["FileName"],
            "OSPath": row["OSPath"],
            "Description": "Synthetic rule coverage",
        }
        for row in build_mft_replay_coverage.build_coverage(rules)
    ]


def build_cases(rules, input_paths=None, include_synthetic=True):
    cases = []
    for path in input_paths or [DEFAULT_INPUT]:
        cases.extend(replay_mft.read_csv(path))
    if include_synthetic:
        cases.extend(synthetic_cases(rules))
    return cases


def benchmark(rules, whitelists, cases, iterations=5):
    durations = []
    raw_matches = []
    retained = []
    suppressed = []

    for _ in range(iterations):
        started = time.perf_counter()
        raw_matches = replay_mft.replay(rules, cases)
        retained, suppressed = replay_mft.apply_whitelists(
            raw_matches, whitelists)
        durations.append(time.perf_counter() - started)

    summary = replay_mft.summarize(cases, retained)
    mean_seconds = statistics.mean(durations)
    summary.update({
        "BenchmarkVersion": 1,
        "Rules": len(rules),
        "Whitelists": len(whitelists),
        "Iterations": iterations,
        "EstimatedRuleEvaluationsPerIteration": (
            len(rules) * len(cases)),
        "RawRuleMatches": len(raw_matches),
        "RetainedRuleMatches": len(retained),
        "SuppressedMatches": len(suppressed),
        "MinSeconds": round(min(durations), 6),
        "MeanSeconds": round(mean_seconds, 6),
        "MaxSeconds": round(max(durations), 6),
        "CasesPerSecond": round(
            len(cases) / mean_seconds, 2) if mean_seconds else 0,
        "RuleEvaluationsPerSecond": round(
            (len(rules) * len(cases)) / mean_seconds, 2)
        if mean_seconds else 0,
    })
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument(
        "--whitelists", type=Path, default=DEFAULT_WHITELISTS)
    parser.add_argument(
        "--input", action="append", type=Path,
        help="Replay-format CSV input. Repeat for multiple files.")
    parser.add_argument(
        "--no-synthetic", action="store_true",
        help="Do not add one generated positive case per rule.")
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument(
        "--output", type=Path,
        help="Optional explicit JSON output path.")
    args = parser.parse_args()

    if args.iterations < 1:
        parser.error("--iterations must be at least 1")

    rules = replay_mft.read_csv(args.rules)
    whitelists = replay_mft.read_csv(args.whitelists)
    cases = build_cases(
        rules,
        input_paths=args.input,
        include_synthetic=not args.no_synthetic,
    )
    result = benchmark(
        rules, whitelists, cases, iterations=args.iterations)
    output = json.dumps(result, indent=2, sort_keys=True) + "\n"
    print(output, end="")
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
