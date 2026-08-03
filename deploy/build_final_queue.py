#!/usr/bin/env python3
"""Build a provider-neutral, non-duplicating final CUDA queue."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

PAD_END = 1 << 32
SHARD = 1 << 25
Q_VALUES = tuple(range(18, 35, 2))
CHAINS = (0, 1)
INDEXES = tuple(range(20))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def covered(intervals: list[list[int]], start: int, stop: int) -> bool:
    return any(a <= start and stop <= b for a, b in intervals)


def compress_paths(cells: list[tuple[int, int]]) -> list[dict[str, int]]:
    ranges: list[dict[str, int]] = []
    for chain in CHAINS:
        indexes = sorted(i for c, i in cells if c == chain)
        if not indexes:
            continue
        start = previous = indexes[0]
        for index in indexes[1:]:
            if index == previous + 1:
                previous = index
                continue
            ranges.append({"chain": chain, "index_start": start, "index_count": previous - start + 1})
            start = previous = index
        ranges.append({"chain": chain, "index_start": start, "index_count": previous - start + 1})
    return ranges


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, default=root / "artifacts/final_coverage_2026-08-03.json")
    parser.add_argument("--output", type=Path, default=root / "artifacts/final_run_queue_2026-08-03.json")
    args = parser.parse_args()

    ledger = json.loads(args.ledger.read_text(encoding="utf-8"))
    prior: dict[tuple[int, int, int], list[list[int]]] = defaultdict(list)
    for row in ledger["coverage"]:
        q = row["post_terms_sessions"]
        chain = row["chain"]
        if q not in Q_VALUES or chain not in CHAINS:
            continue
        for index in row["indexes"]:
            if index in INDEXES:
                prior[(q, chain, index)].extend(row["completed_pad_intervals"])

    jobs = []
    remaining = 0
    for q in Q_VALUES:
        boundaries = set(range(0, PAD_END + 1, SHARD))
        boundaries.add(PAD_END)
        for chain in CHAINS:
            for index in INDEXES:
                for start, stop in prior[(q, chain, index)]:
                    boundaries.update((start, stop))
        points = sorted(boundaries)
        for start, stop in zip(points, points[1:]):
            missing = [
                (chain, index)
                for chain in CHAINS
                for index in INDEXES
                if not covered(prior[(q, chain, index)], start, stop)
            ]
            if not missing:
                continue
            path_ranges = compress_paths(missing)
            derivations = (stop - start) * len(missing)
            remaining += derivations
            jobs.append(
                {
                    "job_id": f"q{q}-p{start}-{stop}",
                    "post_terms_sessions": q,
                    "pad_start": start,
                    "pad_stop": stop,
                    "path_ranges": path_ranges,
                    "path_arguments": [
                        item
                        for path in path_ranges
                        for item in ("-P", f"{path['chain']}:{path['index_start']}:{path['index_count']}")
                    ],
                    "unique_candidate_address_derivations": derivations,
                }
            )

    full = len(Q_VALUES) * len(CHAINS) * len(INDEXES) * PAD_END
    strict = ledger["strict_unique_candidate_address_derivations"]
    expected = full - strict
    if remaining != expected:
        raise SystemExit(f"queue mismatch: generated {remaining}, expected {expected}")

    output = {
        "plan": "BIP84 account 0, external/change indexes 0-19, Q=18..34, RTC=0/0, P=2",
        "source_ledger": str(args.ledger.relative_to(root)),
        "source_ledger_sha256": sha256(args.ledger),
        "scanner_sha256": sha256(root / "gpu/cuda/scan.cu"),
        "mandatory_validation": "bash deploy/validate_cuda_path_ranges.sh gpu/cuda/cscan",
        "full_matrix_derivations": full,
        "strict_prior_derivations": strict,
        "remaining_derivations": remaining,
        "job_count": len(jobs),
        "shard_size": SHARD,
        "fixed_arguments": ["-r", "0", "-s", "0", "-F", "2", "-C", "1"],
        "jobs": jobs,
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"QUEUE_OK jobs={len(jobs)} remaining={remaining}")


if __name__ == "__main__":
    main()
