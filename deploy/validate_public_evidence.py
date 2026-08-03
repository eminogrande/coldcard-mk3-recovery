#!/usr/bin/env python3
"""Verify the strict coverage ledger, evidence hashes, and final queue."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

PAD_END = 1 << 32
FULL_MATRIX = 9 * 2 * 20 * PAD_END


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def key_values(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            result[key] = value
    return result


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    ledger_path = root / "artifacts/final_coverage_2026-08-03.json"
    queue_path = root / "artifacts/final_run_queue_2026-08-03.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    production = ledger["production_inputs"]

    require(sha(root / "scan/bip39_english.txt") == production["bip39_english_sha256"], "wordlist hash mismatch")
    require(sha(root / "targets/all_bc1q.txt") == production["targets_all_bc1q_sha256"], "target hash mismatch")
    source = subprocess.check_output(
        ["git", "show", f"{production['git_commit']}:{production['source_path']}"], cwd=root
    )
    require(sha_bytes(source) == production["scan_cu_sha256"], "production CUDA source hash mismatch")

    strict = 0
    for row in ledger["coverage"]:
        audit = root / row["audit_log"]
        require(sha(audit) == row["audit_sha256"], f"audit hash mismatch: {audit}")
        pads = sum(stop - start for start, stop in row["completed_pad_intervals"])
        expected = pads * len(row["indexes"])
        require(expected == row["unique_candidate_address_derivations"], f"coverage count mismatch: {audit}")
        strict += expected
    require(strict == ledger["strict_unique_candidate_address_derivations"], "strict total mismatch")
    require(ledger["real_target_hits"] == 0, "ledger unexpectedly records a corpus hit")

    q28_audit = root / "artifacts/public_logs/cuda_firstboot_q28_i0_7_audit.log"
    q28 = key_values(q28_audit)
    require(sha(root / "artifacts/public_logs/cuda_firstboot_q28_i0_7_controller.log") == q28["controller_log_sha256"], "Q28 controller hash mismatch")
    require(sha(root / "artifacts/public_logs/cuda_firstboot_q28_i0_7_sweep.log") == q28["sweep_log_sha256"], "Q28 sweep hash mismatch")

    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    require(queue["source_ledger_sha256"] == sha(ledger_path), "queue ledger hash mismatch")
    require(queue["scanner_sha256"] == sha(root / "gpu/cuda/scan.cu"), "queue scanner hash mismatch")
    require(queue["strict_prior_derivations"] == strict, "queue prior total mismatch")
    require(queue["full_matrix_derivations"] == FULL_MATRIX, "queue full-matrix mismatch")
    require(queue["remaining_derivations"] + strict == FULL_MATRIX, "queue remaining total mismatch")
    require(queue["job_count"] == len(queue["jobs"]), "queue job count mismatch")

    job_total = 0
    ids = set()
    for job in queue["jobs"]:
        require(job["job_id"] not in ids, f"duplicate queue id: {job['job_id']}")
        ids.add(job["job_id"])
        paths = 0
        by_chain: dict[int, list[tuple[int, int]]] = {}
        for path in job["path_ranges"]:
            start = path["index_start"]
            stop = start + path["index_count"]
            require(path["chain"] in (0, 1) and 0 <= start < stop <= 20, f"invalid path range: {job['job_id']}")
            by_chain.setdefault(path["chain"], []).append((start, stop))
            paths += path["index_count"]
        for ranges in by_chain.values():
            ranges.sort()
            require(all(a_stop <= b_start for (_, a_stop), (b_start, _) in zip(ranges, ranges[1:])), f"overlapping queue paths: {job['job_id']}")
        expected = (job["pad_stop"] - job["pad_start"]) * paths
        require(expected == job["unique_candidate_address_derivations"], f"queue job count mismatch: {job['job_id']}")
        job_total += expected
    require(job_total == queue["remaining_derivations"], "queue job sum mismatch")

    print(f"PUBLIC_EVIDENCE_OK strict={strict} jobs={len(queue['jobs'])} remaining={job_total}")


if __name__ == "__main__":
    main()
