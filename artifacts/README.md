# Artifact classification

The canonical strict result is [`final_coverage_2026-08-03.json`](final_coverage_2026-08-03.json). It counts only derivations supported by retained, unambiguous evidence.

## Public evidence

| Path | Classification |
|---|---|
| `final_coverage_2026-08-03.json` | immutable strict coverage ledger |
| `final_run_queue_2026-08-03.json` | deterministic final matrix minus strict prior coverage |
| `public_logs/cuda_physical_post*_audit.log` | sanitized index-0 per-history audits |
| `public_logs/cuda_firstboot_q28_i0_7_{controller,sweep,audit}.log` | sanitized Q=28 external-indexes-0–7 evidence |
| `cuda_firstboot_vector.json` and related hit files | synthetic first-boot positive controls; no funds |
| `hit_planted_demo.json`, `hit_cuda_planted.json` | synthetic positive controls; no funds |
| `hit_dk27ss_thirdparty.json` | already-public inert demonstration fixture |

The older `public_coverage_snapshot.json` is retained only as a historical snapshot and is superseded by `final_coverage_2026-08-03.json`.

## Excluded evidence

Operational counters, mutable checkpoints, interleaved controller output, missing worker logs, and partial shutdown shards are excluded from the strict total even when they suggest additional work occurred. The exact exclusions are listed in the canonical ledger.

## Never commit

Git ignores production secret material and mutable provider state, including:

```text
artifacts/*_private.json
artifacts/hit_real*.json
artifacts/HIT_FOUND.json
artifacts/budget-run-*/
**/control_private.json
artifacts/cuda_physical_live_post*_checkpointed.log
artifacts/cuda_physical_live_post*_checkpoint.json
```

If a corpus match occurs, publish only the public address, fixed inert BIP322 proof, model coordinates, and evidence hashes. Never commit the mnemonic or private key.
