# Artifact manifest and data classification

This directory contains reproducibility evidence. Some fixtures contain private
keys, but only for deterministic synthetic wallets or already-public inert demo
wallets that never held funds.

## Key-bearing public fixtures

| File | Classification |
|---|---|
| `hit_planted_demo.json` | synthetic planted wallet; no funds |
| `hit_cuda_planted.json` | synthetic planted wallet; no funds |
| `hit_dk27ss_thirdparty.json` | independently published public demo wallet; inert |
| `cuda_firstboot_vector.json` | synthetic split-skip control; explicitly labeled in JSON |
| `cuda_firstboot_hits.json` | raw CUDA output for `cuda_firstboot_vector.json`; same synthetic key |
| `cuda_physical_firstboot_vector.json` | synthetic source-faithful physical-flow control; explicitly labeled in JSON |

BIP322 files prove control only of those inert fixtures. They are not evidence
of a real-victim recovery.

## Real-target evidence

`public_coverage_snapshot.json` records exact merged half-open intervals,
fingerprints, control/error counts and SHA-256 provenance at a fixed timestamp.
`public_logs/` contains concise per-history sanitized audits. Mutable raw
provider logs and live checkpoint JSONs stay local and Git-ignored; they contain
no scientific input absent from the public ledger. A production hit is written
separately with mode `0600` and immediately triggers fleet shutdown.

## Never commit

`.gitignore` excludes all production secret forms:

```text
artifacts/*_private.json
artifacts/hit_real*.json
artifacts/HIT_FOUND.json
artifacts/budget-run-*/
**/control_private.json
artifacts/cuda_physical_live_post*_checkpointed.log
artifacts/cuda_physical_live_post*_checkpoint.json
```

If a real target ever matches, Git may contain only the public address, fixed
inert message, BIP322 proof, hashes, and coverage metadata—never the recovered
private key or mnemonic.
