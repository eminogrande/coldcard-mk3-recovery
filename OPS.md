# Operations runbook

**STATUS 2026-08-02: eight corrected first-boot Vast.ai GPU workers are live.
Historical Hetzner/local fixed-skip workers are stopped. No real-victim hit
exists as of this snapshot.**

## Current production boundary

```text
GPU fleet           2080 Ti/3060/3090/4060 Ti/4070/4070 Ti/4070S/4090
aggregate rental    approximately $0.925/hour at snapshot
reference build     CUDA 12.4, sm_89 on RTX 4090
source mode         first-boot (-F), not manual skip Cartesian mode
RTC                 TR=0, SSR=0 clean-cold-boot hypothesis
pre-Terms sessions  P=2
post-Terms sessions Q selected per pass
path                m/84'/0'/0'/0/index
active targets      targets/all_bc1q.txt (2,311 P2WPKH addresses)
private output      remote mode 0600, ignored by Git
```

Do not present the Metal scanner as first-boot-capable. It implements the older
fixed-skip model. The corrected physical-flow production kernel is CUDA
`gpu/cuda/scan.cu`.

## Prerequisites

- Use Python 3.11 for the Vast.ai CLI virtualenv. The host's older Xcode Python
  fails on dependencies that use dataclass slots.
- Obtain the Vast.ai API credential from 1Password at runtime. Never paste it
  into this repository, shell scripts, logs, GitHub, or documentation.
- On SSH, force the specifically registered key:

```sh
ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -p "$PORT" root@"$HOST"
```

Without `IdentitiesOnly=yes`, the 1Password/agent key set can trigger “too many
authentication failures.”

## Build discipline

Upload only the pinned public inputs:

```text
gpu/cuda/scan.cu
scan/bip39_english.txt
targets/all_bc1q.txt
proof/firstboot_reference.py
```

Build on the GPU host:

```sh
nvcc -std=c++14 -O3 -arch=sm_89 scan.cu -o cscan
```

This translation unit can take roughly 11 minutes to compile. An SSH timeout
does not prove `nvcc` stopped. Before retrying, inspect `nvcc`, `cicc`, `ptxas`,
and `cudafe`; kill duplicate builds and leave one clean compiler process.

Record hashes before scanning:

```sh
sha256sum scan.cu cscan bip39_english.txt all_bc1q.txt
```

Current pinned values are in `SEARCH_STATUS.md`.

## Mandatory validation gate

Never spend the production budget after a source/compiler/target change until
all three gates pass:

1. CPU reference and independent CPU flow agree on raw RNG bytes, entropy,
   chip/mixer draw counts, HASH160 and address.
2. The exact deployed CUDA debug candidate agrees at every stage.
3. The exact deployed scanner finds one expected planted address in a tiny pad
   interval and writes private output mode `0600`.

A debug-vector match alone does not test target loading or hit emission. The
small full-path target search is mandatory.

## Production command

For one source-faithful first-boot history:

```sh
./cscan \
  -t all_bc1q.txt -w bip39_english.txt \
  -r 0 -s 0 \
  -F 2 -A "$Q" -C 1 \
  -i "$INDEX_COUNT" \
  -p "$PAD_START" -e 4294967296 \
  -b 4194304 \
  -o "hit_real_q${Q}_i${INDEX_COUNT}_private.json"
```

Semantics:

- pad interval is half-open `[PAD_START, 4294967296)`;
- `-F 2` enables the physical first-boot flow with P=2;
- `-A Q -C 1` tests exactly one post-Terms session history;
- `-i N` derives external receive indexes `[0,N)`;
- `-r/-s 0` pins the clean cold-boot RTC hypothesis;
- output contains private material only on hit.

Do not add manual chip/mixer skip ranges to a first-boot command. Current code
rejects contradictory combinations.

## Checkpoint/resume rules

A checkpoint is valid only when all of these match:

- `scan.cu` SHA-256;
- BIP39 wordlist SHA-256;
- target-file SHA-256;
- RTC, P, Q, path and index count;
- log contains the exact candidate interval and an exhausted/no-hit terminal
  line;
- the next pad equals the end of the completed half-open interval.

Never infer completion from elapsed time, an SSH disconnect, or a missing
process. Never advance a checkpoint on CUDA error, timeout, OOM, provider stop,
or absent terminal counter.

Seven current shard workers reuse local mutable checkpoint files that are
Git-ignored. The public immutable ledger is
`artifacts/public_coverage_snapshot.json`, with sanitized audit summaries under
`artifacts/public_logs/`. The documentation audit stopped a duplicate 4090
Q=22/index-0 pass after all public hashes matched and reassigned that GPU to
Q=22 indexes 0–7. Q=24 has a documented `[0,4,194,304)` evidence gap that must
be backfilled before a full-coverage claim.

## Monitoring

Live health check:

```sh
nvidia-smi --query-gpu=utilization.gpu,power.draw,power.limit,temperature.gpu \
  --format=csv,noheader
pgrep -af cscan
tail -3 /root/sweep_*.log
```

Healthy index-0 first-boot rate on the current 4090 is approximately 0.29
million candidates/second at 100% utilization. Low VRAM utilization is normal:
this kernel is compute-bound.

The local script `~/.hermes/scripts/coldcard-budget-watch.sh` runs every five
minutes outside this repository. It emits nothing during healthy operation. It
detects local hit files from every checkpoint worker and the remote 4090 hit
marker. It reports and destroys all running rentals on:

- a nonempty `/root/HIT_FOUND.json`;
- credit at or below $0.40;
- all workers stopped;
- provider/instance stop or controller failure.

The controller and watchdog intentionally stay outside Git because they contain
live connection/contract metadata. This document records behavior, not secrets.

## Hit handling

On a hit:

1. Stop `cscan` and the controller immediately; do not continue spending.
2. Copy the hit via SCP into a local directory mode `0700`; keep the file mode
   `0600` and confirm its SHA-256.
3. Independently derive the public key/HASH160/address from the private key and
   confirm it equals both the hit and target.
4. Sign the fixed inert research message using `proof/bip322.py`, then verify
   with the local verifier and a second implementation plus negative controls.
5. Destroy the GPU only after hit/log collection is verified. Commit only the
   public address, fixed message, proof, hashes, coverage and reproduction
   metadata—never mnemonic/private key material.

Never create or broadcast a Bitcoin transaction.

## No-hit shutdown

When budget or planned coverage ends:

1. collect every sweep log, controller log, source/binary hashes and final Vast
   account/instance summary;
2. calculate exact completed half-open intervals—do not count a partial batch as
   complete;
3. destroy the instance and verify it no longer appears as running;
4. update `RESULTS.md`, `EXPERIMENT_LOG.md` and `SEARCH_STATUS.md` with terminal
   coverage/cost;
5. choose the next experiment from the no-hit decision tree instead of rerunning
   an exhausted range.

## Historical fleet

Earlier local, Hetzner and Vast.ai workers tested fixed skip hypotheses such as
chip 0–8/mixer 0. They are stopped. Their logs/checkpoints remain useful only as
exact negative fixed-state evidence and implementation controls; they are not
fresh-device first-wallet coverage.
