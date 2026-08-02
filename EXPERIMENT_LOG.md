# Experiment log

**STATUS 2026-08-02: corrected first-boot GPU search live; no real-victim hit
as of this snapshot.**

## Phase 1 — pipeline reconstruction

1. Reimplemented the Mk3 v4 fallback RNG, libngu mixer, SHA-256, BIP39,
   PBKDF2-HMAC-SHA512, BIP32/BIP84 and P2WPKH matching in Python and Go.
2. Recovered a planted address from address-only input, then reproduced the
   same key in Apple Metal and NVIDIA CUDA.
3. Independently recovered DK27ss's published 38M demo target.
4. Created an inert BIP322 proof and verified positive and negative controls.

Result: the address → candidate seed → private-key pipeline works. This phase
did not prove the call history of a physical first wallet.

## Phase 2 — historical real-target sweeps

The first CPU/GPU fleets searched `RTC=0/0`, chip skips approximately 0–8,
mixer skip 0, and receive indexes 0–7/15 depending on worker. No listed target
matched.

Those negative results are retained as exact fixed-state evidence, but their
physical interpretation was withdrawn. A freshly erased first wallet has
already consumed thousands of RNG words before `make_new_wallet()`.

## Phase 3 — source corrections

### RTC

An intermediate analysis incorrectly concluded that `rtc_init_finalise()`
started the RTC and made `TR` track session uptime. Pinned Mk3 configuration
shows `MICROPY_HW_ENABLE_RTC=0`; `rtc_init_start()` is not reached and
`rtc_init_finalise()` returns. Clean cold boot therefore supports
`RTC_TR=RTC_SSR=0`. Warm/retained or modified-device states remain separate
hypotheses.

### Fresh-device baseline

Pinned `nvstore.py`, `seed.py`, and `mempad.py` yield:

```text
initial empty-slot shuffle                  31 chip draws
three 4 KiB noise slots                     3072 chip draws
first Terms/settings save                   31 chip draws
keypad sessions                             3 chip draws each
```

The mandatory erased-flash baseline is 3,134 chip words, plus physical keypad
sessions before and after the Terms save.

### Mixer divergence

Libngu `_rand_below()` retries rejected values using mixer-only words. Mixer
position is therefore candidate/pad-dependent and cannot be represented by one
fixed offset. This explained why merely moving the old chip skip to 3,134 would
still be wrong.

## Phase 4 — corrected implementation validation

1. Added `proof/firstboot_reference.py`, a source-faithful CPU model of nvstore,
   noise generation, Terms persistence, keypad shuffles, seed generation, and
   BIP84 derivation.
2. Added the independently written `proof/firstboot_flow.py` cross-check.
3. Compared both references across diverse pads and P/Q histories: raw bytes,
   entropy, chip count, and mixer count matched bit for bit.
4. Added CUDA first-boot mode (`-F/-A/-C`) that replays the flow per pad and
   rejects contradictory manual skip ranges.
5. Compiled the deployed binary for RTX 4090 (`sm_89`, CUDA 12.4). A debug
   candidate matched the CPU reference at every recorded stage.
6. Ran a full target-path positive control over a 100-pad interval. It recovered
   exactly the expected planted pad/key and no other hit.

Production fingerprints:

```text
scan.cu               9ffb27b69352a431c39d1c59040bbbc463d1a6b703825803bbcc244f5a9dd08e
bip39_english.txt      2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
all_bc1q.txt           e046efba8a8baf55493e3628c61cd266fe6348da9a37cd39c370e01e3396466a
current cscan binary   471256263d8d9626582e1e383965c76f93bc507093516c47a70d4db20655bc29
```

## Phase 5 — checkpointed corrected real-target search

The first corrected production jobs used 2^25-pad shards. Each shard:

1. checked the public source/wordlist/target hashes;
2. ran a tiny first-boot positive control;
3. scanned 2,311 real P2WPKH targets at BIP84 external index 0;
4. required `[cscan] exhausted ... no hit` before advancing the checkpoint;
5. wrote the next half-open pad boundary to JSON.

Sanitized public state at `2026-08-02T18:19:44Z`:

| Q | Exhausted pad prefix | Coverage |
|---:|---:|---:|
| 18 | `[0, 3,556,769,792)` | 82.8125% |
| 20 | `[0, 1,107,296,256)` | 25.78125% |
| 22 | `[0, 2,147,483,648)` | 50.00% |
| 24 | `[4,194,304, 3,678,404,608)` | 85.546875%; first 4,194,304 not evidenced |
| 26 | `[0, 2,214,592,512)` | 51.5625% |
| 28 | `[0, 1,946,157,056)` | 45.3125% |
| 30 | `[0, 1,677,721,600)` | 39.0625% |

Reconciled snapshot total: 16,324,231,168 corrected candidates, or 3.80078125
full-pad equivalents spread across seven Q histories. No target matched.

The earlier monolithic Q=24 log starts at pad `4,194,304`, proves progress
through `322,961,408`, then ends with a CUDA launch failure. The checkpointed
replacement continues from there. Because no preserved terminal evidence
covers `[0,4,194,304)`, that interval is excluded until explicitly backfilled.

The public machine-readable ledger is
`artifacts/public_coverage_snapshot.json`; concise sanitized audits are under
`artifacts/public_logs/`. Mutable provider logs/checkpoints remain local and
Git-ignored.

## Phase 6 — current budget continuation

Seven checkpoint workers were already live when a cost-efficient RTX 4090 was
added with approximately $12.91 account credit available. The resulting fleet
contains eight single-GPU workers at approximately $0.925/hour aggregate. The
exact deployed 4090 binary passed stage and full-path positive controls before
production; every checkpoint shard also runs its planted control.

The first 4090 command mistakenly restarted Q=22/index 0 from pad zero while a
dedicated RTX 4070 checkpoint worker was already advancing the same history.
During the repository/documentation audit, the fleet processes and changing
checkpoint files were discovered. Source, BIP39 and target hashes matched. The
duplicated 4090 work was stopped at pad 473,956,352 and is not counted as new
negative coverage.

The RTX 4090 was reassigned to Q=22 receive indexes 0–7. At index count 1 it
measured approximately 0.29 million candidates/second at 100% GPU utilization.
The non-overlapping fleet plan is:

1. seven checkpoint workers finish Q=18,20,22,24,26,28,30 index 0;
2. the 4090 runs Q=22, indexes 0–7;
3. the 4090 then runs Q=32 and Q=34 index 0 from pad zero;
4. remaining credit goes to adjacent Q=21 and Q=23;
5. backfill the Q=24 `[0,4,194,304)` evidence gap before a completion claim.

A five-minute local watchdog is silent while healthy. It detects remote 4090
hits and local private-hit files from all seven shard workers. On hit, provider
stop, or credit below $0.40 it signals the fleet stop, collects private/log
artifacts, destroys every running rental, and reports once.

## Pending terminal record

When the controller stops, append:

- exact completed half-open ranges for every Q/index combination;
- final source/binary/target hashes;
- wall-clock GPU time, rate and cloud spend;
- real hit and independently verified BIP322 proof, **or** exact no-hit scope;
- unsearched dimensions and the next hardware/corpus experiment.

The interpretation rules and prioritized no-hit decision tree live in
[`SEARCH_STATUS.md`](SEARCH_STATUS.md).
