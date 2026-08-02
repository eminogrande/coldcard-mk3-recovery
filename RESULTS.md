# Results ledger

**State (2026-08-02): the corrected first-boot search is live; implementation
validated end to end; no real-victim hit recovered as of this snapshot.**

## Validation results

| # | Test | Result / evidence |
|---:|---|---|
| 1 | Python planted wallet: address-only recovery | exact mnemonic/key/HASH160 (`artifacts/hit_planted_demo.json`) |
| 2 | Go planted wallet | exact same recovery (`scan/hit.json`) |
| 3 | Apple M4 Metal planted target | exact hit |
| 4 | CUDA planted target | exact hit (`artifacts/hit_cuda_planted.json`) |
| 5 | Independent DK27ss 38M public demo | exact address-only recovery (`artifacts/hit_dk27ss_thirdparty.json`) |
| 6 | BIP322 inert message proof | signs/verifies; message mutation fails (`artifacts/bip322_proof_dk27ss.txt`, unit tests) |
| 7 | Split chip/mixer CUDA Cartesian control | exact `(pad=3547157718, chip=3103, mixer=3161)` (`artifacts/cuda_firstboot_*`) |
| 8 | Corrected physical-flow CPU references | bit-identical raw bytes, entropy, and draw counts across diverse P/Q/pad vectors |
| 9 | Deployed RTX 4090 debug vector | raw RNG bytes, entropy, key, and HASH160 match CPU reference |
| 10 | Deployed full scanner positive control | exact planted first-boot key emitted from a 100-pad target search |
| 11 | Real drained-address recovery | **not yet observed** |

The live positive control proves target loading, source-faithful RNG replay,
BIP39/PBKDF2, BIP32/BIP84 derivation, HASH160 lookup, and private-output handling
inside the exact deployed GPU binary. It does not establish that a listed
incident address used the tested physical history.

## Corrected physical model

The historical `chip_skip=0..8, mixer_skip=0` real-target sweeps were not a
valid fresh-wallet test. A fully erased first wallet consumes:

```text
31       initial nvstore shuffle
3072     48 × random.bytes(256) noise generation
3P       P pre-Terms keypad scan sessions
31       first Terms/settings save shuffle
3Q       Q post-Terms keypad scan sessions
------------------------------------------------
3134 + 3(P+Q) chip words before the seed bytes
```

Libngu rejection retries consume mixer-only words, so `mixer_skip` is
pad-dependent. The corrected CUDA `-F` mode replays these operations per
candidate; it does not scan a guessed fixed mixer offset.

For clean cold boot, Mk3 builds have `MICROPY_HW_ENABLE_RTC=0`, supporting
`RTC_TR=RTC_SSR=0`. `UID_low32 XOR SysTick->VAL` then collapses to one universal
32-bit `pad`; one full pad pass covers every UID/timer preimage for a fixed
physical and derivation history.

## Corrected real-target negative coverage

The source, wordlist, and target hashes for all rows are pinned in
[`SEARCH_STATUS.md`](SEARCH_STATUS.md). Every 2^25-pad shard ran a planted
positive control before production, and a checkpoint advanced only after the
scanner printed its exhausted candidate count.

| Q | Exhausted range at snapshot | Fraction of full pad | Result |
|---:|---:|---:|---|
| 18 | `[0, 3,556,769,792)` | 82.8125% | no target match |
| 20 | `[0, 1,107,296,256)` | 25.78125% | no target match |
| 22 | `[0, 2,147,483,648)` | 50.00% | no target match |
| 24 | `[4,194,304, 3,678,404,608)` | 85.546875% | no target match; first 4,194,304 not evidenced |
| 26 | `[0, 2,214,592,512)` | 51.5625% | no target match |
| 28 | `[0, 1,946,157,056)` | 45.3125% | no target match |
| 30 | `[0, 1,677,721,600)` | 39.0625% | no target match |

Sanitized public snapshot at `2026-08-02T18:19:44Z`:
**16,324,231,168 candidates**, equivalent to **3.80078125 full 32-bit pad
passes** distributed across seven Q histories, BIP84
account-0 external index 0, and 2,311 target addresses.

Machine-readable intervals: `artifacts/public_coverage_snapshot.json`.
Sanitized per-history audits: `artifacts/public_logs/`. Mutable provider logs
and checkpoint files stay local and Git-ignored.

## Active run

Eight live single-GPU workers run at an aggregate rental rate of approximately
$0.925/hour. Seven checkpoint workers complete Q=18,20,22,24,26,28,30 at BIP84
external index 0. The RTX 4090 scans Q=22 receive indexes 0–7, then Q=32/34 and
adjacent histories as budget allows. Its measured index-0 rate was
approximately **0.29 million candidates/second**.

The documentation audit detected that an initially launched 4090 Q=22/index-0
pass duplicated the dedicated Q=22 checkpoint worker. It was stopped and the
4090 was reassigned to indexes 0–7. Source/wordlist/target SHA-256 values match
the historical logs exactly, so all seven checkpoint workers retain their
verified ranges.

## Historical negative evidence

Earlier CPU/Metal/CUDA fleets found no real target under later-session fixed
skip hypotheses, including `RTC=0/0`, chip skips 0–8, and mixer skip 0. Those
runs validate parts of the implementation and eliminate only their exact
states. They do **not** test a normal fresh-erased first wallet and should not be
combined with the corrected coverage table.

## Interpretation threshold

A real-world exploit claim requires all of the following:

1. one recovered private key matches a listed drained address;
2. the hit is reproduced independently from the recorded public state;
3. an inert BIP322 proof verifies in at least two implementations;
4. altered message/address/signature negative controls fail;
5. no transaction is created or broadcast.

Until then, the defensible result is: **the firmware weakness and recovery
pipeline are reproduced; the tested target/history combinations have not
produced a real hit.**

For exact assumptions and the next experiments after a no-hit, see
[`SEARCH_STATUS.md`](SEARCH_STATUS.md).
