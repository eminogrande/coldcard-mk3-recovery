# Public handoff: continue the COLDCARD Mk3 recovery research

**Snapshot: 2026-08-02. The corrected search is live. No real-victim key has
been recovered.**

This file is the shortest path for a new researcher to reproduce the validated
parts, avoid already-tested ranges, and improve the next search rather than
starting over.

## 1. Read these first

1. [`README.md`](README.md) — confirmed root cause and minimum reproduction.
2. [`SEARCH_STATUS.md`](SEARCH_STATUS.md) — exact assumptions, intervals and
   no-hit interpretation.
3. [`artifacts/public_coverage_snapshot.json`](artifacts/public_coverage_snapshot.json)
   — machine-readable public coverage ledger.
4. [`EXPERIMENT_LOG.md`](EXPERIMENT_LOG.md) — chronology, failures and corrected
   decisions.
5. [`OPS.md`](OPS.md) — build, validation, checkpoint and hit-handling rules.

## 2. Clone and validate

```sh
git clone https://github.com/eminogrande/coldcard-mk3-recovery.git
cd coldcard-mk3-recovery
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

cd proof
python -m unittest -v test_firstboot_reference.py test_bip322.py
cd ../scan
go test ./...
```

Expected result at this snapshot: eight Python tests pass, the BIP322 negative
controls pass, and the Go scanner tests pass. OpenSSL 3 may print deprecation
warnings for the older SHA-512 C API; those warnings are not test failures.

CUDA validation requires an NVIDIA host:

```sh
cd gpu/cuda
nvcc -std=c++14 -O3 -arch=sm_89 scan.cu -o cscan
```

Before production, run the CPU-vs-CPU vector comparison, exact CUDA stage
comparison, and planted full-scanner target test described in `OPS.md`.

## 3. Do we need the device UID?

**No for a complete search; yes for a much cheaper one.** The vulnerable
firmware reduces the relevant device/timer state to:

```text
pad = UID32 XOR SysTick->VAL
```

The existing full-pad search enumerates all `2^32` pad values, so it covers every
UID/timer preimage without knowing the device. If the actual device's 32-bit UID
word is available, the Mk3's 80 MHz/1 kHz SysTick leaves approximately 80,000
possible timer values. Only `{UID32 XOR t | 0 <= t < 80000}` must then be tested:
about 53,687 times fewer pad candidates.

UID does **not** resolve:

- RTC register state;
- keypad and setup call history (P/Q);
- address path, chain, account or index;
- BIP39 passphrase or dice-derived entropy;
- whether a target address actually belongs to an affected device.

Highest-value implementation task: add a CUDA pad-list input so the 80,000
UID-derived values can be tested directly, and prove its output equals the same
candidates selected from full sequential mode.

## 4. Do not repeat completed work

Use only half-open intervals from
`artifacts/public_coverage_snapshot.json`. At the public snapshot:

```text
model: RTC=0/0, P=2, BIP84 m/84'/0'/0'/0/0, 2,311 bc1q targets
Q=18  [0, 3556769792)
Q=20  [0, 1107296256)
Q=22  [0, 2147483648)
Q=24  [4194304, 3678404608)   # [0,4194304) remains a known gap
Q=26  [0, 2214592512)
Q=28  [0, 1946157056)
Q=30  [0, 1677721600)
```

Those ranges total 16,324,231,168 uniquely evidenced candidates, or
3.80078125 complete 32-bit pad equivalents across different Q histories. They
contained no real-target match. Live workers continued after the snapshot, so
check the repository for a later terminal ledger before renting compute.

## 5. Highest-value next work

1. **UID-aware pad lists:** implement/test explicit non-contiguous pad input.
2. **Derivation coverage:** add index start, change chain/accounts, then BIP44
   and BIP49 for the 23 legacy targets.
3. **Physical traces:** instrument an affected Mk3 to record UID32, actual
   SysTick/RTC state and RNG calls across fresh, interrupted and warm setup.
4. **Corpus provenance:** classify incident addresses as victim receive,
   attacker, change or unrelated; confirm firmware/setup provenance where
   possible.
5. **History generator:** enumerate source-reachable setup histories rather than
   arbitrary chip/mixer Cartesian products.

## 6. Data most useful from an affected device

Collect without publishing seed material:

- firmware version when the seed was created;
- whether creation happened on a freshly erased first boot;
- the 32-bit UID word read by the vulnerable code, if the device survives;
- PIN lengths and exact setup interruptions/retries;
- RTC/warm-reset behavior and USB/settings interactions;
- address script type, account/change branch and receive index;
- whether dice entropy or a BIP39 passphrase was used.

Do not collect or post the mnemonic, seed, xprv or private key.

## 7. Evidence and publication rules

- A planted/demo hit validates machinery, not real-world attribution.
- A no-hit excludes only its exact target hash, RTC, P/Q history, path, indexes
  and pad intervals.
- A real-hit claim requires independent re-derivation and an inert BIP322 proof
  with altered-message/address/signature negative controls.
- Keep real private output mode `0600`, outside Git and public logs.
- Never construct or broadcast a transaction from recovered material.

## 8. Submitting work

Open an issue describing the exact hypothesis, inputs, intervals, hashes and
validation gate before launching expensive compute. Submit code and sanitized
coverage metadata in a pull request. Never attach provider credentials, live
host identifiers, mnemonic/private material or mutable raw worker logs.
