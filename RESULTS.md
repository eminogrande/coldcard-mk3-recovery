# Results — COLDCARD Mk3 weak-RNG recovery

State: **tool fully validated on 4 engines; real-victim GPU sweep running.**

## Proofs (all reproducible)

| # | Proof | Where |
|---|---|---|
| 1 | Planted wallet recovered from address alone — Python CPU | `ext/ColdCard-38M-PoC/recover.py` (61s) |
| 2 | Same, Go CPU scanner, bit-exact | `scan/ccscan -mode demo` |
| 3 | Same, Apple M4 Metal GPU, bit-exact | `gpu/metal/mscan` |
| 4 | **Third-party artifact**: DK27ss's published demo address `bc1qk92z65wv...lpdj7h` recovered (pad 482111261, skip 2) | `artifacts/hit_dk27ss_thirdparty.json` |
| 5 | BIP322 offline signature on the third-party key: `verify: True` | `artifacts/bip322_proof_dk27ss.txt` |
| 6 | **CUDA on RTX 4090**: planted hit exact (pad 3547157718, skip 3, priv `a735f2a4...`) | `gpu/cuda/scan.cu` |

RNG model cross-validated: 3z (binary-verified vs 4.1.9 firmware) ≡ DK27ss
(on-device) ≡ our ports. Firmware 4.1.9 disassembly confirms
`pad = UID ^ SysTick`, `n = RTC_TR`, `d = RTC_SSR`.

## Bugs found along the way

- Other agent's `hash160.h`: RIPEMD-160 IV constants rotated one slot → GPU could never hit. Fixed.
- Other agent's "universal 69/233" RNG model: 69/233 are libngu *mixer* constants, not chip RTC values. Disassembly disproved it; their `goscan` sweep is wasted CPU.
- Our CUDA host: `vector<array<uchar,20>>::size()` returns elements, not bytes → target buffer 1/20th sized → `targetHit` searched garbage. Fixed.
- `#pragma unroll 16` miscompiled the SHA-512 ring schedule (wrong results in `scanKernel` only, correct in `debugCandidate` — classic optimization-dependent UB). Removed.

## Targets

- `targets/all_bc1q.txt` — 2,311 drained P2WPKH addresses: 2,298 coldcard-watch + 13 Bill Fowler (extracted from the drain-tx inputs onchain). 23 non-segwit (P2PKH/P2SH) addresses from the drain list are NOT covered yet — need BIP44/49 derivation in-kernel (next step).

## Cost / performance

- Apple M4 CPU (Go): ~3k cand/s. M4 Metal: ~9k cand/s.
- RTX 4090 (vast.ai, $0.259/h): ~140k cand/s → 2^32 × 3 skips ≈ 34 h ≈ $8.
- Real sweep (running): rtc 0/0, skip 0–2, idx 0–7, all 2,311 targets.
- Remaining hypotheses if no hit: skip 3–8, then RTC≠0 windows, then BIP44/49 targets. Est. $20–60 total.

## Legal scope

Drained addresses (balance 0) only; research on public data. Never broadcast
from derived keys. Still-funded vulnerable wallets: notify owner only.
