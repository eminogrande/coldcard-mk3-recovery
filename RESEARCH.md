# Research log — corrected enumeration model (2026-08-02)

## Confirmed RNG model

- `shared/seed.py`: `ngu.hash.sha256s(ngu.random.bytes(32))`.
- Libngu combines one `rng_get()` word with one internal Yasmarang word per
  four output bytes.
- Mk3 4.1.9 resolves `rng_get()` to MicroPython's deterministic fallback:
  `pad = UID32 ^ SysTick->VAL`, `n = RTC->TR`, `d = RTC->SSR`.
- Libngu's mixer starts at `{0x0A8CE26F, 69, 233, 0}`.
- Python, Go, Metal, and CUDA recover the same planted keys. A published
  third-party demo target was independently recovered and signed with BIP322.

## RTC correction

Earlier claim that `rtc_init_finalise()` starts RTC and makes `TR` session
uptime was wrong.

- Mk3 sets `MICROPY_HW_ENABLE_RTC=0`; startup does not call
  `rtc_init_start()`.
- `rtc_init_finalise()` returns unless `rtc_init_start()` first set
  `rtc_need_init_finalise`; `RTC_CalendarConfig()` is unreachable here.
- On clean power-up RTC registers reset to `TR=0`, `SSR=0`; no LSE clock is
  enabled to advance them. Warm or modified-device states are separate cases.

Original `rtc=0/0` value was plausible. Those sweeps failed because their RNG
call history was wrong, not because zero RTC was disproven.

## Independent chip and mixer skips

Libngu's `_rand_below()` performs one mixer draw XOR one chip draw. Rejected
samples retry with **mixer-only** draws. Fisher-Yates therefore makes histories
diverge:

```
chip_skip  = mandatory random calls
mixer_skip = chip_skip + _rand_below rejection count
```

Source-derived mandatory chip baselines before `make_new_wallet()`:

| Setup state | Chip baseline | Cause |
|---|---:|---|
| All 32 nvstore slots erased; Terms absent | 3134 | initial shuffle (31) + three 4 KiB noise slots (3072) + Terms-save shuffle (31) |
| Valid prelogin settings; Terms absent | 30 | Terms-save shuffles remaining 31 slots |
| Terms already accepted | 0 | no mandatory save or draw |

Physical keypad scan sessions add three chip draws each because
`mempad._start_scan()` shuffles four rows. Exact session count depends on key
timing. Optional USB encrypted setup, MITM checks, concurrent settings saves,
and unusual flows add more draws. Thus 3134/30/0 are baselines, not complete
universal skips.

## CUDA validation

`gpu/cuda/scan.cu` supports two distinct modes:

```
fixed-skip: pad × chip_skip × mixer_skip × address_index
first-boot: pad × physical P/Q history × address_index
```

An RTX 4090 compiled the source whose SHA-256 is recorded in
`artifacts/cuda_firstboot_sha256sums.txt`. A synthetic model-only vector with
`RTC=0/0`, `chip_skip=3103`, `mixer_skip=3161` was placed in a 2-pad × 3-chip ×
3-mixer window. CUDA returned exactly expected pad, unequal skips, private key,
and HASH160. Debug output matched CPU-reference raw bytes and entropy.

This proves the older split-skip implementation. It does **not** claim
3103/3161 is full
physical first-wallet state; mandatory Terms persistence makes erased-flash
chip baseline 3134 before keypad draws.

The corrected first-boot mode does not enumerate arbitrary skip pairs. For each
candidate pad it replays the initial settings shuffle, 48 noise blocks, P/Q
keypad shuffles, Terms save, and every `_rand_below()` rejection before
emitting the 32 seed bytes. Two independent CPU references agree with that
implementation. On the deployed RTX 4090, a debug candidate matched the CPU
raw bytes, entropy, key and HASH160, and a 100-pad target search recovered
exactly one planted first-boot key.

## Feasibility

Each fixed physical history and derivation boundary needs at most one universal
`2^32` pad pass. UID and SysTick must not be multiplied separately; only their
XOR enters the PRNG. If the relevant 32-bit UID word is known, the 80 MHz/1 kHz
SysTick constrains the useful pad list to approximately 80,000 values, about
53,687 times fewer than a full pass.

The current RTX 4090 measures about 290k source-faithful first-boot candidates/s
at one BIP84 address index, or roughly four hours for one complete pad pass.
Correct total cost still depends on keypad-session histories, wallet paths,
address indices, settings state, optional activity, and RTC state. Coinkite's
preliminary “about 40 bits” estimate has no published composition; it should
not be converted into a cost claim without specifying those dimensions.

## Bottom line

- No real victim key recovered.
- A budget-limited corrected GPU run is live and reuses verified checkpoints.
- The sanitized corrected snapshot totals 16,324,231,168 tested candidates
  (3.80078125 full-pad equivalents) across Q=18–30 at BIP84 external
  index 0; Q=24 has one documented 4,194,304-pad evidence gap.
- Previous `10^15–10^17`/UID-leak conclusion is withdrawn.
- A no-hit eliminates only its exact target hash, P/Q history, RTC/state,
  derivation path, index range, and pad interval. See `SEARCH_STATUS.md` for the
  next experiments and the alternative-truth test.