# COLDCARD Mk2/Mk3 weak-RNG key-recovery research

Independent reproduction of the July 2026 COLDCARD entropy failure affecting
Mk2/Mk3 seeds created on firmware 4.0.1–4.1.9. A link-time integration mistake
wired wallet seed generation to MicroPython's deterministic Yasmarang fallback
instead of the STM32 hardware TRNG.

**Current state (2026-08-02): the source-faithful first-boot GPU search is
running against 2,311 drained P2WPKH addresses. No real-victim hit has been
recovered as of this commit.**

Start here:

- [`HANDOFF.md`](HANDOFF.md) — clone, validate, avoid duplicate ranges, and pick
  up the highest-value next task;
- [`SEARCH_STATUS.md`](SEARCH_STATUS.md) — exact assumptions, verified negative
  coverage, active plan, and what to do if every funded pass returns no hit;
- [`BLOG_POST.md`](BLOG_POST.md) — plain-language story for a general reader;
- [`BLOG.md`](BLOG.md) — technical reconstruction and validation ledger;
- [`RESEARCH.md`](RESEARCH.md) — source-derived model and corrections;
- [`RESULTS.md`](RESULTS.md) — evidence table and measured results;
- [`OPS.md`](OPS.md) — historical and current compute runbook.

## What is confirmed

```text
shared/seed.py:  random.bytes(32) → SHA-256 → BIP39 entropy
shared/random.py: bytes = ngu.random.bytes
libngu:           rng_get() XOR fixed-state Yasmarang mixer
Mk3 build:        MICROPY_HW_ENABLE_RNG = 0
linked rng_get(): MicroPython deterministic Yasmarang fallback
```

The fallback initializes from:

```text
pad = UID_low32 XOR SysTick->VAL
n   = RTC->TR
d   = RTC->SSR
```

For the clean cold-boot model, the Mk3 RTC is not initialized and the registers
remain `0/0`. UID and SysTick collapse into one 32-bit `pad`, so one
`pad=[0,2^32)` pass covers all UID/timer preimages under those conditions. No
per-device UID is needed for that pass.

### Is knowing UID useful?

**Yes—very useful, but not required.** A full `2^32` pad sweep is complete
without UID. If the 32-bit UID word read by the firmware is known, the Mk3's
80 MHz/1 kHz SysTick limits the timer side to approximately 80,000 values. The
candidate pad set then shrinks to `{UID32 XOR t | 0 <= t < 80000}`: about
**53,687× fewer pad candidates**.

UID does not reveal RTC state, setup/keypad call history, derivation path,
passphrase or dice use. See [`HANDOFF.md`](HANDOFF.md) for the proposed CUDA
pad-list implementation and the other metadata needed to turn UID into a much
smaller useful search.

## Why the original two-day search did not hit

The key pipeline was correct; its call-history hypothesis was not.

The historical fleet scanned `chip_skip=0..8` with `mixer_skip=0`. A wallet
created on a freshly erased device consumes approximately 3,134 chip words
before seed generation: initial nvstore shuffle (31), three 4 KiB noise writes
(3,072), and the Terms/settings-save shuffle (31), plus keypad-session draws.
The old scan was therefore thousands of calls too early.

Libngu `_rand_below()` makes this subtler: rejections advance only its fixed
mixer stream. The correct mixer offset is pad-dependent. Current CUDA
first-boot mode replays the actual source flow per candidate instead of guessing
a fixed pair of skips.

## Evidence ladder

| Proof | Result |
|---|---|
| Planted address-only recovery on Python and Go | exact |
| Same planted target on Apple Metal and CUDA | bit-identical |
| Independently published DK27ss demo address | recovered; inert BIP322 verifies |
| Corrected first-boot flow in two CPU references | bit-identical across test vectors |
| Deployed RTX 4090 stage comparison | raw bytes, entropy, key, and HASH160 equal CPU reference |
| Live 100-pad first-boot positive control | exactly one expected key recovered |
| Real drained-address match | **not yet observed** |

A demo hit proves the pipeline. Only a real address match followed by an
independently verified inert BIP322 signature proves control of a listed real
key.

## First-boot model

```text
initial shuffle(32)
48 × random.bytes(256)          # three 4 KiB noise slots
P × keypad shuffle(4)           # before Terms save
Terms/settings shuffle(32)
Q × keypad shuffle(4)           # before New Wallet
random.bytes(32) → SHA-256 → BIP39 → BIP84 → P2WPKH
```

```text
chip_skip = 3134 + 3 × (P + Q)
mixer_skip = chip_skip + candidate-dependent rejection draws
```

The standard fully separated first-PIN path gives
`Q = 2 × total_PIN_digits + 10`, or Q=18,20,…34 for 4–12 total digits. Fast
physical keypresses can merge scan sessions, so those nine even values are
high-priority histories, not an exhaustive set.

## Reproduce the validation

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

cd proof
python -m unittest -v test_firstboot_reference.py test_bip322.py

cd ../scan
go test ./...

cd ../gpu/cuda
nvcc -std=c++14 -O3 -arch=sm_89 scan.cu -o cscan
```

Synthetic first-boot reference:

```sh
python proof/firstboot_reference.py \
  --pad 0xD36D2096 --pre-terms-sessions 2 --post-terms-sessions 17 \
  --index 0 --output control_private.json --target-output control_target.txt
```

Source-faithful CUDA search (Q=22, index 0, full pad):

```sh
./gpu/cuda/cscan \
  -t targets/all_bc1q.txt -w scan/bip39_english.txt \
  -r 0 -s 0 -F 2 -A 22 -C 1 -i 1 \
  -p 0 -e 4294967296 -b 4194304 -o hit_real_private.json
```

`-F` enables physical first-boot mode and sets pre-Terms sessions. `-A/-C`
select a contiguous post-Terms session range. First-boot mode rejects manual
fixed chip/mixer offsets so the command cannot silently contradict the physical
model.

## Scope that is not yet covered

- 23 legacy P2PKH/P2SH targets need BIP44/BIP49 derivation;
- change-chain, account, and wider address-index ranges are incomplete;
- warm/retained RTC states and alternate settings/setup histories are separate
  hypotheses;
- dice-derived seeds and unknown BIP39 passphrases are outside this enumeration;
- the public incident list is on-chain evidence, not proof that every address is
  an affected Mk2/Mk3 first-wallet address.

See [`SEARCH_STATUS.md`](SEARCH_STATUS.md) before interpreting any no-hit.

## Safety boundary

- Drained, balance-zero addresses and clearly labeled synthetic/public demo
  targets only.
- Never create or broadcast a transaction from recovered material.
- Keep any real hit mode `0600`, off Git and off public logs.
- Publish only an inert BIP322 message proof independently verified with
  negative controls.
- For a still-funded vulnerable wallet: notify the owner; never sweep it.

## Primary references

- [Coinkite: *Technical Deep Dive into the Entropy Issue*](https://blog.coinkite.com/entropy-technical-backgrounder/)
- [Block Engineering: *Predictable RNG Fallback and 32-Bit Reseed in COLDCARD Firmware*](https://engineering.block.xyz/blog/predictable-rng-fallback-and-32-bit-reseed-in-coldcard-firmware)
- [`3z/coldcard-mk3-rng-disclosure`](https://github.com/3z/coldcard-mk3-rng-disclosure)
  — binary-verified reconstruction
- [`DK27ss/ColdCard-38M-PoC`](https://github.com/DK27ss/ColdCard-38M-PoC)
  — independent pipeline and split-skip analysis
- [COLDCARD firmware tag `2023-06-26T1241-v4.1.9`](https://github.com/Coldcard/firmware/tree/2023-06-26T1241-v4.1.9)
