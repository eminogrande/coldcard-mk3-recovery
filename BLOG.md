# Rebuilding the COLDCARD Mk3 weak-RNG recovery pipeline

*Independent reproduction of the July 2026 COLDCARD RNG vulnerability,
including bit-exact CPU/GPU implementations, failed assumptions, and corrected
split-state search model.*

## Executive summary

- COLDCARD Mk2/Mk3 firmware 4.0.1–4.1.9 routed wallet seed generation through
  MicroPython's deterministic Yasmarang fallback, not STM32 hardware TRNG.
- Full seed-to-address pipeline was reconstructed in Python, Go, Apple Metal,
  and CUDA. Planted targets were recovered on every applicable engine.
- A separately published demo target was recovered and proved with BIP322. It
  was a public demo, **not a drained victim**.
- **No real victim key was recovered as of this snapshot.** A corrected,
  budget-limited RTX 4090 search is live.
- Earlier fleet searched `RTC=0/0`, chip skip 0–8, mixer skip 0. RTC was
  plausible; call-history model was wrong. Libngu shuffle retries advance only
  mixer, and fresh-device setup consumes thousands of words.
- Correct CUDA scanner supports both independent fixed-skip ranges and a
  source-faithful physical first-boot mode. The deployed RTX 4090 recovered
  exact split-skip and physical-flow controls with bit-identical stages.

## 1. Root cause

Three repositories compose failure: `Coldcard/firmware`, `switck/libngu`, and
`Coldcard/micropython`.

```text
shared/seed.py:   seed = ngu.hash.sha256s(ngu.random.bytes(32))
shared/random.py: bytes = ngu.random.bytes
libngu random.c:  chip = CHIP_TRNG_32(); chip ^= my_yasmarang()
mpconfigboard.h:  MICROPY_HW_ENABLE_RNG = 0
MicroPython:      rng_get() = deterministic Yasmarang fallback
```

Libngu tested whether `MICROPY_HW_ENABLE_RNG` was defined, not whether its
value was nonzero. Build succeeded while libngu's global `rng_get()` resolved
to fallback implementation.

Fallback initializes once:

```c
rtc_init_finalise();
pad = *(uint32_t *)MP_HAL_UNIQUE_ID_ADDRESS ^ SysTick->VAL;
n   = RTC->TR;
d   = RTC->SSR;
```

Shipping Mk3 4.1.9 disassembly confirms SysTick, UID, RTC register reads, then
Yasmarang transition. Independent Python replicas agree byte-for-byte with our
Go, Metal, and CUDA ports.

## 2. Full candidate pipeline

```text
(pad, rtc_tr, rtc_ssr, chip_skip, mixer_skip)
  chip  = Yasmarang(pad, rtc_tr, rtc_ssr)
  mixer = Yasmarang(0x0A8CE26F, 69, 233)
  advance chip and mixer independently
  raw[8] = chip.next() XOR mixer.next()
  entropy = SHA256(raw bytes)
  mnemonic = BIP39(entropy)
  seed64 = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048)
  derive m/84'/0'/0'/0/index
  compare P2WPKH HASH160 against every target
```

Validation ledger:

| Proof | Result |
|---|---|
| Planted address-only recovery, Python | exact |
| Same planted target, Go | bit-identical |
| Same planted target, Apple Metal | bit-identical |
| Same planted target, CUDA/RTX 4090 | bit-identical |
| Independently published demo address | key recovered; BIP322 verifies |
| Split-skip Cartesian CUDA control | exact unequal chip/mixer skips |
| Corrected first-boot CPU references | bit-identical across diverse vectors |
| Deployed full-path first-boot GPU control | exact planted key from target search |
| Real drained-address target | **not yet recovered** |

Artifacts live under `artifacts/`. Synthetic material is clearly labeled and
never held funds.

## 3. RTC correction

Initial analysis made a serious source-reading error: seeing
`rtc_init_finalise()` before RTC reads, it inferred RTC started and `TR`
represented session uptime. Pinned MicroPython source disproves this.

- Mk3 has `MICROPY_HW_ENABLE_RTC=0`.
- Startup does not call `rtc_init_start()`.
- `rtc_init_finalise()` returns unless `rtc_init_start()` set its flag.
- Clean power-on resets `RTC->TR` and `RTC->SSR` to zero; no LSE clock is
  enabled to advance them.

So `RTC=0/0` is supported for clean cold boot. Warm, retained, debug, or
modified-device states can differ. Earlier zero-RTC sweeps missed because call
history was incomplete, not because RTC zero was impossible.

## 4. Why one skip is wrong

Libngu maintains another deterministic Yasmarang mixer. `random.bytes()` and
`random_uint32()` advance chip and mixer one-to-one. `_rand_below()`, used by
Fisher-Yates, differs:

```c
pt = my_yasmarang();
pt ^= CHIP_TRNG_32();
while ((pt & mask) >= mx) {
    pt ^= my_yasmarang();       // mixer-only retry
}
```

Every shuffle step consumes exactly one chip word but possibly several mixer
words. Correct state has `chip_skip` and `mixer_skip`.

Source-derived mandatory chip baselines:

| Device/settings state | Chip baseline |
|---|---:|
| All 32 settings slots erased, Terms absent | 3134 |
| Valid settings exist, Terms absent | 30 |
| Terms already accepted | 0 |

For erased storage: first load shuffles 32 slots (31 chip draws), writes three
4 KiB noise slots (3072 draws), then Terms persistence shuffles 32 slots again
(31 draws): `31 + 3072 + 31 = 3134`.

Every physical keypad scan session shuffles four rows, adding three chip draws
plus mixer-only rejections. Key timing determines session count. Optional USB,
other settings saves, and alternate flows add more calls.

This is why `3103/3161` artifact is synthetic: it proves scanner axes, but
mandatory Terms save means 3103 is not full erased-flash wallet baseline.

## 5. CUDA implementation and validation

The kernel has two explicit modes:

```text
fixed-skip: pad × chip_skip × mixer_skip × address_index
first-boot: pad × physical P/Q history × address_index
```

First-boot mode replays the nvstore/noise/Terms/keypad operations and
candidate-dependent mixer rejections inside each GPU thread. It also fixes the
earlier target-buffer byte-count bug, an optimization-sensitive SHA-512
unroll, final partial-batch/grid bounds, numeric overflows, conflicting flags,
and private-buffer cleanup.

Validation used two layers:

1. The historical 18-candidate Cartesian control recovered exactly
   `(pad=3547157718, chip=3103, mixer=3161)` and matched CPU raw bytes, entropy,
   private key and HASH160.
2. Two independent CPU first-boot references matched each other. The exact
   deployed RTX 4090 binary matched a representative Q=22 candidate at every
   stage, then recovered the exact planted key from a 100-pad target search.

The second layer is important: a debug candidate does not test target loading
or hit emission; the tiny full-path search does.

## 6. Measured search and result

For a fixed physical history and derivation boundary, enumerating all `2^32`
pad values is universal. UID and SysTick enter only as XOR, so multiplying them
as independent spaces double-counts. If the device's actual 32-bit UID word is
known, only the approximately 80,000 possible `UID32 XOR SysTick` pads need be
tested—about 53,687 times fewer candidates.

The RTX 4090 measures approximately 290,000 source-faithful first-boot
candidates/second at one address index: about four hours for one full pad pass.
A sanitized snapshot contains 16,324,231,168 uniquely evidenced candidates
across Q=18,20,22,24,26,28,30 at BIP84 external index 0—3.80078125 complete
pad-pass equivalents—with no match among 2,311 targets. Q=24 has a
separate documented 4,194,304-pad evidence gap.

Seven live workers continue those Q=18–30 checkpoints while the 4090 expands
Q=22 to indexes 0–7, then spends remaining budget on Q=32/34. **No
real-victim hit has been recovered as of this writeup.** A no-hit applies only
to the exact target hash, physical history, RTC/settings state, derivation path,
index range and pad interval. `SEARCH_STATUS.md` records every boundary and the
next experiments if the funded run remains empty.

## 7. Reproduce

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

cd proof
python -m unittest -v test_firstboot_reference.py test_bip322.py

cd ../scan && go test ./...

cd ../gpu/cuda
nvcc -std=c++14 -O3 -arch=sm_89 scan.cu -o cscan
./cscan -t ../../targets/all_bc1q.txt -w ../../scan/bip39_english.txt \
  -r 0 -s 0 -F 2 -A 22 -C 1 -i 1 \
  -p 0 -e 4294967296 -b 4194304 -o hit_real_private.json
```

`-F` is the corrected physical-flow mode. Manual `-B/-k/-m/-K/-M` skip
arguments are for fixed-state experiments and are intentionally rejected when
they contradict first-boot mode.

## 8. Safety and victim guidance

1. Upgrade to fixed firmware, generate a completely new seed, verify backup
   and receive address, then migrate funds. Firmware update alone does not fix
   existing affected seed.
2. At least 50 independent private dice rolls or strong unique BIP39
   passphrase materially changes risk; follow Coinkite's current advisory.
3. Never provide seed words to unsolicited recovery services.
4. Preserve addresses, transaction IDs, firmware version, and setup details if
   reporting theft.

Legal scope: public data and self-generated/public demo targets only. No funds
were moved. Drained targets were balance-zero; still-funded wallets must be
notified, never swept.

## References

- Coinkite: *Technical Deep Dive into the Entropy Issue* and Mk3 advisory
- Block Engineering: *Predictable RNG Fallback and 32-Bit Reseed in COLDCARD Firmware*
- 3z/coldcard-mk3-rng-disclosure — binary-verified firmware reconstruction
- DK27ss/ColdCard-38M-PoC — pipeline and split-skip analysis
- COLDCARD firmware tag `2023-06-26T1241-v4.1.9`