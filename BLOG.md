# Rebuilding the COLDCARD Mk3 Weak-RNG Key Recovery Pipeline — and Mapping Exactly Where It Breaks

*An independent reproduction of the July 2026 COLDCARD RNG vulnerability, with a
working scanner on four engines, a third-party key recovery proof, and a rigorous
answer to the question everyone is asking: can the stolen funds be recovered by
re-enumerating the seeds?*

**TL;DR**

- We rebuilt the full Mk3 (fw 4.0.1–4.1.9) seed-generation chain — MicroPython's
  Yasmarang fallback ⊕ libngu's whitener — and validated it bit-exact on four
  independent implementations (Python, Go/CPU, Apple Metal, CUDA).
- We recovered the private key for an **independently created** demo address
  published by another researcher (DK27ss), from the address alone, and proved
  control with a BIP322 offline signature. The pipeline works.
- We then ran 14× RTX 4090 through the "obvious" enumeration windows — and hit
  nothing, because the obvious model is wrong. Disassembling the firmware and
  reading MicroPython's `rtc.c` showed why: **the RTC is initialized to
  00:00:00 at first RNG use and counts session uptime**, so `RTC->TR` at seed
  generation is minutes of uptime, not zero.
- Corrected enumeration math says a universal, device-agnostic sweep is
  ~10^15–10^17 candidates — infeasible. The observed mass theft therefore
  implies the attacker has **per-device UID knowledge at scale** (a production/
  distribution data leak), or a composition nobody has published.
- Practical consequence for victims: **recovery by brute force is not possible
  without device-specific priors. Migrate now. Anyone offering "recovery" is
  scamming you.**

---

## 1. The bug in 90 seconds

Three public codebases compose the failure (per Wizardsardine's excellent
writeup): `Coldcard/firmware` (seed flow), `switck/libngu` (crypto lib),
`Coldcard/micropython` (the OS).

```
shared/seed.py:   seed = ngu.hash.sha256s(ngu.random.bytes(32))
libngu random.c:  my_random_bytes():  chip = CHIP_TRNG_32(); chip ^= my_yasmarang()
                  CHIP_TRNG_32() resolves to rng_get() at link time
mpconfigboard.h:  #define MICROPY_HW_ENABLE_RNG (0)   // "We have our own version"
ports/stm32/rng.c: with the flag 0, rng_get() = pyb_rng_yasmarang()  (software)
```

libngu's compile-time safeguard (`#ifndef MICROPY_HW_ENABLE_RNG → #error`)
tested **existence, not value** — the macro exists with value 0, so the guard
passed silently for five years. `rng_get()` became the deterministic Yasmarang
PRNG, seeded once per boot from:

```c
rtc_init_finalise();
pad = *(uint32_t *)MP_HAL_UNIQUE_ID_ADDRESS ^ SysTick->VAL;
n   = RTC->TR;
d   = RTC->SSR;
```

We confirmed this against the shipping binary, not just source. The official
4.1.9 DFU (SHA-256 `f6fb19d9…e640e`, verified against the published hash)
disassembles at `rng_get` (0x0803df94) to:

```
ldr  r2, [r3, #0x18]     ; SysTick->VAL   (0xE000E018)

## 2. Reproducing the chain (and proving it four ways)

The full candidate pipeline, as reconstructed from `vuln_rng.py` (DK27ss) and
`poc_mk3_rng.py` (3z) — which we cross-validated byte-for-byte against each
other:

```
(pad32, rtc_tr, rtc_ssr, skip)
  chip = yasmarang(pad32, rtc_tr, rtc_ssr); advance chip by skip
  mixer = yasmarang(0x0A8CE26F, 69, 233)    # fresh per boot
  raw[8 words]: chip.next() ^ mixer.next()  (reject if chip==last, as on device)
  entropy = SHA256(raw)                     # shared/seed.py
  mnemonic = BIP39(entropy)                 # 24 words
  seed64 = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048)
  m/84'/0'/0'/0/i -> P2WPKH hash160 -> match vs target set
```

Validation results (all in this repo, `artifacts/`):

| # | Proof | Result |
|---|---|---|
| 1 | Planted wallet (random state), recovered from address only — Python | 61 s, exact |
| 2 | Same — Go CPU scanner | 140 s, bit-identical key |
| 3 | Same — Apple M4 Metal GPU | bit-identical |
| 4 | **Third-party artifact**: DK27ss's published demo address `bc1qk92z65wv…lpdj7h` | pad 482111261, skip 2, key recovered from the address alone |
| 5 | BIP322 simple signature on the recovered third-party key | verifies offline |
| 6 | Same planted target — CUDA on RTX 4090 | bit-identical |

Two implementation bugs found along the way are worth documenting, because
both are the kind that silently eat GPU-weeks:

- A RIPEMD-160 final-combine with the five IV constants **rotated by one slot**
  (in a collaborator's GPU kernel) — every hash160 wrong, zero hits forever.
- Our own CUDA host allocated the target buffer with
  `vector<array<uchar,20>>::size()` — element count, not bytes — so the device
  binary-searched 1/20th of a target list. The crypto chain was correct the
  whole time; the match layer was searching garbage. A single-candidate debug
  kernel (print every chain stage for a known state) isolated it in one run.
  Also: an innocent-looking `#pragma unroll 16` on the SHA-512 message-schedule
  ring miscompiled under `-O3` — correct results in one kernel, wrong in
  another. Unrolling never changed semantics in the textbook; in ptxas output
  it did.

## 3. The enumeration model — and where the naive one dies

The fallback state at seed generation is fully described by five values:

```
pad  = UID32 ^ SysTick->VAL     (UID: wafer X/Y coordinates — structured)
n    = RTC->TR                  (time, BCD)
d    = RTC->SSR                 (sub-seconds, 0..255)
skip = RNG draws before seed-gen (boot flow dependent)
mixer_skip = whitener draws (same boot)
```

Our first fleet ran the naive hypothesis — `rtc = 0/0`, `skip ∈ [0,8)` —
across 14× RTX 4090 (~2^35 candidates checked). Zero hits. The disassembly
plus MicroPython's `rtc.c` explain why the window was dead *by construction*:

```c
// ports/stm32/rng.c, first rng_get() of the boot:
rtc_init_finalise();            // -> rtc.c
...
// rtc.c: on first use the RTC is started and then:
RTC_CalendarConfig();           // sets date 2015-01-01, **time 00:00:00**
```

The RTC is zeroed at boot and **counts session uptime**. At seed generation,
`RTC->TR` holds the setup duration (typically minutes, in BCD), and
`RTC->SSR` the sub-second (256 steps/s). Both are unknown per device, and the
second is never zero in practice.

Corrected universal-sweep space, per hypothesis combination:

```
2^32 (pad) × TR_range (~100–1800 s) × SSR (256) × skip_range (flow-dependent)
≈ 10^15 – 10^17
```

Even a perfectly tuned GPU fleet does not touch that. The SSR factor deserves
special note, because it is the one that looks removable: SysTick->VAL and

## 4. So how is the attacker draining thousands of wallets?

Our space analysis collides with the on-chain evidence: 2,321+ addresses
drained in days (coldcard-watch), ~1,082 BTC reconstructed by independent
chain forensics. For that to work, per-device recovery must be *cheap*, and
our math says cheap requires collapsing the pad dimension — i.e., **knowing
the device's UID**.

The UID is a poor secret by design (Wizardsardine): it encodes factory lot
(ASCII), wafer number, and X/Y wafer coordinates — structured, not random.
And the USB serial number exposes 6 of the 12 UID bytes to any host the
device has ever enumerated on (the firmware's own comment calls it "probably
public info"). Per 3z's serial analysis, even a full serial leaves ~5.9×10^8
candidates for the seed word — not enough on its own. A *full* UID, though,
shrinks the per-device space to roughly SysTick (80k) × TR-window × skip:
minutes on a single GPU.

The only consistent reading of a mass sweep: **the attacker possesses exact
UIDs at industrial scale** — factory programming logs (which necessarily read
the UID at flash time), or production/order data from a large distributor.
We found no public evidence of such a breach; we note simply that the math
admits few alternatives. (An alternative worth flagging for completeness:
the attacker may be exploiting a different affected surface entirely — Block
enumerates Key Teleport, Web2FA and others that expose RNG-state oracles.)

## 5. Feasibility ledger (measured)

| Engine | Throughput | Notes |
|---|---|---|
| Python (10-core M4, OpenSSL PBKDF2) | ~9k cand/s | reference |
| Go CPU (cached-pad C PBKDF2) | ~3k cand/s | wall = PBKDF2-SHA512×2048 |
| Apple M4 Metal | ~9k cand/s | after stack-spill fixes |
| RTX 4090 CUDA | ~140k cand/s | 255-reg kernel, 12% occupancy — headroom ~5–10× |
| 14× 4090 fleet | ~1.7M cand/s | ≈ 2^32 pads × 3 skips in ~3 h (~$7) |

Rule of thumb: each full "2^32 × one hypothesis" pass costs single-digit
dollars. The problem was never the price of a pass; it is that the number of
hypotheses (TR × SSR × skip × uid) is the attacker's secret, not compute.

## 6. What victims should actually do

1. **Migrate now**, following Coinkite's advisory: fixed firmware (4.2.0 /
   5.6.0 / 1.5.0Q), generate a *new* seed, move funds. Dice (≥50 rolls) and
   strong passphrases are the only existing-seed mitigations; a weak
   passphrase buys hours at best.
2. **Do not wait for a white-hat recovery.** Without your device's UID
   (plus tight boot-timing knowledge), brute-forcing your seed is
   structurally infeasible — for us and for anyone else on public models.
3. **Ignore every unsolicited "recovery service."** They cannot do it. The
   same math that stops us stops them; your seed words are the only thing
   they are actually after.
4. If you were drained: record txids, addresses, device model, firmware
   version, seed-creation circumstances; Coinkite offers incident summaries
   for police/insurance reports.

## 7. Reproduce everything

```sh
# Go CPU scanner (demo = recover a planted wallet end-to-end)
cd scan && go build -o ccscan . && ./ccscan -mode demo -target <target.json>

# CUDA sweep (validated on RTX 4090)
cd gpu/cuda && nvcc -O3 -arch=sm_89 scan.cu -o cscan
./cscan -t targets.txt -r <rtcTR> -s <rtcSSR> -B <skipBase> -k <skipN> -i <idxMax> -p <padStart> -e <padEnd>

# BIP322 proof tool
python3 proof/bip322.py selftest
python3 proof/bip322.py sign <privkey_hex> <bc1q_address>
python3 proof/bip322.py verify <address> <proof_b64> <message>
```

All artifacts (planted + third-party recoveries, signatures) are in
`artifacts/`; the full experiment history is in `EXPERIMENT_LOG.md`; the
model analysis in `RESEARCH.md`.

## 8. References

- Block Engineering: *Predictable RNG Fallback and 32-Bit Reseed in COLDCARD
  Firmware* (2026-07-30)
- Coinkite advisory (2026-07-30) + emergency firmware 4.2.0/5.6.0/1.5.0Q
- Wizardsardine (Loaec et al.): *Critical Coldcard flaw* (2026-08-01)
- 3z/coldcard-mk3-rng-disclosure — binary-verified Mk3 recon
- DK27ss/ColdCard-38M-PoC — on-device-validated pipeline replica
- coldcard-watch — drained-address tracker (2,321 entries)
- Kelbie/coldcard-rng-postmortem — chain forensics (1,082 BTC, three waves)

*Legal scope: all research on public data and self-generated targets. No funds
were ever moved; drained addresses are balance-zero by definition. If you
recognize a still-funded vulnerable address, notify the owner — never sweep.*

RTC->SSR both derive from the same instant, so in principle they are coupled.
But exploiting the coupling requires separating `pad` back into `UID` and
`SysTick` — which requires knowing the UID. For the device-agnostic attacker
the 256 stands. We checked this carefully; it is not an oversight, it is
structural.

ldr.w r3, [r3, #0x590]   ; UID word       (0x1FFF7590)
eors r3, r2              ; pad = UID ^ SysTick
ldr  r2, [r3]            ; n = RTC->TR    (0x40002800)
ldr  r3, [r3, #0x28]     ; d = RTC->SSR   (0x40002828)
```

followed by the Yasmarang transition — matching the C model bit-for-bit.
