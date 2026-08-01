# Research log — enumeration model (2026-08-01)

## Confirmed model (source + disassembly + 3 engines cross-validated)

- `shared/seed.py: seed = ngu.hash.sha256s(ngu.random.bytes(32))`
- libngu `my_random_bytes`: `chip = rng_get(); chip ^= my_yasmarang()` per 4 bytes
- Mk3 v4 `rng_get()` = MicroPython Yasmarang fallback (`MICROPY_HW_ENABLE_RNG=0`):
  `pad = UID32 ^ SysTick->VAL; n = RTC->TR; d = RTC->SSR` (first call per boot)
- libngu whitener: compiled constants `{0x0A8CE26F, 69, 233, 0}` per boot + call history
- Tool recovered planted keys + DK27ss's third-party demo address on 4 engines.

## The RTC discovery (rtc.c, v4-master)

- First `rng_get()` calls `rtc_init_finalise()` → if RTC not running, it is
  started and `RTC_CalendarConfig()` sets **2015-01-01 00:00:00**.
- Therefore `n = RTC->TR` at seed generation = **session uptime in BCD**
  (typically minutes), NOT a frozen constant. `d = RTC->SSR` = 0..255.
- Our initial rtc 0/0 sweeps (skip 0–8, 14× RTX 4090, ~2^35 candidates) were
  structurally dead. Stopped, ~$17 saved.

## Feasibility estimates (ours)

Blind universal enumeration per (TR, SSR, skip) hypothesis:
`2^32 pads × TR_range(~100–1800) × SSR(256) × skip(~5)` ≈ 1e15–1e17 → infeasible.

Coinkite states "≈40 bits" for Mk3 (preliminary, composition unpublished),
LLFOURN cost model referenced but not publicly reachable. The thefts prove a
working enumeration exists; plausible compositions that reach ~2^40:

1. UID structure: uid word 0 = wafer X/Y coordinates (structured, not random).
   If ~2^16–2^20 realistic values across shipped devices × SysTick (2^16.3)
   ≈ 2^32–2^36 pads; × constrained (TR, SSR, skip) ≈ 2^40.
2. SysTick↔RTC coupling: SSR and SysTick both derive from the same instant —
   may collapse the SSR dimension (256) if modeled exactly.
3. Deterministic first-boot wizard call history → skip becomes exact.

## Open research items (free)

- Exact RNG draw count before seed-gen in the first-boot flow (skip; nvstore
  v4.1.9 shows no RNG use at lines 205–215 — DK27ss's "3103" is unverified).
- Wizard timing distribution → realistic TR window.
- STM32L4 UID layout (RM0351): coords vs lot/wafer entropy of word 0.

## Bottom line

Tool: validated and publishable. Real-victim recovery at scale needs the
attacker's exact composition (uid priors and/or coupling) — a blind sweep is
a lottery, not a plan. Next spend only after the composition is nailed down.
