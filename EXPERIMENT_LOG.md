# Coldcard Mk3 Recovery — Experiment Log

**STATUS 2026-08-01 19:40 CEST: CPU-Phase beendet.** Hetzner-Flotte (skip 3,4,6,7)
und Mac-Worker (skip 5) abgeschaltet — CUDA (RTX 4090, anderer Dev) ist der
schnellere Weg und läuft auf seiner Seite weiter. Finale Coverage-Checkpoints
(was getestet wurde, leer befunden): `artifacts/coverage/ckpt_skip{3,4,5,6,7}.json`
(skip 3: 374,6M / 8,7% · skip 4: 302,6M / 7,0% · skip 5: 271,3M / 6,3% ·
skip 6: 232,2M / 5,4% · skip 7: 174,2M / 4,1%). Spend gestoppt.

Live log of what has been tried, what's running, what's excluded.
Ops runbook: `OPS.md`. Proofs: `RESULTS.md`.

## Current hypothesis (ACTIVE)

| parameter | value | rationale |
|---|---|---|
| rtc_tr | 0 | Mk3 has no RTC battery → clock resets to 0 on boot |
| rtc_ssr | 0 | same |
| chip_skip | 0–7 (ALL 8) | RNG call history before seed gen; 0 = factory-fresh |
| mixer_skip | 0 | RNG mixer state |
| nidx | 8 | address indices 0–7 derived per candidate (first receive addresses) |
| passphrase | "" (none) | standard BIP39; majority case |

## Targets

| set | count | file |
|---|---|---|
| victims (drained) + Fowler | 2,311 | targets/all_bc1q.txt (CUDA) |
| above + 5 site-notables | 2,316 | targets/all_bech32.txt (Hetzner + Mac) |

All targets are P2WPKH (20-byte bech32) = single-sig. No multisig, no P2SH.
23 legacy non-segwit addresses excluded (need BIP44/49).

## Workers running NOW (skip map, no duplication)

| worker | platform | skip | rate | cost |
|---|---|---|---|---|
| vast.ai | RTX 4090 CUDA | 0–2 | ~130–140k/s | ~$0.26/h (his) |
| ccscan-s3 | Hetzner CPX62 | 3 | ~13k/s | €0.208/h |
| ccscan-s4 | Hetzner CPX62 | 4 | ~11k/s | €0.208/h |
| Mac M4 | local | 5 | ~9.9k/s | €0 |
| ccscan-s6 | Hetzner CPX62 | 6 | ~11k/s | €0.208/h |
| ccscan-s7 | Hetzner CPX62 | 7 | ~11k/s | €0.208/h |

## Coverage

- Pads scanned (fleet+Mac): ~540M (as of ~14:00) + CUDA fresh on skip 0–2
- Full window (2^32 × 8): 34.36B → fleet+Mac ~1.6%; CUDA now dominates rate
- Cost: ≈ €3.3 real to date (see OPS.md cost table), €0.83/h running rate

## What is NOT tried (gaps)

| gap | who covers | status |
|---|---|---|
| idx 8–15 | nobody | deferred (nidx cut 16→8); CUDA full pass can restore |
| rtc_tr ≠ 0 / rtc_ssr ≠ 0 | nobody | correlated risk: if rtc 0/0 wrong, all miss |
| mixer_skip ≠ 0 | nobody | low priority |
| legacy P2PKH/P2SH (23 addrs) | nobody | needs BIP44/49 in-kernel |
| multisig (P2WSH) | nobody | not in target set |

## Validations (tool proven correct)

See RESULTS.md — 6 proofs across Python/Go/Metal/CUDA engines, bit-exact,
incl. third-party DK27ss artifact + BIP322 signature. CUDA validated on
RTX 4090 (planted hit exact) after 2 bug fixes (buffer size, pragma unroll).

## Kill criteria

- Hit → watchdog destroys fleet, saves hit.json, notifies (see OPS.md)
- €45 spend (running fleet) → watchdog destroys fleet
- CUDA validated & extended → delete redundant CPU boxes
- 48h box self-timeout (timeout 172800) as backstop

## Open questions for the other dev

1. 5 site-notables (incl. ~562 BTC whale) — in fleet's all_bech32.txt but
   not in his all_bc1q.txt. Victim or attacker/destination addresses?
2. Legacy 23 → BIP44/49 support planned?
3. CUDA skip plan after 0–2: extend to 3–8, or split pads across GPUs?

