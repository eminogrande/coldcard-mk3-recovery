# Coldcard Mk3 Recovery — Experiment Log

Live log of what has been tried, what's running, what's excluded.
Updated: 2026-08-01 12:45 UTC

## Current hypothesis (ACTIVE)

| parameter | value | rationale |
|---|---|---|
| rtc_tr | 0 | Mk3 has no RTC battery → clock resets to 0 on boot |
| rtc_ssr | 0 | same |
| chip_skip | 0–5 (6 of 8) | RNG call history before seed gen; 0 = factory-fresh |
| mixer_skip | 0 | RNG mixer state |
| nidx | 8 | address indices 0–7 derived per candidate (first receive addresses) |
| passphrase | "" (none) | standard BIP39; majority case |

## Targets

| set | count | source |
|---|---|---|
| victims (drained Mk3 wallets) | 2,298 | coldcard-watch.vercel.app / drains.js |
| Fowler (published case) | 13 | targets/billfowler.txt |
| site-notables (whale etc.) | 5 | coldcard-watch.vercel.app inline |
| **total (P2WPKH single-sig)** | **2,316** | targets/all_bech32.txt |

All targets are P2WPKH (20-byte bech32) = single-sig. No multisig, no P2SH.

## Workers running NOW

| worker | platform | skip | rate | checkpoint (pads) |
|---|---|---|---|---|
| ccscan-bench | Hetzner CPX62 (16 vCPU) | 0 | ~9k/s | 38,797,312 |
| ccscan-s1 | Hetzner CPX62 | 1 | ~10k/s | 40,894,464 |
| ccscan-s2 | Hetzner CPX62 | 2 | ~12k/s | 44,040,192 |
| ccscan-s3 | Hetzner CPX62 | 3 | ~12k/s | 46,923,776 |
| ccscan-s4 | Hetzner CPX62 | 4 | ~10k/s | 37,748,736 |
| Mac M4 | local (10 cores) | 5 | ~5k/s | 5,898,240 |
| **aggregate** | | | **~58k/s** | **214,302,720 total** |

## Coverage

- Pads scanned: 214,302,720
- Full window (2^32 × 8 skips): 34,359,738,368 → **0.62% covered**
- Searched subspace (2^32 × 6 skips 0–5): 25,769,803,776 → **0.83% covered**
- Cost: €1.34 / €45 cap (Hetzner only; Mac free)

## What is NOT tried (gaps)

| gap | who covers | status |
|---|---|---|
| skip 6–7 | nobody | uncovered |
| idx 8–15 | nobody (deferred from nidx cut) | CUDA full pass will cover |
| rtc_tr ≠ 0 / rtc_ssr ≠ 0 | nobody | correlated risk: if rtc 0/0 wrong, all miss |
| mixer_skip ≠ 0 | nobody | low priority |
| legacy P2PKH/P2SH (23 addrs) | nobody | needs BIP44 derivation path |
| multisig (P2WSH) | nobody | not in target set; different script type |

## Validations (tool proven correct)

1. Planted demo wallet → mnemonic → key → address (bit-exact, on Mac + Hetzner)
2. DK27ss third-party PoC → key match (GPU dk_scan.log)
3. BIP322 sign→verify roundtrip (proof/bip322.py selftest passes)
4. Cross-platform: ccscan produces identical hit.json on macOS and Ubuntu

## Kill criteria

- Hit → watchdog destroys fleet, saves hit.json, notifies
- €45 spend → watchdog destroys fleet
- CUDA validated ≥500k/s → destroy CPU fleet, migrate
- 48h box self-timeout (timeout 172800 on ccscan) as backstop

## Open questions for the other dev

1. 5 site-notables (incl. 562 BTC whale) — excluded from his all.txt. Attacker/destination addresses? Or oversight?
2. Legacy 23 addresses → BIP44 support planned?
3. CUDA port (gpu/cuda/scan.cu, 1008 lines) — ETA to validation?
