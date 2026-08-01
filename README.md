# Coldcard Mk3 weak-RNG key recovery

Private research repo for the July 2026 COLDCARD Mk3 RNG vulnerability
(fw 4.0.1–4.1.9): `rng_get()` links to MicroPython's Yasmarang software
fallback instead of the hardware TRNG. Seed = deterministic function of
`pad = uid32 ^ SysTick`, `RTC_TR`, `RTC_SSR`, and the RNG call history
("skip"). An address alone is a validation oracle for offline key recovery.

## Status

| Milestone | State |
|---|---|
| RNG model cross-validated (3z ≡ DK27ss, byte-identical) | done |
| Planted-wallet recovery, address-only → mnemonic → key | done, bit-exact |
| BIP322 offline proof of key control (sign + verify tool) | done, self-tested |
| Real-victim target set (13 addresses, public chain data) | done |
| CPU sweep vs real targets (rtc 0/0, skip 0–8) | running, no hit yet |
| Metal GPU sweep | in progress (option A) |

**No real victim key has been recovered.** The only recovered key is the
synthetic planted demo wallet (`artifacts/hit_planted_demo.json`).

## Layout

- `scan/` — Go scanner: bit-exact RNG port + BIP39/PBKDF2(OpenSSL C)/
  BIP32-BIP84 + hash160 matching. Modes: `demo` (recover planted target),
  `sweep` (2^32 pad scan × rtc/skip hypotheses vs target list, checkpoints)
- `proof/bip322.py` — BIP322 simple signatures for P2WPKH: sign/verify/selftest
- `targets/billfowler.txt` — 13 victim wallet addresses, extracted from the
  inputs of the 13 drain transactions the victim published (public chain data)
- `artifacts/` — planted-demo recovery + signature artifacts
- `ext/` — third-party references (not vendored): DK27ss/ColdCard-38M-PoC,
  3z/coldcard-mk3-rng-disclosure

## Run it

```sh
cd scan && go build -o ccscan .
./ccscan -mode demo -target <target.json>                 # planted recovery
./ccscan -mode sweep -targets <addrs.txt> -rtc-tr 0 -rtc-ssr 0 \
  -skip-lo 0 -skip-hi 8 -nidx 16 -checkpoint ckpt.json    # real sweep
../recovery/.venv/bin/python ../proof/bip322.py selftest  # signature tool
```

Measured on M4: ~3.5k candidates/s (nidx=16, 10 cores) → 2^32 ≈ 14 days
per hypothesis on CPU. GPU target: 2^32 in minutes–hours.

## Legal scope

Drained addresses (balance 0) only; research on public data. Never
broadcast transactions from derived keys. Still-funded vulnerable wallets:
notify owner only, never sweep.

## References

- Block: "Predictable RNG Fallback and 32-Bit Reseed in COLDCARD Firmware" (2026-07-30)
- DK27ss/ColdCard-38M-PoC — on-device-validated pipeline replica
- 3z/coldcard-mk3-rng-disclosure — binary-verified firmware recon
- Coinkite advisory: blog.coinkite.com/coldcard-mk3-seed-generation-warning/
