# Changelog

Newest first. Every bullet names the commit that caused it.

## 2026-10-14 — [RELEASE] v0.1.0 — hermes-agent for emino

- State at `master` HEAD `f30e679c`: frozen negative result, no corpus hit, strict ledger of 35,597,058,048 unique derivations.
- Final run queue of 1,153 non-duplicating jobs (1,510,591,168,512 derivations) is committed and reproducible.
- Docs only in this release: README gains Logs, Status, Architecture, User flow, Components, CLI and Run sections. CHANGELOG.md and PROMPTLOG.md added. No code changed.

## 2026-08-03

- `f30e679c` Publish strict final coverage ledger, deterministic final run queue, CUDA `-P` disjoint path ranges with validation gate, BIP84 path tests and evidence validator. Removes superseded RESEARCH.md, RESULTS.md, SEARCH_STATUS.md.

## 2026-08-02

- `d5bb0005` Source-faithful Mk3 first-boot model: corrected CUDA flow, two independent CPU references, first-boot tests, sanitized per-history audit logs.
- `e0c58a09` README status corrected: fleet stopped, RTC 0/0 assumption disproven, pointer to corrected analysis.
- `1ef85108` BLOG.md technical writeup added and linked from README.

## 2026-08-01

- `83eadf0a` RESEARCH.md: RTC reset-at-boot finding, why blind sweeps are dead, feasibility estimates.
- `928aa6c1` README status covers full arc; OPS.md marked historical with final cost.
- `bad53c8a` CPU phase ended: fleet shut down, final coverage checkpoints recorded, all empty.
- `29dbd049` CUDA: lockstep mixer-skip mode (`-M`).
- `c3af9824` Targets: 16 Mk4 duress-wallet addresses plus reseed analysis.
- `b5ff225c` README links OPS.md and EXPERIMENT_LOG.md.
- `d578abec` OPS.md fleet runbook, watchdog and cost tracking; experiment log update.
- `5c721c1a` CUDA: pad end parameter (`-e`) to split pad space across GPUs.
- `0eb79c3e` CUDA: skip base parameter (`-B`) for skip-range probes.
- `d10f0ce5` RESULTS.md proof table and costs; fresh 2,311-address `bc1q` target list.
- `45d9ee26` CUDA: removed miscompiling unroll pragma; CUDA port validated on RTX 4090 with a planted hit.
- `d4b4fa3d` CUDA: fixed target buffer size so the scan kernel can match; debug kernel added.
- `7c48d93a` CUDA port of the validated chain (RNG, SHA-256/512, PBKDF2, BIP32, secp256k1, hash160 match).
- `7d401481` Third-party recovery proof for the public DK27ss demo address plus BIP322 signature.
- `0be37530` Working Metal sweep; planted hit verified bit-exact; merged 2,311-target list.
- `7ea388e3` Metal host runner (`mscan`); fixed RIPEMD-160 IV bug; binaries ignored.
- `63438000` Initial commit: Go scanner (demo and sweep), BIP322 proof tool, 13 targets, planted-demo artifacts, README.

Earlier history: none. First commit is `63438000` on 2026-08-01.
