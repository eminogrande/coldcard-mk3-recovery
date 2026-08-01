# Ops — sweep infrastructure & runbook

> **STATUS 2026-08-01 19:40 CEST: CPU fleet phase ENDED.** All Hetzner boxes
> (s3,s4,s6,s7) and the M4 worker were shut down — CUDA (RTX 4090, other
> contributor) is the faster path and continues on his side. Billing stopped;
> final coverage checkpoints saved to `artifacts/coverage/`. Watchdog launchd
> job unloaded. This file is now the **historical runbook** — how the fleet
> was run and how to re-fire it if the hypothesis changes.

Operations side of the recovery sweep: who scans what, how the fleet is
run, how spend is capped, how hits are caught. For proofs/targets/cost-per-
engine see `RESULTS.md`. This file is the no-nonsense ops log.

## Sweep map (at shutdown, no duplication)

Every chip-skip was assigned to exactly one worker. No two workers scanned
the same (skip, pad) space.

| chip-skip | worker | engine | rate | cost |
|---|---|---|---|---|
| 0–2 | RTX 4090 (vast.ai) | CUDA `gpu/cuda/scan.cu` | ~130–140k cand/s | ~$0.26/h (his budget) |
| 3 | Hetzner `ccscan-s3` (CPX62) | Go `scan/ccscan` | ~13k cand/s | €0.208/h |
| 4 | Hetzner `ccscan-s4` (CPX62) | Go `scan/ccscan` | ~11k cand/s | €0.208/h |
| 5 | Apple M4 (local) | Go `scan/ccscan` | ~9.9k cand/s | €0 |
| 6 | Hetzner `ccscan-s6` (CPX62) | Go `scan/ccscan` | ~11k cand/s | €0.208/h |
| 7 | Hetzner `ccscan-s7` (CPX62) | Go `scan/ccscan` | ~11k cand/s | €0.208/h |

Hypothesis everywhere: `rtc_tr=0 rtc_ssr=0 mixer_skip=0`, idx 0–7 (nidx 8),
targets = P2WPKH single-sig only.

### Targets files (differ intentionally)

- `targets/all_bc1q.txt` — 2,311 addresses (2,298 coldcard-watch + 13 Fowler). Used by CUDA.
- `targets/all_bech32.txt` — 2,316 = above **+ 5 coldcard-watch "notable" addresses** (incl. the ~562 BTC whale). Used by Hetzner fleet + Mac. Superset, open question whether the 5 are victim or attacker/destination addresses.

Do NOT feed `targets/all.txt` to the scanner — it contains 23 legacy
P2PKH/P2SH addresses that crash the bech32-only loader (`panic: bad target
address`). Those 23 need BIP44/49 derivation (not implemented yet).

## Hetzner fleet

Cloud servers, hourly billing, **no monthly contract** (Hetzner Cloud;
€0.2083/h per CPX62, €129.99/mo is only a ceiling). Delete server = billing
stops same minute.

Scripts in `deploy/`:

| script | purpose |
|---|---|
| `hetzner-fire.sh [N]` | original sharded fleet launcher (CCX default) |
| `fleet-fire.sh <skips...>` | one CPX62 per skip arg, builds + launches sweep |
| `fleet-watch.sh` | watchdog: spend cap + hit detection (see below) |
| `hetzner-collect.sh` | pull checkpoints/hits from boxes |
| `hetzner-destroy.sh` | delete fleet, stop billing |

SSH note: boxes reject auth if the local agent floods keys — all scripts use
`ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes`. The Hetzner-side key is
`ccscan-key` (fingerprint matches local `~/.ssh/id_ed25519.pub`).

Per-box command (what runs on each):

```
./ccscan -mode sweep -targets ../ttargets/all_bech32.txt -rtc-tr 0 -rtc-ssr 0 \
  -skip-lo S -skip-hi S+1 -mixer-skip 0 -nidx 8 -workers 16 \
  -pad-start <checkpoint> -checkpoint /root/ckpt.json
```

`timeout 172800` (48h) wraps the process as a backstop; checkpoints every
60s allow resume without losing progress.

## Watchdog (`deploy/fleet-watch.sh`)

Runs under **launchd** (`~/Library/LaunchAgents/com.nuri.ccscan-watch.plist`,
`KeepAlive=true`, wrapped in `caffeinate -dims` so the Mac never sleeps while
the fleet is billed). Every 5 min:

1. Computes spend of running `app=ccscan` servers × €0.208/h.
2. **Hit check**: pulls `/root/cc/scan/hit.json` from every box → on hit,
   saves to `recovery/artifacts/hit_real_<ts>.json`, destroys the fleet,
   macOS notification, exits.
3. **Cap**: spend ≥ €45 → destroys fleet, notification, exits.

Log: `/tmp/fleet-watch.log` (5-min entries). Hit line: `*** REAL HIT ***`.

### Watchdog bugs found & fixed (important)

- **PATH bug (critical):** launchd runs with `PATH=/usr/bin:/bin` — `hcloud`
  (at `/opt/homebrew/bin/hcloud`) was not found → spend calc returned 0 →
  **€45 cap was silently dead.** Fixed: script now exports
  `PATH=/opt/homebrew/bin:...` at the top. Verify with `tail /tmp/fleet-watch.log`
  — spend must be a real number, not €0.
- **Spend undercount:** the cap only sees *currently running* servers.
  Deleted servers' hours drop out of the calc. Real cumulative spend =
  watchdog value + deleted boxes (≈ €2.0 so far). Acceptable for a €50 budget
  but do not treat the watchdog number as the invoice total.
- `pkill -f 'ccscan -mode'` on a box **kills the invoking SSH shell itself**
  (its argv contains the pattern) → use `pkill -x ccscan`.

## Cost tracking (real, CEST)

| item | spend |
|---|---|
| Positive-control test box (CPX62, planted hit) | ≈ €0.21 |
| Fleet skips 0–2 (3 boxes, ~2.6h, deleted — redundant with CUDA) | ≈ €1.62 |
| Fleet skips 3,4,6,7 (4 boxes until shutdown) | ≈ €1.66 |
| **Final total (CPU phase, ended 19:40)** | **≈ €3.5** |

Budget: €50 total. Cap logic guards the running fleet; CUDA side is the
other dev's separate vast.ai budget (~$0.26/h).

## Reproduce a fleet box

```
hcloud server create --name ccscan-sX --type cpx62 --image ubuntu-24.04 \
  --location fsn1 --ssh-key ccscan-key --label app=ccscan
scp -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes /tmp/ccscan-src2.tar.gz root@IP:/root/
ssh ... 'apt install golang-go libssl-dev; tar xzf ...; go build'
ssh ... 'nohup timeout 172800 ./ccscan -mode sweep ... -skip-lo S -skip-hi S+1 ... &'
```

## Security

- The Hetzner API token was pasted into a chat during setup — **rotate it**
  (Cloud Console → Security → API Tokens → delete + regenerate). It lives in
  `~/.config/hcloud/cli.toml` (chmod 600, not committed).
- Never commit `cli.toml`, `hit.json` with funded keys, or any private key.
- Drained-address (balance 0) targets only; never broadcast from derived keys.

## Open ops items

1. skip 0–2 overlap window: CUDA started at pad 0 while Hetzner 0–2 boxes
   already had ~2% — accepted, CUDA is 10× faster and catches up in minutes.
2. skip 0–2 done by CUDA → reassign or delete Hetzner 3,4 as CUDA extends.
3. idx 8–15 + BIP44/49 legacy addresses: not covered anywhere yet.
4. If €45 cap reached with no hit → stop, do not blind re-fire; reassess
   hypothesis (rtc≠0 windows, skip order, idx range).
