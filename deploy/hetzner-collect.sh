#!/usr/bin/env bash
# Poll all ccscan boxes: show hits (if any) + last progress line.
set -uo pipefail
mkdir -p hits
for s in $(hcloud server list --selector app=ccscan -o noheader -o columns=name); do
  ip=$(hcloud server ip "$s")
  echo "== $s ($ip)"
  ssh -o ConnectTimeout=5 root@"$ip" 'grep -A12 HIT /root/sweep.log 2>/dev/null; tail -1 /root/sweep.log' 2>/dev/null \
    && ssh -o ConnectTimeout=5 root@"$ip" 'grep -A12 HIT /root/sweep.log' 2>/dev/null \
    | tee "hits/$s.hit" >/dev/null || echo "  (unreachable)"
done
ls hits/ 2>/dev/null | while read -r f; do
  [ -s "hits/$f" ] && echo "*** HIT FILE: hits/$f"
done