#!/usr/bin/env bash
# Watchdog for label app=ccscan: spend cap auto-destroy + hit detection.
# Hard cap €45 (target budget €50, margin for polling lag).
set -u
SSH="ssh -i $HOME/.ssh/id_ed25519 -o IdentitiesOnly=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
CAP_EUR=45
LOG=/tmp/fleet-watch.log
HITDIR=/Users/eminmahrt/Developer/coldcard-mk3-research/recovery/artifacts

notify() { osascript -e "display notification \"$1\" with title \"ccscan fleet\" sound name \"Glass\"" 2>/dev/null || true; }
spend() {
  hcloud server list -l app=ccscan -o json 2>/dev/null | python3 -c "
import json,sys,datetime
try: ss=json.load(sys.stdin)
except Exception: print(0); exit()
now=datetime.datetime.now(datetime.timezone.utc)
t=0.0
for s in ss:
    c=datetime.datetime.fromisoformat(s['created'].replace('Z','+00:00'))
    t+=(now-c).total_seconds()/3600*0.208
print(f'{t:.2f}')"
}
destroy_all() {
  for n in $(hcloud server list -l app=ccscan -o noheader -o columns=name 2>/dev/null); do
    hcloud server delete "$n" >> "$LOG" 2>&1 || true
  done
}

echo "$(date +%FT%T) watchdog start, cap €$CAP_EUR" >> "$LOG"
while true; do
  eur=$(spend)
  # hit check on every box
  for ip in $(hcloud server list -l app=ccscan -o noheader -o columns=ipv4 2>/dev/null); do
    hit=$($SSH root@"$ip" 'cat /root/cc/scan/hit.json 2>/dev/null' 2>/dev/null || true)
    if [ -n "$hit" ]; then
      f="$HITDIR/hit_real_$(date +%Y%m%d_%H%M%S).json"
      printf '%s\n' "$hit" > "$f"
      echo "$(date +%FT%T) *** REAL HIT *** saved $f (box $ip)" >> "$LOG"
      notify "REAL HIT! saved $f"
      destroy_all
      echo "$(date +%FT%T) fleet destroyed after hit" >> "$LOG"
      exit 0
    fi
  done
  over=$(python3 -c "print(1 if float('$eur') >= $CAP_EUR else 0)")
  if [ "$over" = 1 ]; then
    echo "$(date +%FT%T) CAP €$eur >= €$CAP_EUR, destroying fleet" >> "$LOG"
    notify "spend cap €$CAP_EUR reached, fleet destroyed"
    destroy_all
    exit 0
  fi
  echo "$(date +%FT%T) ok spend=€$eur" >> "$LOG"
  sleep 300
done
