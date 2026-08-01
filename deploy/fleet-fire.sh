#!/usr/bin/env bash
# Fire one CPX62 per skip given as args. Usage: fleet-fire.sh 1 2 3 4
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
SSH="ssh -i $HOME/.ssh/id_ed25519 -o IdentitiesOnly=yes"
SCP="scp -i $HOME/.ssh/id_ed25519 -o IdentitiesOnly=yes"
TAR=/tmp/ccscan-src.tar.gz
tar -czf "$TAR" -C "$DIR" scan/main.go scan/pbkdf2.go scan/go.mod scan/go.sum scan/bip39_english.txt targets
for skip in "$@"; do
  hcloud server create --name "ccscan-s$skip" --type cpx62 --image ubuntu-24.04 \
    --location fsn1 --ssh-key ccscan-key --label app=ccscan >/dev/null &
done
wait
for skip in "$@"; do
  (
    name="ccscan-s$skip"
    ip=$(hcloud server ip "$name")
    ssh-keygen -R "$ip" >/dev/null 2>&1 || true
    until $SSH -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 root@"$ip" true 2>/dev/null; do sleep 3; done
    $SCP -q "$TAR" root@"$ip":/root/
    $SSH root@"$ip" 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq golang-go libssl-dev >/dev/null 2>&1; mkdir -p /root/cc; tar xzf /root/ccscan-src.tar.gz -C /root/cc; cd /root/cc/scan && go build -o ccscan .'
    $SSH root@"$ip" "cd /root/cc/scan && nohup timeout 172800 ./ccscan -mode sweep -targets ../targets/all.txt -rtc-tr 0 -rtc-ssr 0 -skip-lo $skip -skip-hi $((skip+1)) -mixer-skip 0 -nidx 16 -workers 16 -checkpoint /root/ckpt.json > /root/sweep.log 2>&1 &"
    echo "box $name ($ip): skip $skip running"
  ) &
done
wait
echo FLEET_UP
