#!/usr/bin/env bash
# Fire ccscan sweep sharded by chip-skip across N Hetzner dedicated-vCPU boxes.
# Usage: ./hetzner-fire.sh [N_SERVERS]   N in 1,2,4,8 (default 8 = one per skip)
# Prereq: hcloud context create (API token), ~/.ssh/id_ed25519.pub exists
set -euo pipefail
N="${1:-8}"
TYPE="${CCX_TYPE:-ccx63}"
LOCATION="${LOC:-fsn1}"
IMAGE=ubuntu-24.04
LABEL=app=ccscan
DIR="$(cd "$(dirname "$0")/.." && pwd)"
SSH_KEY_NAME=ccscan-key

if [[ ! -f ~/.ssh/id_ed25519.pub ]]; then
  ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519
fi
if ! hcloud ssh-key describe "$SSH_KEY_NAME" >/dev/null 2>&1; then
  hcloud ssh-key create --name "$SSH_KEY_NAME" --public-key-from-file ~/.ssh/id_ed25519.pub >/dev/null
fi

SKIPS_PER_BOX=$(( 8 / N ))
TAR=/tmp/ccscan-src.tar.gz
tar -czf "$TAR" -C "$DIR" scan/main.go scan/pbkdf2.go scan/go.mod scan/go.sum scan/bip39_english.txt targets

for i in $(seq 0 $((N-1))); do
  hcloud server create --name "ccscan-$i" --type "$TYPE" --image "$IMAGE" \
    --location "$LOCATION" --ssh-key "$SSH_KEY_NAME" --label "$LABEL" >/dev/null &
done
wait

for i in $(seq 0 $((N-1))); do
  ip=$(hcloud server ip "ccscan-$i")
  lo=$(( i * SKIPS_PER_BOX )); hi=$(( lo + SKIPS_PER_BOX ))
  (
    ssh-keygen -R "$ip" >/dev/null 2>&1 || true
    until ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 root@"$ip" true 2>/dev/null; do sleep 3; done
    ssh root@"$ip" 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq golang-go libssl-dev >/dev/null 2>&1'
    scp -q "$TAR" root@"$ip":/root/
    ssh root@"$ip" 'mkdir -p /root/cc && tar -xzf /root/ccscan-src.tar.gz -C /root/cc && cd /root/cc/scan && go build -o ccscan .'
    ssh root@"$ip" "cd /root/cc/scan && nohup ./ccscan -mode sweep -targets ../targets/billfowler.txt -rtc-tr 0 -rtc-ssr 0 -skip-lo $lo -skip-hi $hi -mixer-skip 0 -nidx 16 -checkpoint /root/ckpt.json > /root/sweep.log 2>&1 &"
    echo "box ccscan-$i ($ip): skips [$lo,$hi) running"
  ) &
done
wait
echo "FIRED $N x $TYPE. collect: $0-dir/hetzner-collect.sh  destroy: hetzner-destroy.sh"