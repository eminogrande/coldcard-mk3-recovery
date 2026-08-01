#!/usr/bin/env bash
# Tear down ALL ccscan boxes + ssh key. Stops all billing.
set -uo pipefail
hcloud server list --selector app=ccscan -o noheader -o columns=name \
  | xargs -r -n1 -P8 hcloud server delete
hcloud ssh-key delete ccscan-key 2>/dev/null || true
echo "all ccscan servers deleted"