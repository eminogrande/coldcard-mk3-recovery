#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN=${1:-"$ROOT/gpu/cuda/cscan"}
WORDS="$ROOT/scan/bip39_english.txt"
TARGETS="$ROOT/proof/cuda_path_range_targets.txt"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [[ ! -x "$BIN" ]]; then
  printf 'missing executable CUDA scanner: %s\n' "$BIN" >&2
  exit 2
fi

DEBUG=$(
  "$BIN" -t "$TARGETS" -w "$WORDS" \
    -r 0 -s 0 -F 2 -A 22 -C 1 -i 1 \
    -D 3547157718 2>&1
)
for expected in \
  'flow=firstboot preTerms=2 postTerms=22 chipSkip=3206 mixerSkip=3514' \
  'rawB=8e1d0981' \
  'ent=da85ce09' \
  'chain=0 index=0' \
  'h160=74f34da837a78231dd3bd6ccc983638570454cdb'; do
  grep -Fq "$expected" <<<"$DEBUG" || {
    printf 'debug vector mismatch: missing %s\n' "$expected" >&2
    exit 1
  }
done

OUT="$TMP/path_hits.json"
"$BIN" -t "$TARGETS" -w "$WORDS" \
  -r 0 -s 0 -F 2 -A 17 -C 1 \
  -P 0:8:12 -P 1:0:20 \
  -p 3547144342 -e 3547144343 -b 1 -o "$OUT"

python3 - "$OUT" <<'PY'
import json, os, stat, sys
path = sys.argv[1]
hits = json.load(open(path, encoding='utf-8'))
actual = {(item['chain'], item['idx']) for item in hits}
expected = {(0, 8), (0, 19), (1, 0), (1, 19)}
if actual != expected or len(hits) != 4:
    raise SystemExit(f'path control mismatch: expected {sorted(expected)}, got {sorted(actual)}')
mode = stat.S_IMODE(os.stat(path).st_mode)
if mode != 0o600:
    raise SystemExit(f'private output mode is {mode:o}, expected 600')
print('CUDA_PATH_RANGE_CONTROL_OK hits=4 mode=600')
PY
