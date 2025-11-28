#!/usr/bin/env bash
set -euo pipefail

# Run AFL++ for all harnesses listed in fuzzer/harnesses.json (or a provided index).
# Usage: run_afl_all.sh [harness_index_json]

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INDEX="${1:-${ROOT}/fuzzer/harnesses.json}"
IMAGE="${AFL_IMAGE:-mini-crs-afl}"
CONFIG="${ROOT}/config.yml"

if [ ! -f "${INDEX}" ]; then
  echo "[afl] Harness index not found: ${INDEX}" >&2
  exit 1
fi

# Read time limit from config (seconds).
TIME_LIMIT="$(
python3 - <<'PY'
import os, re
cfg = os.path.abspath(os.environ.get("CONFIG_PATH", os.path.join(os.path.dirname(__file__), "..", "..", "config.yml")))
default = "60"
try:
    with open(cfg, "r") as f:
        for line in f:
            m = re.match(r"\s*afl_time_limit\s*:\s*(\d+)", line)
            if m:
                print(m.group(1))
                raise SystemExit
except FileNotFoundError:
    pass
print(default)
PY
)"

echo "[afl] Using image: ${IMAGE}"
echo "[afl] Harness index: ${INDEX}"
echo "[afl] Time limit (seconds): ${TIME_LIMIT}"

# Extract harness list
HARNESS_LIST=($(python3 - <<PY
import json, sys, os
root = os.path.abspath("${ROOT}")
with open("${INDEX}", "r") as f:
    data = json.load(f)
for h in data.get("harnesses", []):
    print(h)
PY
))

for h in "${HARNESS_LIST[@]}"; do
  name="$(basename "${h}" .c)"
  outdir="/workspace/fuzzer/out-${name}-$(date +%s)"
  echo "[afl] Running harness ${h} -> ${outdir}"
  bash "${ROOT}/fuzzer/Afl++/run_afl.sh" "${h}" "${outdir}"
done
