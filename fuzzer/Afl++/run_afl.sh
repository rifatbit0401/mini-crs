#!/usr/bin/env bash
set -euo pipefail

# Usage: run_afl.sh path/to/harness.c [output_dir]
# Builds the given harness with afl-clang-fast inside the AFL++ docker image
# and launches afl-fuzz. Requires the AFL++ image tag set by setup_afl_docker.sh.

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 path/to/harness.c [output_dir]" >&2
  exit 1
fi

HARNESS="$1"
OUTDIR="${2:-/workspace/fuzzer/out}"
IMAGE="${AFL_IMAGE:-mini-crs-afl}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="${ROOT}/config.yml"

# Read optional AFL time limit (seconds) from config.yml (key: afl_time_limit)
TIME_LIMIT="$(
ROOT_ENV="${ROOT}" CONFIG_ENV="${CONFIG}" python3 - <<'PY'
import os, re
cfg = os.environ.get("CONFIG_ENV") or os.environ.get("CONFIG_PATH") or "config.yml"
default = "60"
try:
    with open(cfg, "r") as f:
        for line in f:
            m = re.match(r"\s*afl_time_limit\s*:\s*(\d+)", line)
            if m:
                print(m.group(1).strip())
                raise SystemExit
except FileNotFoundError:
    pass
print(default)
PY
)"

# Seeds directory (absolute path)
SEEDS_DIR="$(
ROOT_ENV="${ROOT}" CONFIG_ENV="${CONFIG}" python3 - <<'PY'
import os, re
root = os.environ["ROOT_ENV"]
cfg = os.environ.get("CONFIG_ENV") or os.path.join(root, "config.yml")
default = os.path.join(root, "fuzzer", "user_seeds")
val = default
try:
    with open(cfg, "r") as f:
        for line in f:
            m = re.match(r"\s*seeds_dir\s*:\s*(.+)", line)
            if m:
                raw = m.group(1).strip()
                if os.path.isabs(raw):
                    val = raw
                else:
                    val = os.path.abspath(os.path.join(root, raw))
                break
except FileNotFoundError:
    pass
print(val)
PY
)"
# Container path for seeds (under /workspace if within repo)
SEEDS_CONT="${SEEDS_DIR}"
if [[ "${SEEDS_DIR}" == "${ROOT}"* ]]; then
  SEEDS_CONT="/workspace${SEEDS_DIR#${ROOT}}"
fi

# Resolve harness path relative to repo root
HARNESS_ABS="$(cd "$(dirname "${HARNESS}")" && pwd)/$(basename "${HARNESS}")"
HARNESS_REL="$(python3 -c "import os; root=os.path.abspath('${ROOT}'); path=os.path.abspath('${HARNESS_ABS}'); print(os.path.relpath(path, root))")"
HARNESS_NAME="$(basename "${HARNESS_REL}" .c)"

echo "[afl] Using image: ${IMAGE}"
echo "[afl] Harness: ${HARNESS_REL}"
echo "[afl] Time limit (seconds): ${TIME_LIMIT}"
echo "[afl] Seeds dir: ${SEEDS_DIR}"

docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "${ROOT}:/workspace" \
  -w /workspace/fuzzer \
  "${IMAGE}" \
  bash -lc "set -euo pipefail; \
    mkdir -p build \"${OUTDIR}\" \"${SEEDS_CONT}\"; \
    AFL_SKIP_CPUFREQ=1 afl-clang-fast -I../ossfuzz-target/include ${HARNESS_REL#fuzzer/} -o build/${HARNESS_NAME}; \
    AFL_SKIP_CPUFREQ=1 afl-fuzz -V \"${TIME_LIMIT}\" -i \"${SEEDS_CONT}\" -o \"${OUTDIR}\" -- build/${HARNESS_NAME} @@"
