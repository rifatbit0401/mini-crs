#!/usr/bin/env bash
set -euo pipefail

# Run CodeQL against the ossfuzz-target project.
#
# Environment overrides:
#   CODEQL_BIN   - path to codeql CLI (default: codeql)
#   TARGET       - project root to scan (default: ../ossfuzz-target)
#   DB_DIR       - CodeQL database directory (default: code-ql/db)
#   RESULTS      - SARIF output path (default: code-ql/findings.sarif)
#   QUERY_SUITE  - CodeQL suite/queries to run (default: /workspace/code-ql/queries)
#
# Example:
#   bash code-ql/run_codeql.sh
#   CODEQL_BIN=/path/to/codeql DB_DIR=/tmp/db RESULTS=/tmp/out.sarif bash code-ql/run_codeql.sh

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CODEQL_BIN="${CODEQL_BIN:-codeql}"
TARGET="${TARGET:-${ROOT}/ossfuzz-target}"
DB_DIR="${DB_DIR:-${ROOT}/code-ql/db}"
RESULTS="${RESULTS:-${ROOT}/code-ql/findings.sarif}"
# Default to custom queries bundled in this repo; override to run other suites.
QUERY_SUITE="${QUERY_SUITE:-/workspace/code-ql/queries}"
# Include both the CLI bundles and the downloaded packs.
SEARCH_PATH="${SEARCH_PATH:-/opt/codeql:/root/.codeql/packages}"

if ! command -v "${CODEQL_BIN}" >/dev/null 2>&1; then
  echo "[codeql] codeql CLI not found. Install CodeQL and ensure it is on PATH or set CODEQL_BIN." >&2
  exit 1
fi

if [ ! -d "${TARGET}" ]; then
  echo "[codeql] Target directory does not exist: ${TARGET}" >&2
  exit 1
fi

if [ -d "${DB_DIR}" ]; then
  echo "[codeql] Removing existing database at ${DB_DIR}"
  rm -rf "${DB_DIR}"
fi

mkdir -p "${DB_DIR}"
mkdir -p "$(dirname "${RESULTS}")"

# Generate a small build wrapper to avoid quoting issues in --command.
BUILD_WRAPPER="$(mktemp)"
cat > "${BUILD_WRAPPER}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd "${TARGET}"
mkdir -p out
CC=clang CXX=clang++ OUT=out LIB_FUZZING_ENGINE="-fsanitize=fuzzer" CFLAGS=-g CXXFLAGS=-g ./build.sh
EOF
chmod +x "${BUILD_WRAPPER}"

echo "[codeql] Creating database at ${DB_DIR} ..."
"${CODEQL_BIN}" database create "${DB_DIR}" \
  --language=cpp \
  --source-root "${TARGET}" \
  --command "${BUILD_WRAPPER}"

# Ensure query dependencies are installed/resolved before analysis.
"${CODEQL_BIN}" pack install "${QUERY_SUITE}" --search-path "${SEARCH_PATH}"

echo "[codeql] Analyzing with suite ${QUERY_SUITE} ..."
"${CODEQL_BIN}" database analyze "${DB_DIR}" "${QUERY_SUITE}" \
  --search-path "${SEARCH_PATH}" \
  --library-path "${SEARCH_PATH}" \
  --format=sarifv2.1.0 \
  --output "${RESULTS}" \
  --threads=0

echo "[codeql] Analysis complete. SARIF written to ${RESULTS}"
