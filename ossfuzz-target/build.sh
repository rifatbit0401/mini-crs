#!/bin/bash
set -euxo pipefail

# OSS-Fuzz build script for the intentionally vulnerable library.
project_dir="$(cd "$(dirname "$0")" && pwd)"

cd "${project_dir}"

"${CC}" ${CFLAGS} -Iinclude -c src/vuln_lib.c -o vuln_lib.o
"${CXX}" ${CXXFLAGS} -std=c++17 -Iinclude \
  fuzz/fuzz_target.cc vuln_lib.o \
  -o "${OUT}/vuln_fuzzer" ${LIB_FUZZING_ENGINE}
