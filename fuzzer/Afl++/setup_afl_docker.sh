#!/usr/bin/env bash
set -euo pipefail

# Pull and tag an AFL++ docker image for running harnesses.
# Override AFL_IMAGE to use a different local tag.

IMAGE="${AFL_IMAGE:-mini-crs-afl}"

echo "[afl] Pulling aflplusplus/aflplusplus..."
docker pull aflplusplus/aflplusplus
echo "[afl] Tagging image as ${IMAGE}"
docker tag aflplusplus/aflplusplus "${IMAGE}"
echo "[afl] Done."
