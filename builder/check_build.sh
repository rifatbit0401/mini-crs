#!/usr/bin/env bash
set -euo pipefail

# Simple build check: tries to build the Dockerized ossfuzz-target image.
# Optional: set IMAGE_TAG to change the output tag.

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required but not found in PATH" >&2
  exit 1
fi

project_dir="$(cd "$(dirname "$0")/../ossfuzz-target" && pwd)"
image_tag="${IMAGE_TAG:-mini-crs-fuzz-check}"

echo "Building ossfuzz-target image as '${image_tag}'..."
docker build -t "${image_tag}" "${project_dir}"
echo "Build succeeded; image tagged as '${image_tag}'."
