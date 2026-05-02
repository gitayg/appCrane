#!/usr/bin/env bash
#
# Build appcrane-studio:latest from infra/studio.Dockerfile.
#
# Use case: pre-bake the image on a fresh AppCrane host so the first user
# request doesn't pay the ~2 min cold build. AppCrane will also build it
# automatically on the first plan/contextBuilder/coder job (see
# server/services/appstudio/generator.js ensureStudioImage), but pre-baking
# is friendlier than making a real user wait through it.
#
# Reads the version from server/services/appstudio/generator.js so the label
# stays in lockstep with what AppCrane expects.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE="${ROOT}/infra/studio.Dockerfile"
GENERATOR="${ROOT}/server/services/appstudio/generator.js"

if [[ ! -f "${DOCKERFILE}" ]]; then
  echo "missing ${DOCKERFILE}" >&2
  exit 1
fi

# Source of truth for the version — keep it tied to what ensureStudioImage()
# checks via the appcrane.studio.version label. Falls back to the ARG default
# baked into the Dockerfile if the regex misses.
VERSION="$(grep -oE "STUDIO_IMAGE_VERSION = '[^']+'" "${GENERATOR}" 2>/dev/null | head -1 | sed -E "s/.*'([^']+)'/\\1/")"
if [[ -z "${VERSION:-}" ]]; then
  echo "warn: could not read STUDIO_IMAGE_VERSION from ${GENERATOR}; using Dockerfile default" >&2
fi

TAG="${APPSTUDIO_IMAGE:-appcrane-studio:latest}"
echo "building ${TAG} (version=${VERSION:-dockerfile-default}) from ${DOCKERFILE}"

if [[ -n "${VERSION:-}" ]]; then
  docker build \
    --build-arg "STUDIO_IMAGE_VERSION=${VERSION}" \
    -t "${TAG}" \
    -f "${DOCKERFILE}" \
    "${ROOT}/infra"
else
  docker build -t "${TAG}" -f "${DOCKERFILE}" "${ROOT}/infra"
fi

echo
echo "done. verify:"
echo "  docker images ${TAG%:*}"
docker images "${TAG%:*}"
