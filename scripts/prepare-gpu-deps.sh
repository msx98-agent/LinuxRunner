#!/bin/bash
set -euo pipefail
printf 'prepare-gpu-deps.sh:start: preparing pinned Metal dependencies\n'
trap 'printf "prepare-gpu-deps.sh:exit: status=%s\n" "$?"' EXIT
: "${GPU_DEPS:?Set GPU_DEPS to an absolute dependency directory}"
mkdir -p "$GPU_DEPS"

checkout_dependency() {
    printf 'prepare-gpu-deps.sh:checkout_dependency: entering %s at %s\n' "$1" "$3"
    local dependency_name=$1 dependency_url=$2 dependency_revision=$3
    git init "$GPU_DEPS/$dependency_name"
    git -C "$GPU_DEPS/$dependency_name" fetch --depth 1 "$dependency_url" "$dependency_revision"
    git -C "$GPU_DEPS/$dependency_name" checkout --detach FETCH_HEAD
    printf 'prepare-gpu-deps.sh:checkout_dependency:end: prepared %s at %s\n' "$dependency_name" "$dependency_revision"
}

checkout_dependency virglrenderer https://gitlab.freedesktop.org/virgl/virglrenderer.git e0a1caf3b147bb26dfe524dbb85ded1177e7e49e
checkout_dependency libepoxy https://github.com/anholt/libepoxy.git d1f952c4565c389d82fd1657153e84e050f35b27
checkout_dependency angle https://chromium.googlesource.com/angle/angle feebf60fe088ccec3a26a7419d6ac68edf542c7a
checkout_dependency depot_tools https://chromium.googlesource.com/chromium/tools/depot_tools.git a20039648c0de69d8156906b18052bd47e9bf230
export PATH="$GPU_DEPS/depot_tools:$PATH"
export DEPOT_TOOLS_UPDATE=0
cd "$GPU_DEPS/angle"
python3 scripts/bootstrap.py
gclient sync --no-history --shallow
printf 'prepare-gpu-deps.sh:complete: source checkouts and ANGLE toolchain ready\n'
