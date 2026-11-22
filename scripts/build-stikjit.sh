#!/bin/bash
set -euo pipefail
printf 'build-stikjit.sh:start: building pinned StikJIT from source\n'
trap 'printf "build-stikjit.sh:exit: status=%s\n" "$?"' EXIT
cd "$(dirname "$0")/.."
git submodule update --init --checkout -- deps/StikJIT
(cd deps/StikJIT && xcodegen generate)
xcodebuild -project deps/StikJIT/StikJIT.xcodeproj -scheme StikJIT -configuration Release -destination 'generic/platform=iOS' -archivePath "$PWD/build/StikJIT.xcarchive" CODE_SIGNING_ALLOWED=NO SKIP_INSTALL=NO archive
rm -rf build/StikJIT.framework
ditto build/StikJIT.xcarchive/Products/Library/Frameworks/StikJIT.framework build/StikJIT.framework
printf 'build-stikjit.sh:complete: framework ready\n'
