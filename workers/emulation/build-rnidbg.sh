#!/usr/bin/env bash
# Provision only in an isolated worker build environment; no target inputs here.
set -euo pipefail
cd "$(dirname "$0")/rnidbg"
mkdir -p vendor
archive=$(mktemp);trap 'rm -f "$archive"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 'https://codeload.github.com/fuqiuluo/rnidbg/tar.gz/06251628767c577a0579ee8c2b834ed688393bfd' -o "$archive"
printf '%s  %s\n' d470c05d2f6254838fb1bf1d88ec97db0d91d6164a141ce6c22fd6fbd8be0f89 "$archive" | sha256sum --check
[[ ! -e vendor/rnidbg ]] || { echo 'Use a fresh build directory' >&2;exit 1; }
mkdir vendor/rnidbg
tar --extract --gzip --file "$archive" --strip-components=1 --directory vendor/rnidbg
# Stop parent checkout discovery: otherwise git silently skips vendor-relative paths.
(cd vendor/rnidbg && GIT_CEILING_DIRECTORIES="$(dirname "$PWD")" git apply --check ../../upstream-compat.patch && GIT_CEILING_DIRECTORIES="$(dirname "$PWD")" git apply ../../upstream-compat.patch)
grep -q 'pub use tool::UnicornArg;' vendor/rnidbg/emulator/src/lib.rs
CARGO_BUILD_JOBS=2 cargo build --locked --release
