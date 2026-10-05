#!/usr/bin/env bash
# Reviewed static engines only. No input sample is executed by this script.
set -euo pipefail
root="${1:?Provide a private staging directory}"
mkdir -p "$root"
root="$(cd "$root" && pwd)"
curl -fL --retry 2 https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip -o "$root/ghidra.zip"
printf '%s  %s\n' ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db "$root/ghidra.zip" | sha256sum -c -
unzip -q "$root/ghidra.zip" -d "$root"
curl -fL --retry 2 https://corretto.aws/downloads/latest/amazon-corretto-25-x64-linux-jdk.tar.gz -o "$root/jdk.tar.gz"
curl -fL --retry 2 https://corretto.aws/downloads/latest_sha256/amazon-corretto-25-x64-linux-jdk.tar.gz -o "$root/jdk.sha256"
digest="$(cat "$root/jdk.sha256")"
[[ "$digest" =~ ^[a-fA-F0-9]{64}$ ]] || { echo 'Invalid provider JDK checksum'; exit 1; }
printf '%s  %s\n' "$digest" "$root/jdk.tar.gz" | sha256sum -c -
mkdir -p "$root/jdk"
tar -xzf "$root/jdk.tar.gz" -C "$root/jdk"
mapfile -t homes < <(find "$root/jdk" -mindepth 1 -maxdepth 1 -type d)
[[ ${#homes[@]} == 1 ]] || { echo 'Unexpected JDK archive layout'; exit 1; }
home="${homes[0]}"
"$home/bin/java" -version
engine="$root/ghidra_12.1.4_PUBLIC/support/analyzeHeadless"
test -f "$engine"
if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'JAVA_HOME=%s\nCLINE_RE_GHIDRA=%s\n' "$home" "$engine" >> "$GITHUB_ENV"
fi
printf 'Ghidra 12.1.4 archive verified; provider JDK SHA-256: %s\n' "$digest"
# The latest provider JDK URL is not a reproducibility pin. Its checked digest
# and Java version are preserved in the CI log; this is not measured isolation.
