#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p fixtures/build
clang -nostdlib -static -Wl,--build-id=none -o fixtures/build/owned-x64 fixtures/entry-x64.s
clang --target=aarch64-linux-android23 -fuse-ld=lld -shared -fPIC -nostdlib -Wl,--hash-style=sysv -o fixtures/build/owned-arm64.so fixtures/owned-jni.c
clang --target=armv7a-linux-androideabi23 -fuse-ld=lld -shared -fPIC -nostdlib -Wl,--hash-style=sysv -o fixtures/build/owned-arm32.so fixtures/owned-jni.c

clang -nostdlib -static -Wl,--build-id=none -o fixtures/build/denied-x64 fixtures/denied-x64.s
clang --target=aarch64-linux-android23 -fuse-ld=lld -shared -fPIC -nostdlib -DCLINE_OWNED_DENIED_SYSCALL -Wl,--hash-style=sysv -o fixtures/build/denied-arm64.so fixtures/owned-jni.c
clang --target=armv7a-linux-androideabi23 -fuse-ld=lld -shared -fPIC -nostdlib -DCLINE_OWNED_DENIED_SYSCALL -Wl,--hash-style=sysv -o fixtures/build/denied-arm32.so fixtures/owned-jni.c

# Qiling uses separate static Linux entry images, never the Android JNI libraries.
for arch in arm32 arm64; do
  target=armv7-linux-gnueabihf
  if [[ "$arch" == arm64 ]]; then target=aarch64-linux-gnu; fi
  clang --target="$target" -fuse-ld=lld -nostdlib -static -Wl,--build-id=none -Wl,-e,_start -o "fixtures/build/owned-linux-$arch" "fixtures/entry-$arch.s"
  clang --target="$target" -fuse-ld=lld -nostdlib -static -Wl,--build-id=none -Wl,-e,_start -o "fixtures/build/denied-linux-$arch" "fixtures/denied-linux-$arch.s"
done
