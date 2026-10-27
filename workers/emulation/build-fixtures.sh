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
