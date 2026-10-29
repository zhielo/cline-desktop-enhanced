# CI build environment only; exported runtime contains no compiler/build tools.
ARG COMPILER_IMAGE
ARG PYTHON_IMAGE
FROM ${COMPILER_IMAGE} AS compiler
FROM ${PYTHON_IMAGE} AS build
ARG ENGINE
ENV CARGO_HOME=/usr/local/cargo RUSTUP_HOME=/usr/local/rustup
ENV PATH=/usr/local/cargo/bin:$PATH
COPY --from=compiler /usr/local/cargo /usr/local/cargo
COPY --from=compiler /usr/local/rustup /usr/local/rustup
RUN apt-get update && apt-get install -y --no-install-recommends build-essential clang lld cmake libffi-dev libssl-dev pkg-config git curl ca-certificates maven openjdk-17-jdk-headless zlib1g-dev libjpeg62-turbo-dev libpng-dev libfreetype6-dev && rm -rf /var/lib/apt/lists/*
COPY workers/emulation /build/emulation
COPY workers/re-analysis /build/re-analysis
COPY workers/managed-emulation/engines /build/managed
RUN python3.13 -B /build/managed/prepare.py "$ENGINE"
FROM ${PYTHON_IMAGE} AS runtime
COPY --from=build /opt/cline-engine /opt/cline-engine
# Never start an emulator/fixture during image build. Actual execution is in QEMU.
