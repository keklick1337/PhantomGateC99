# ---------------------------------------------------
# Dockerfile (Debian-based) for cross-compiling PhantomGate
# for multiple Linux architectures (x86_64, ARMv7, AArch64, MIPS, i386, riscv64), statically.
# ---------------------------------------------------
FROM debian:bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y && apt-get install -y --no-install-recommends \
    build-essential make file pkg-config \
    gcc g++ \
    gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
    gcc-mips-linux-gnu g++-mips-linux-gnu \
    gcc-riscv64-linux-gnu g++-riscv64-linux-gnu \
    gcc-multilib \
    ca-certificates git wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY build.sh /build.sh
RUN chmod +x /build.sh

CMD ["/build.sh"]