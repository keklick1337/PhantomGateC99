#!/usr/bin/env bash
CROSS_BUILD_NAME="phantomgate-build-cross"
I386_BUILD_NAME="phantomgate-build-i386"

docker build -t $CROSS_BUILD_NAME -f Dockerfile.cross .
docker build -t $CROSS_BUILD_NAME -f Dockerfile.i386 .

rm -rf aarch64 armv7 mips x86_64 riscv64 i386
docker run --rm -v "$PWD/../src":/src -v "$PWD":/cross-build $CROSS_BUILD_NAME
docker run --rm -v "$PWD/../src":/src -v "$PWD":/cross-build $I386_BUILD_NAME