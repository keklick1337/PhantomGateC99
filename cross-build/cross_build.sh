#!/usr/bin/env bash
docker build -t phantomgate-cross .
rm -rf aarch64 armv7 mips x86_64
docker run --rm -v "$PWD/../src":/src -v "$PWD":/cross-build phantomgate-cross