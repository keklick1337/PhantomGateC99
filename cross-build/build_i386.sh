#!/usr/bin/env bash

echo "=== Starting i386-build for PhantomGate (Debian-based) ==="
BUILD_ROOT=/cross-build

mkdir -p "$BUILD_ROOT/i386"

echo "--- Building for i386 (-m32) ---"
gcc -std=c99 -m32 -static -Wall -Wextra -o "$BUILD_ROOT/i386/phantomgate" /src/*.c -pthread
strip "$BUILD_ROOT/i386/phantomgate"
cd "$BUILD_ROOT/i386"; cp /signatures.txt . ; tar czf ../phantomgate_i386.tar.gz .

echo "=== i386 build done! ==="
ls -lR "$BUILD_ROOT"
