#!/usr/bin/env bash
set -e

echo "=== Starting i386-build for PhantomGate (Debian-based) ==="
BUILD_ROOT=/cross-build

mkdir -p "$BUILD_ROOT/i386"

echo "--- Building for i386 (-m32) ---"
gcc -std=c99 -m32 -static -o "$BUILD_ROOT/i386/phantomgate" /src/src/*.c -pthread
strip "$BUILD_ROOT/i386/phantomgate"

echo "=== i386 build done! ==="
ls -lR "$BUILD_ROOT"
