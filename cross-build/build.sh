#!/usr/bin/env bash
set -e

echo "=== Starting cross-build for PhantomGate (Debian-based) ==="
BUILD_ROOT=/cross-build

mkdir -p "$BUILD_ROOT/x86_64" \
         "$BUILD_ROOT/i386" \
         "$BUILD_ROOT/armv7" \
         "$BUILD_ROOT/aarch64" \
         "$BUILD_ROOT/mips" \
         "$BUILD_ROOT/riscv64"

# 1) x86_64 (native)
echo "--- Building for x86_64 (native) ---"
gcc -std=c99 -static -o "$BUILD_ROOT/x86_64/phantomgate" /src/src/*.c -pthread
strip "$BUILD_ROOT/x86_64/phantomgate"

# 2) i386 (using -m32 + multilib)
echo "--- Building for i386 (-m32) ---"
gcc -std=c99 -m32 -static -o "$BUILD_ROOT/i386/phantomgate" /src/src/*.c -pthread
strip "$BUILD_ROOT/i386/phantomgate"

# 3) armv7
echo "--- Building for armv7 (arm-linux-gnueabihf) ---"
arm-linux-gnueabihf-gcc -std=c99 -static -o "$BUILD_ROOT/armv7/phantomgate" /src/src/*.c -pthread
strip "$BUILD_ROOT/armv7/phantomgate"

# 4) aarch64
echo "--- Building for aarch64 (aarch64-linux-gnu) ---"
aarch64-linux-gnu-gcc -std=c99 -static -o "$BUILD_ROOT/aarch64/phantomgate" /src/src/*.c -pthread
strip "$BUILD_ROOT/aarch64/phantomgate"

# 5) mips
echo "--- Building for mips (mips-linux-gnu) ---"
mips-linux-gnu-gcc -std=c99 -static -o "$BUILD_ROOT/mips/phantomgate" /src/src/*.c -pthread
strip "$BUILD_ROOT/mips/phantomgate"

# 6) riscv64
echo "--- Building for riscv64 (riscv64-linux-gnu) ---"
riscv64-linux-gnu-gcc -std=c99 -static -o "$BUILD_ROOT/riscv64/phantomgate" /src/src/*.c -pthread
strip "$BUILD_ROOT/riscv64/phantomgate"

echo "=== All cross-builds done! ==="
ls -lR "$BUILD_ROOT"
