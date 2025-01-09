#!/usr/bin/env bash

echo "=== Starting x86_64, armv7, aarch64, mips, riscv64 builds for PhantomGate (Debian-based) ==="
BUILD_ROOT=/cross-build

mkdir -p "$BUILD_ROOT/x86_64" \
         "$BUILD_ROOT/armv7" \
         "$BUILD_ROOT/aarch64" \
         "$BUILD_ROOT/mips" \
         "$BUILD_ROOT/riscv64"

# 1) x86_64 (native)
echo "--- Building for x86_64 (native) ---"
gcc -std=c99 -static -o "$BUILD_ROOT/x86_64/phantomgate" /src/*.c -pthread
strip "$BUILD_ROOT/x86_64/phantomgate"
cd "$BUILD_ROOT/x86_64"; cp /signatures.txt . ; tar czf ../phantomgate_x86_64.tar.gz .

# 2) armv7
echo "--- Building for armv7 (arm-linux-gnueabihf) ---"
arm-linux-gnueabihf-gcc -std=c99 -static -o "$BUILD_ROOT/armv7/phantomgate" /src/*.c -pthread
arm-linux-gnueabihf-strip "$BUILD_ROOT/armv7/phantomgate"
cd "$BUILD_ROOT/armv7"; cp /signatures.txt . ; tar czf ../phantomgate_armv7.tar.gz .

# 3) aarch64
echo "--- Building for aarch64 (aarch64-linux-gnu) ---"
aarch64-linux-gnu-gcc -std=c99 -static -o "$BUILD_ROOT/aarch64/phantomgate" /src/*.c -pthread
aarch64-linux-gnu-strip "$BUILD_ROOT/aarch64/phantomgate"
cd "$BUILD_ROOT/aarch64"; cp /signatures.txt . ; tar czf ../phantomgate_aarch64.tar.gz .

# 4) mips
echo "--- Building for mips (mips-linux-gnu) ---"
mips-linux-gnu-gcc -std=c99 -static -o "$BUILD_ROOT/mips/phantomgate" /src/*.c -pthread
mips-linux-gnu-strip "$BUILD_ROOT/mips/phantomgate"
cd "$BUILD_ROOT/mips"; cp /signatures.txt . ; tar czf ../phantomgate_mips.tar.gz .

# 5) riscv64
echo "--- Building for riscv64 (riscv64-linux-gnu) ---"
riscv64-linux-gnu-gcc -std=c99 -static -o "$BUILD_ROOT/riscv64/phantomgate" /src/*.c -pthread
riscv64-linux-gnu-strip "$BUILD_ROOT/riscv64/phantomgate"
cd "$BUILD_ROOT/riscv64"; cp /signatures.txt . ; tar czf ../phantomgate_riscv64.tar.gz .

echo "=== x86_64, armv7, aarch64, mips, riscv64 builds done! ==="
ls -lR "$BUILD_ROOT"
