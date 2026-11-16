#!/bin/bash
# Static OpenSSL for ARMv7 (armhf) and the AES-GCM / ChaCha20-Poly1305 versions
# of mavcrypt_tool for the emulated Cortex-A9, so that their instruction counts
# can be compared with Ascon's (bench/qemu_microbench.sh).
#
#   bash bench/build_openssl_arm.sh
#
# OpenSSL keeps its ARM assembly (NEON, ARMv4 fall-backs). Whether the NEON
# paths run is decided at run time by OPENSSL_armcap, so the same binary gives
# both measurements: default (what OpenSSL would pick on a Cortex-A9 with NEON,
# like an ARM Cortex-A9 board's) and OPENSSL_armcap=0 (no NEON, plain ARMv7 code).
set -eu
KIT=$(cd -P "$(dirname "$0")/.." && pwd -P)
VER=${OPENSSL_VER:-3.5.5}
WORK=${WORK:-$HOME/builds/openssl-arm}
PREFIX=$WORK/install
CROSS=arm-linux-gnueabihf-
mkdir -p "$WORK"
cd "$WORK"
if [ ! -d "openssl-$VER" ]; then
    URL=https://github.com/openssl/openssl/releases/download/openssl-$VER/openssl-$VER.tar.gz
    curl -fsSL -o "openssl-$VER.tar.gz" "$URL"
    curl -fsSL -o "openssl-$VER.tar.gz.sha256" "$URL.sha256"
    echo "$(cut -d' ' -f1 "openssl-$VER.tar.gz.sha256")  openssl-$VER.tar.gz" | sha256sum -c -
    tar xzf "openssl-$VER.tar.gz"
fi
if [ ! -f "$PREFIX/lib/libcrypto.a" ]; then
    cd "openssl-$VER"
    ./Configure linux-armv4 --cross-compile-prefix=$CROSS no-shared no-tests no-apps no-docs \
        no-dso no-engine no-module --prefix="$PREFIX" --libdir=lib
    make -j"$(nproc)" build_libs
    make install_dev
    cd "$WORK"
fi
echo "libcrypto.a: $(ls -la "$PREFIX/lib/libcrypto.a")"

cd "$KIT"
A=third_party/ascon-c
for spec in 2:aesgcm 3:chacha; do
    n=${spec%%:*}; name=${spec##*:}
    ${CROSS}gcc-13 -std=c99 -O2 -static -D_POSIX_C_SOURCE=199309L -DAP_MAVCRYPT_ENABLED=1 -DAP_MAVCRYPT_ALG=$n \
        -Icommon -I"$PREFIX/include" -o "build/mavcrypt_tool_arm_$name" \
        tools/mavcrypt_tool.c common/mavcrypt_core.c drone/AP_MAVCrypt/mavcrypt_ossl.c \
        "$PREFIX/lib/libcrypto.a" -ldl -lpthread
    echo "built build/mavcrypt_tool_arm_$name"
done
