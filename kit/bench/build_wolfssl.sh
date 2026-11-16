#!/bin/bash
# Builds wolfSSL with DTLS 1.3 (RFC 9147) and the dtls_tunnel program.
#
#   sh bench/build_wolfssl.sh [WOLFSSL_SRC] [PREFIX] [TAG]
#
# Why wolfSSL: it is the free (GPLv3 / commercial) library with a stable DTLS
# 1.3 implementation; OpenSSL announced DTLS 1.3 for its 4.1 release (October
# 2026), which had not been released when this testbed was frozen. See the
# thesis, Section "DTLS 1.3 tunnel and its UDP control".
#
# Acceleration: AES-NI and every other Intel assembly path are *disabled by
# default* in wolfSSL's configure (--enable-aesni / --enable-intelasm are
# opt-in) and are deliberately not passed here, so the record-layer AES-GCM
# runs the portable C implementation -- the closest wolfSSL equivalent of the
# "scalar" OpenSSL configuration (OPENSSL_ia32cap) used for the other
# treatments. The configure summary is saved to build/wolfssl-configure.log
# so the claim can be checked.
set -eu
KIT=$(cd -P "$(dirname "$0")/.." && pwd -P)
SRC=${1:-$HOME/wolfssl}
PREFIX=${2:-$HOME/wolfssl-install}
TAG=${3:-v5.9.4-stable}   # 5.9.1+ includes the DTLS 1.3 ACK-parsing overflow fix

mkdir -p "$KIT/build"
if [ ! -d "$SRC" ]; then
    git clone --depth 1 --branch "$TAG" https://github.com/wolfSSL/wolfssl.git "$SRC"
fi
if [ ! -f "$PREFIX/lib/libwolfssl.a" ]; then
    (cd "$SRC" \
        && { [ -x ./configure ] || ./autogen.sh; } \
        && ./configure --prefix="$PREFIX" --enable-dtls --enable-dtls13 \
                       --disable-shared --enable-static \
                       --disable-examples --disable-crypttests \
           > "$KIT/build/wolfssl-configure.log" 2>&1 \
        && make -j"$(nproc)" > "$KIT/build/wolfssl-build.log" 2>&1 \
        && make install >> "$KIT/build/wolfssl-build.log" 2>&1)
fi
echo "wolfSSL: $(git -C "$SRC" describe --tags --always 2>/dev/null) -> $PREFIX"
grep -i -E "AES-NI|Intel ASM|DTLS|TLS v1.3|Session Ticket" "$KIT/build/wolfssl-configure.log" 2>/dev/null || true

gcc -O2 -Wall -Wextra -I"$PREFIX/include" \
    -o "$KIT/build/dtls_tunnel" "$KIT/bench/dtls_tunnel.c" \
    -L"$PREFIX/lib" -lwolfssl -lm -lpthread
echo "[ok] $KIT/build/dtls_tunnel"
