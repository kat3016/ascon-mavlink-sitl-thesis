#!/bin/sh
# Build the kit's native pieces and run every offline test.
#
#   sh tests/build_and_test.sh
#
# Builds (in build/):
#   libmavcrypt.so                 C core + ascon-c opt32, used by the Python proxy
#   genkat_opt32, genkat_ref       official KAT generators (PC)
#   test_core, mavcrypt_tool       unit tests and benchmark/cross-check tool (PC)
#   genkat_arm, test_core_arm,     same, cross-compiled static for ARM
#   mavcrypt_tool_arm              (ARMv7 Cortex-A9, arm-linux-gnueabihf)
# The ARM binaries are executed with qemu-arm when it is installed.
# Ends with "ALL n TESTS PASSED" or exits with an error.

set -u
KIT=$(cd -P "$(dirname "$0")/.." && pwd -P)
cd "$KIT" || exit 1
B=build
A=third_party/ascon-c
OFFICIAL_KAT_MD5=519e7cc7eb7558852adc822d1e5c9b70
CC=${CC:-gcc}
ARMCC=${ARMCC:-}
if [ -z "$ARMCC" ]; then
    for c in arm-linux-gnueabihf-gcc-13 arm-linux-gnueabihf-gcc; do
        command -v "$c" >/dev/null 2>&1 && { ARMCC=$c; break; }
    done
fi
CFLAGS="-std=c99 -O2 -Wall -Wextra -D_POSIX_C_SOURCE=199309L"
mkdir -p "$B"

passed=0
failed=0
ok()   { passed=$((passed + 1)); echo "  [PASS] $1"; }
bad()  { failed=$((failed + 1)); echo "  [FAIL] $1"; }
step() { echo; echo "== $1"; }

kat_check() { # $1 = label, $2 = directory with the generated KAT file
    if cmp -s "$2/LWC_AEAD_KAT_128_128.txt" "$A/LWC_AEAD_KAT_128_128.txt"; then
        ok "$1 KAT identical to the official file (md5 $(md5sum < "$2/LWC_AEAD_KAT_128_128.txt" | cut -c1-32))"
    else
        bad "$1 KAT differs from the official file"
    fi
}

step "Build (PC, $($CC --version | head -n1))"
CORE="common/mavcrypt_core.c $A/opt32/aead.c $A/opt32/permutations.c"
$CC $CFLAGS -I$A/opt32 -I$A/tests -o $B/genkat_opt32 $A/tests/genkat_aead.c $A/opt32/aead.c $A/opt32/permutations.c \
    && $CC $CFLAGS -I$A/ref -I$A/tests -o $B/genkat_ref $A/tests/genkat_aead.c $A/ref/aead.c \
    && $CC $CFLAGS -Icommon -I$A/opt32 -I$A/tests -o $B/test_core tests/test_core.c $CORE \
    && $CC $CFLAGS -Icommon -I$A/opt32 -I$A/tests -o $B/mavcrypt_tool tools/mavcrypt_tool.c $CORE \
    && $CC $CFLAGS -fPIC -shared -Icommon -I$A/opt32 -I$A/tests -o $B/libmavcrypt.so gcs/mavcrypt_pyshim.c $CORE \
    && ok "PC binaries and libmavcrypt.so built" || { bad "PC build"; exit 1; }

step "Ascon-AEAD128 known-answer tests (NIST SP 800-232 vectors)"
mkdir -p $B/kat_opt32 $B/kat_ref
(cd $B/kat_opt32 && ../genkat_opt32 >/dev/null) && kat_check "opt32 (used in the drone)" $B/kat_opt32
(cd $B/kat_ref && ../genkat_ref >/dev/null) && kat_check "ref" $B/kat_ref
[ "$(md5sum < $A/LWC_AEAD_KAT_128_128.txt | cut -c1-32)" = "$OFFICIAL_KAT_MD5" ] \
    && ok "official KAT file md5 = $OFFICIAL_KAT_MD5" || bad "official KAT file md5"

step "Core unit tests (PC)"
if $B/test_core > $B/test_core.log 2>&1; then
    ok "$(tail -n 2 $B/test_core.log | head -n 1)"
else
    cat $B/test_core.log; bad "core unit tests"
fi

step "AES-128-GCM and ChaCha20-Poly1305 (OpenSSL backend, official test vectors)"
if pkg-config --exists libcrypto 2>/dev/null || [ -f /usr/include/openssl/evp.h ]; then
    for ALG in 2:aesgcm 3:chacha; do
        n=${ALG%%:*}; name=${ALG##*:}
        if $CC $CFLAGS -DAP_MAVCRYPT_ENABLED=1 -DAP_MAVCRYPT_ALG=$n -Icommon \
               -o $B/test_ossl_$name tests/test_ossl_vectors.c common/mavcrypt_core.c \
               drone/AP_MAVCrypt/mavcrypt_ossl.c -lcrypto 2> $B/test_ossl_$name.build.log \
           && $B/test_ossl_$name > $B/test_ossl_$name.log 2>&1; then
            ok "$(cat $B/test_ossl_$name.log)"
        else
            cat $B/test_ossl_$name.build.log $B/test_ossl_$name.log 2>/dev/null
            bad "$name OpenSSL backend"
        fi
    done
else
    echo "  [skip] openssl/evp.h not found (install libssl-dev)"
fi

step "Python tests (pyascon cross-check, pymavlink frames, stream)"
if python3 tests/test_python.py --tool $B/mavcrypt_tool --tool-runner "" > $B/test_python.log 2>&1; then
    ok "$(tail -n 2 $B/test_python.log | head -n 1)"
else
    cat $B/test_python.log; bad "python tests"
fi

step "ARM (Cortex-A9) cross build"
if [ -z "$ARMCC" ]; then
    bad "no arm-linux-gnueabihf-gcc found (sudo apt install gcc-arm-linux-gnueabihf)"
else
    ACF="$CFLAGS -static"
    $ARMCC $ACF -I$A/opt32 -I$A/tests -o $B/genkat_arm $A/tests/genkat_aead.c $A/opt32/aead.c $A/opt32/permutations.c \
        && $ARMCC $ACF -Icommon -I$A/opt32 -I$A/tests -o $B/test_core_arm tests/test_core.c $CORE \
        && $ARMCC $ACF -Icommon -I$A/opt32 -I$A/tests -o $B/mavcrypt_tool_arm tools/mavcrypt_tool.c $CORE \
        && ok "genkat_arm, test_core_arm, mavcrypt_tool_arm built with $ARMCC ($($ARMCC -dumpversion))" \
        || bad "ARM build"
    QEMU=""
    for q in qemu-arm qemu-arm-static; do
        command -v $q >/dev/null 2>&1 && { QEMU=$q; break; }
    done
    if [ -z "$QEMU" ]; then
        echo "  [skip] qemu-arm not installed: ARM binaries not executed"
    else
        step "ARM binaries under $QEMU"
        mkdir -p $B/kat_arm
        (cd $B/kat_arm && $QEMU ../genkat_arm >/dev/null) && kat_check "ARM opt32" $B/kat_arm
        if $QEMU $B/test_core_arm > $B/test_core_arm.log 2>&1; then
            ok "ARM $(tail -n 2 $B/test_core_arm.log | head -n 1)"
        else
            cat $B/test_core_arm.log; bad "ARM core unit tests"
        fi
        if python3 tests/test_python.py --tool $B/mavcrypt_tool_arm --tool-runner "$QEMU" > $B/test_tool_arm.log 2>&1; then
            ok "ARM mavcrypt_tool produces the same frames as the PC library"
        else
            tail -n 20 $B/test_tool_arm.log; bad "ARM tool cross-check"
        fi
    fi
fi

echo
if [ $failed -eq 0 ]; then
    echo "ALL $passed TESTS PASSED"
    exit 0
fi
echo "$failed FAILED, $passed passed"
exit 1
