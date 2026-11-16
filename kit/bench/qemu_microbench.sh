#!/bin/bash
# Per-frame instruction cost on an emulated ARM Cortex-A9, via the QEMU TCG
# plugin of count.c. Counts instructions with 0 and with 20000 repetitions of
# the same payload length and subtracts, so that process start-up and argv
# parsing (constant, independent of the repeat count) cancel out:
#   instructions per operation (seal or open, measured separately) = (I1 - I0) / 20000
#
#   sh bench/qemu_microbench.sh [qemu-arm path] [libcount.so path]
#
# Measures Ascon-AEAD128 (kit/build/mavcrypt_tool_arm, built by
# tests/build_and_test.sh). The AES-GCM and ChaCha20-Poly1305 versions
# (mavcrypt_tool_arm_aesgcm / _chacha, cross-compiled against a static OpenSSL
# for armhf by bench/build_openssl_arm.sh) are measured with
# bench/qemu_microbench_all.sh.
set -eu
KIT=$(cd -P "$(dirname "$0")/.." && pwd -P)
QEMU=${1:-$HOME/qemu/build/qemu-arm}
PLUGIN=${2:-$KIT/bench/libcount.so}
TOOL=$KIT/build/mavcrypt_tool_arm
[ -x "$QEMU" ] || { echo "qemu-arm not found: $QEMU (build it first, see bench/build_qemu_plugin.sh)"; exit 2; }
[ -f "$PLUGIN" ] || { echo "plugin not found: $PLUGIN (build it first, see bench/build_qemu_plugin.sh)"; exit 2; }
[ -x "$TOOL" ] || { echo "$TOOL not found: run tests/build_and_test.sh or drone/build_all.sh"; exit 2; }

echo "payload,alg,operation,insns_per_frame"
for L in 36 255; do
    for OP in seal open; do
        I0=$("$QEMU" -cpu cortex-a9 -plugin "$PLUGIN" "$TOOL" bench "$L" 0 "$OP" 2>&1 >/dev/null | grep -oP 'insns:\s*\K[0-9]+')
        I1=$("$QEMU" -cpu cortex-a9 -plugin "$PLUGIN" "$TOOL" bench "$L" 20000 "$OP" 2>&1 >/dev/null | grep -oP 'insns:\s*\K[0-9]+')
        PER=$(( (I1 - I0) / 20000 ))
        echo "$L,ascon,$OP,$PER (I0=$I0 I1=$I1)"
    done
done
