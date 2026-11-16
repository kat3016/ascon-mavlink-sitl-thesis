#!/bin/bash
# Instructions per frame on an emulated Cortex-A9 for the three AEADs, seal and
# open measured separately (I(20000) - I(0)) / 20000. The OpenSSL builds are run
# twice: with OpenSSL's default CPU detection (NEON paths, as on an ARM Cortex-A9 board's
# Cortex-A9) and with OPENSSL_armcap=0 (plain ARMv7 code, no NEON).
#
#   SIZES="12 36 64 100 160 255" bash bench/qemu_microbench_all.sh > data/qemu_sweep.csv
set -eu
KIT=$(cd -P "$(dirname "$0")/.." && pwd -P)
QEMU=${QEMU:-$HOME/qemu/build/qemu-arm}
PLUGIN=${PLUGIN:-$KIT/bench/libcount.so}
N=${N:-20000}
echo "alg,config,payload,op,insns_per_frame,I0,I1"
for spec in "ascon:$KIT/build/mavcrypt_tool_arm:own code" \
            "aesgcm:$KIT/build/mavcrypt_tool_arm_aesgcm:NEON" \
            "aesgcm:$KIT/build/mavcrypt_tool_arm_aesgcm:no NEON" \
            "chacha:$KIT/build/mavcrypt_tool_arm_chacha:NEON" \
            "chacha:$KIT/build/mavcrypt_tool_arm_chacha:no NEON"; do
    IFS=: read -r alg tool cfg <<< "$spec"
    for L in ${SIZES:-12 36 64 100 160 255}; do
        for OP in seal open; do
            run() {
                if [ "$cfg" = "no NEON" ]; then export OPENSSL_armcap=0; else unset OPENSSL_armcap; fi
                "$QEMU" -cpu cortex-a9 -plugin "$PLUGIN" "$tool" bench "$L" "$1" "$OP" 2>&1 >/dev/null | grep -oP 'insns:\s*\K[0-9]+'
            }
            I0=$(run 0); I1=$(run "$N")
            echo "$alg,$cfg,$L,$OP,$(( (I1 - I0) / N )),$I0,$I1"
        done
    done
done
