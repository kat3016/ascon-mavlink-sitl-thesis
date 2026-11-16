#!/bin/sh
# Build every ArduCopter binary of the campaign from the SAME patched tree.
#
#   sh drone/build_all.sh [sitl] [arm]      (default: both)
#
# Produces in kit/build/:
#   arducopter_plain_sitl, arducopter_{ascon,aesgcm,chacha}_sitl
#   arducopter_plain_arm, arducopter_ascon_arm, arducopter_ascon_stats_arm
# and kit/build/binaries.md5 (record it in the laboratory log).
# The ARM binaries (ArduPilot board 'bebop' = Linux, ARM Cortex-A9, static) are
# the ones run under QEMU; they use g++ 13 when available; override with
# ARM_CC / ARM_CXX.
set -eu
KIT=$(cd -P "$(dirname "$0")/.." && pwd -P)
AP=${ARDUPILOT:-$HOME/ardupilot}
OUT="$KIT/build"
mkdir -p "$OUT"
TARGETS=${*:-sitl arm}

use_alg() { # ascon | aesgcm | chacha: regenerate the key for this algorithm
            # and (re)install the library + patches before building it.
    python3 "$KIT/gen_key.py" --alg "$1" >/dev/null
    python3 "$KIT/drone/apply_mavcrypt.py" "$AP" >/dev/null
}

use_alg ascon  # also the --check baseline below, and what plain/ascon build against
python3 "$KIT/drone/apply_mavcrypt.py" "$AP" --check >/dev/null || {
    echo "the ArduPilot tree is not patched/up to date: python3 drone/apply_mavcrypt.py $AP"; exit 1; }

build() { # board, define(s), output name, extra env
    echo "== $3"
    (cd "$AP" && ./waf configure --board "$1" $2 > "$OUT/$3.configure.log" 2>&1 \
        && ./waf copter > "$OUT/$3.build.log" 2>&1) || {
        echo "   build failed, see $OUT/$3.build.log"; tail -n 20 "$OUT/$3.build.log"; exit 1; }
    cp "$AP/build/$1/bin/arducopter" "$OUT/$3"
    echo "   $(grep -m1 "bin/arducopter" "$OUT/$3.build.log" | sed 's/  */ /g')"
}

for t in $TARGETS; do
    case $t in
        sitl)
            unset CC CXX 2>/dev/null || true
            build sitl "" arducopter_plain_sitl
            use_alg ascon
            build sitl "--define AP_MAVCRYPT_ENABLED=1 --define AP_MAVCRYPT_ALG=1" arducopter_ascon_sitl
            use_alg aesgcm
            build sitl "--define AP_MAVCRYPT_ENABLED=1 --define AP_MAVCRYPT_ALG=2" arducopter_aesgcm_sitl
            use_alg chacha
            build sitl "--define AP_MAVCRYPT_ENABLED=1 --define AP_MAVCRYPT_ALG=3" arducopter_chacha_sitl
            ;;
        arm)
            if command -v arm-linux-gnueabihf-g++-13 >/dev/null 2>&1; then
                export CC=${ARM_CC:-arm-linux-gnueabihf-gcc-13} CXX=${ARM_CXX:-arm-linux-gnueabihf-g++-13}
            fi
            build bebop "--static" arducopter_plain_arm
            build bebop "--static --define AP_MAVCRYPT_ENABLED=1" arducopter_ascon_arm
            build bebop "--static --define AP_MAVCRYPT_ENABLED=1 --define MAVCRYPT_STATS_EVERY=1000" \
                arducopter_ascon_stats_arm
            unset CC CXX
            ;;
        *) echo "unknown target $t"; exit 2 ;;
    esac
done

cd "$OUT"
{
    echo "# $(date '+%Y-%m-%d %H:%M') ArduPilot $(git -C "$AP" rev-parse --short HEAD)"
    md5sum arducopter_*_sitl arducopter_*_arm 2>/dev/null
} | tee binaries.md5
