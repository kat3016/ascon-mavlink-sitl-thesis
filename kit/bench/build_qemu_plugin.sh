#!/bin/bash
# Builds QEMU from source with TCG plugin support (Ubuntu's qemu-user package
# does not enable --enable-plugins and recent releases dropped the example
# instruction-count plugin), then builds libcount.so against it.
#
#   sudo apt install -y ninja-build libglib2.0-dev pkg-config python3-venv
#   sh bench/build_qemu_plugin.sh [QEMU_DIR] [QEMU_TAG]
set -eu
KIT=$(cd -P "$(dirname "$0")/.." && pwd -P)
DIR=${1:-$HOME/qemu}
# v10.2.1 matches this host's qemu-user package exactly (consistent version
# number for the thesis). v9.2.0 (the originally planned tag) fails to build
# on this host: glibc now
# defines "struct sched_attr" in <linux/sched/types.h>, colliding with
# QEMU's own compat definition in linux-user/syscall.c (fixed upstream by
# v10.2.1's release date).
TAG=${2:-v10.2.1}

if [ ! -x "$DIR/build/qemu-arm" ]; then
    if [ ! -d "$DIR" ]; then
        git clone https://gitlab.com/qemu-project/qemu.git "$DIR"
    fi
    # --disable-werror: v9.2.0 has a const-discard warning (util/log.c) that
    # gcc 15 (Ubuntu 26.04, newer than this QEMU release) treats as an error
    (cd "$DIR" && git checkout "$TAG" \
        && ./configure --target-list=arm-linux-user --enable-plugins --disable-docs \
                       --disable-werror \
        && make -j"$(nproc)")
fi
"$DIR/build/qemu-arm" --version | head -1

gcc -shared -fPIC -O2 $(pkg-config --cflags glib-2.0) -I "$DIR/include/qemu" \
    -o "$KIT/bench/libcount.so" "$KIT/bench/count.c"
echo "[ok] $KIT/bench/libcount.so"
echo "next: sh bench/qemu_microbench.sh $DIR/build/qemu-arm $KIT/bench/libcount.so"
