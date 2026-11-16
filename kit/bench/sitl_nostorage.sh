#!/bin/bash
# Prepares the working directory in which every SITL run is started.
#
# SITL keeps its parameter file (eeprom.bin) and other state in its working
# directory. All runs of the thesis use the same simulator state: default
# parameters loaded in memory at each start (--defaults, -w) and no persistent
# parameter storage. This script makes the directory immutable so that SITL
# cannot write to it, and exports SITL_CWD for tests/bench_e2e.sh.
#
# Source it as root before a campaign:   . bench/sitl_nostorage.sh
# The state is checked on the capture of the S0 gate by bench/check_sitl_state.py.
export SITL_CWD=${SITL_CWD:-$HOME/sitl_nostorage}
mkdir -p "$SITL_CWD"
chattr -i "$SITL_CWD" 2>/dev/null
find "$SITL_CWD" -mindepth 1 -delete 2>/dev/null
chattr +i "$SITL_CWD" || { echo "chattr +i failed on $SITL_CWD"; return 1 2>/dev/null || exit 1; }
if touch "$SITL_CWD/.probe" 2>/dev/null; then
    rm -f "$SITL_CWD/.probe"
    echo "$SITL_CWD is writable"; return 1 2>/dev/null || exit 1
fi
