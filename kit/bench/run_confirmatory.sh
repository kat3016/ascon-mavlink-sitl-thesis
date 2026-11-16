#!/bin/bash
# Confirmatory phase (declared before running, see the thesis, "Equivalence
# testing and declared design"):
#   0. preflight: binaries md5, leftover processes, SITL working directory
#   1. S0 smoke gate (plain, ascon, aesgcm, chacha), not part of the analysis,
#      plus a check of the simulator state on the gate capture
#   2. N1 x S1 x {plain,ascon,aesgcm,chacha} x 5 runs numbered 06..10
# Same conditions as the main campaign (Ultimate Performance + AC power check
# in run_campaign.sh, scalar OpenSSL, core pinning, alternating order).
#
# Run as root:  bash bench/run_confirmatory.sh            (gate + runs, ~2 h)
#               GATE_ONLY=1 bash bench/run_confirmatory.sh (gate only, ~6 min)
set -u
KIT=$(cd -P "$(dirname "$0")/.." && pwd -P)
DATA=$(cd -P "$KIT/.." && pwd -P)/data
WORK=${WORK:-$HOME/confirm}
STATUS=$WORK/status.txt
export ARDUPILOT=${ARDUPILOT:-$HOME/ardupilot}
SCHEMES=plain,ascon,aesgcm,chacha
mkdir -p "$WORK"
exec >> "$WORK/campaign.log" 2>&1
log() { echo "$(date '+%F %T') $*" | tee -a "$STATUS" >&2; }
abort() { log "ABORTED: $*"; echo ABORTED >> "$STATUS"; exit 1; }
: > "$STATUS"
log "START confirmatory phase (GATE_ONLY=${GATE_ONLY:-0})"

# 0. preflight
want="b8415ce793a8 8d7e16af5736 4c7a8c19867e e12cd73278f0"
got=$(cd "$KIT/build" && md5sum arducopter_aesgcm_sitl arducopter_ascon_sitl arducopter_chacha_sitl arducopter_plain_sitl | cut -c1-12 | tr '\n' ' ')
[ "$got" = "$want " ] || abort "binary md5 mismatch: $got"
pkill -f 'arducopter|secure_proxy|dtls_tunnel|tcpdump' 2>/dev/null
ip netns del uav 2>/dev/null; ip link del veth-gcs 2>/dev/null
. "$KIT/bench/sitl_nostorage.sh" || abort "cannot prepare the SITL working directory"
log "preflight ok; md5 $got; SITL_CWD=$SITL_CWD"

# 1. S0 gate + simulator-state check
GATE=$WORK/s0_gate
OUT=$GATE bash "$KIT/bench/run_campaign.sh" N1 S0 --schemes "$SCHEMES" --runs 1 || abort "S0 gate failed"
python3 "$KIT/bench/check_sitl_state.py" "$GATE/S0_N1_plain_run01_capture.pcap" \
    || abort "simulator state differs from the declared one"
log "S0 gate passed; simulator state as declared"
if [ "${GATE_ONLY:-0}" = 1 ]; then echo GATE_DONE >> "$STATUS"; log "GATE_DONE"; exit 0; fi

# 2. confirmatory runs 06..10
bash "$KIT/bench/run_campaign.sh" N1 S1 --schemes "$SCHEMES" --first 6 --runs 5
RC=$?
log "S1/N1 runs 06-10 finished (rc=$RC)"
for r in 06 07 08 09 10; do
    python3 "$KIT/bench/check_sitl_state.py" "$DATA/sitl/S1_N1_plain_run${r}_capture.pcap" || log "WARNING: run $r differs"
done
ip netns del uav 2>/dev/null; ip link del veth-gcs 2>/dev/null
echo ALL_DONE >> "$STATUS"
log "ALL_DONE"
