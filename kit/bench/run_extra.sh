#!/bin/bash
# Second unattended part of the experimental campaign (80 runs), capped at a
# wall-clock budget:
#   1. S0 smoke check (plain, ascon, dtls) under N1 and under N3
#   2. LINK SWEEP N3 x S1,S4 x the five treatments x 5 runs
#   3. HARDWARE   N1 x S2,S3,S4 x aesgcm-hw,chacha-hw x 5 runs
# Same conditions as run_all.sh (Ultimate Performance, AC power, scalar OpenSSL
# unless -hw, core pinning, same SITL state). New data are added to data/sitl.
# Each stage is killed when the budget (default 7 h) runs out.
set -u
KIT=$(cd -P "$(dirname "$0")/.." && pwd -P)
DATA=$(cd -P "$KIT/.." && pwd -P)/data
WORK=${WORK:-$HOME/campaign2}
BUDGET=${BUDGET:-25200}
STATUS=$WORK/status.txt
export ARDUPILOT=${ARDUPILOT:-$HOME/ardupilot}
PY=${PY:-python3}
mkdir -p "$WORK"
exec >> "$WORK/campaign.log" 2>&1
T0=$(date +%s)
log() { echo "$(date '+%F %T') $*" | tee -a "$STATUS" >&2; }
left() { echo $(( BUDGET - ($(date +%s) - T0) )); }
stage() { # name, then the run_campaign.sh arguments
    local name=$1; shift
    local L; L=$(left)
    if [ "$L" -le 600 ]; then log "SKIPPED $name: budget exhausted"; return; fi
    log "STAGE $name (budget left ${L}s)"
    timeout -k 30 "$L" bash "$KIT/bench/run_campaign.sh" "$@"
    log "stage $name finished (rc=$?)"
    ip netns del uav 2>/dev/null; ip link del veth-gcs 2>/dev/null
    pkill -KILL -f 'arducopter|secure_proxy|dtls_tunnel|tcpdump|stream_monitor|latency_timesync|ram_monitor' 2>/dev/null
}
: > "$STATUS"
log "START extra campaign, budget ${BUDGET}s"
pkill -f 'arducopter|secure_proxy|dtls_tunnel|tcpdump' 2>/dev/null
ip netns del uav 2>/dev/null; ip link del veth-gcs 2>/dev/null
. "$KIT/bench/sitl_nostorage.sh" || { log "ABORTED: cannot prepare the SITL working directory"; exit 1; }
OUT=$WORK/s0_gate stage "S0 N1" N1 S0 --schemes plain,ascon,dtls --runs 1
python3 "$KIT/bench/check_sitl_state.py" "$WORK/s0_gate/S0_N1_plain_run01_capture.pcap" \
    || { log "ABORTED: simulator state differs from the declared one"; exit 1; }
OUT=$WORK/s0_gate stage "S0 N3" N3 S0 --schemes plain,ascon,dtls --runs 1
stage "sweep N3" N3 S1 S4 --schemes plain,ascon,aesgcm,chacha,dtls --runs 5
stage "hardware S2-S4" N1 S2 S3 S4 --schemes aesgcm-hw,chacha-hw --runs 5
"$PY" "$KIT/gcs/summarize.py" "$DATA/sitl" > "$WORK/summary_extra.txt" 2>&1
log "ALL_DONE after $(( $(date +%s) - T0 )) s"
echo ALL_DONE >> "$STATUS"
