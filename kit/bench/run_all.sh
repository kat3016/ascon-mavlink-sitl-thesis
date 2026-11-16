#!/bin/bash
# First unattended part of the experimental campaign (210 runs).
# Run as root (network namespaces). Meant to be launched detached, e.g.
#   systemd-run --unit=campaign --collect bash "$PWD/bench/run_all.sh"
#
# Stages, in priority order, so that stopping early still leaves the most
# important data complete:
#   0. preflight: binaries, certificate, leftover processes, SITL working directory
#   1. S0 smoke gate, every treatment (go/no-go; not part of the analysis).
#      Any failure aborts the campaign before collecting data.
#   2. MAIN DESIGN   N1 x S1..S4 x {plain,ascon,aesgcm,chacha,dtls} x 5 runs
#   3. HARDWARE      N1 x S1 x {aesgcm-hw,chacha-hw} x 5 runs
#                    (OpenSSL acceleration left on, to show how much the
#                    ranking depends on the instruction set)
#   4. LINK SWEEP    N0, N2 x S1,S4 x the five treatments x 5 runs
# The second part (bench/run_extra.sh) adds the sweep under N3 and the
# hardware variants of S2-S4; the confirmatory phase is bench/run_confirmatory.sh.
# Treatment order alternates between runs (counterbalancing). Before every
# run the host is checked for AC power and the Ultimate Performance plan
# (run_campaign.sh); a run that fails is retried once.
#
# Progress: $STATUS (one line per stage) and $LOG (everything).
set -u
KIT=$(cd -P "$(dirname "$0")/.." && pwd -P)
DATA=$(cd -P "$KIT/.." && pwd -P)/data
WORK=${WORK:-$HOME/campaign}
STATUS=$WORK/status.txt
LOG=$WORK/campaign.log
export ARDUPILOT=${ARDUPILOT:-$HOME/ardupilot}
PY=${PY:-python3}
SCHEMES=plain,ascon,aesgcm,chacha,dtls
mkdir -p "$WORK"
exec >> "$LOG" 2>&1

stage() { echo "$(date '+%F %T') $*" | tee -a "$STATUS" >&2; }
summarize() {
    "$PY" "$KIT/gcs/summarize.py" "$1" 2>&1 | tail -n 40
}
abort() { stage "ABORTED: $*"; echo ABORTED >> "$STATUS"; exit 1; }

: > "$STATUS"
stage "START campaign"

# ---- 0. preflight ------------------------------------------------------
for f in arducopter_plain_sitl arducopter_ascon_sitl arducopter_aesgcm_sitl arducopter_chacha_sitl \
         libmavcrypt_aesgcm.so libmavcrypt_chacha.so dtls_tunnel; do
    [ -e "$KIT/build/$f" ] || abort "missing $KIT/build/$f"
done
[ -f "$KIT/bench/uav.pem" ] && [ -f "$KIT/bench/uav.key" ] || abort "missing kit/bench/uav.pem/key"
pkill -f 'arducopter|secure_proxy|dtls_tunnel|tcpdump' 2>/dev/null
ip netns del uav 2>/dev/null; ip link del veth-gcs 2>/dev/null
. "$KIT/bench/sitl_nostorage.sh" || abort "cannot prepare the SITL working directory"
stage "preflight ok; binaries md5: $(cd "$KIT/build" && md5sum arducopter_*_sitl dtls_tunnel | cut -c1-8 | tr '\n' ' ')"

# ---- 1. S0 gate --------------------------------------------------------
stage "STAGE 1/4 S0 gate (7 treatments, ~12 min)"
OUT=$WORK/s0_gate bash "$KIT/bench/run_campaign.sh" N1 S0 \
    --schemes "$SCHEMES,aesgcm-hw,chacha-hw" --runs 1 || abort "S0 gate failed (see $LOG)"
python3 "$KIT/bench/check_sitl_state.py" "$WORK/s0_gate/S0_N1_plain_run01_capture.pcap" \
    || abort "simulator state differs from the declared one"
stage "S0 gate passed"

# ---- 2. main design ----------------------------------------------------
stage "STAGE 2/4 main design N1 x S1-S4 x 5 treatments x 5 runs (~6.5 h)"
bash "$KIT/bench/run_campaign.sh" N1 S1 S2 S3 S4 --schemes "$SCHEMES" --runs 5
RC=$?; summarize "$DATA/sitl" > "$WORK/summary_after_stage2.txt"
stage "stage 2 finished (rc=$RC); summary in $WORK/summary_after_stage2.txt"

# ---- 3. hardware-acceleration variants ----------------------------------
stage "STAGE 3/4 hardware variants N1 x S1 x aesgcm-hw,chacha-hw x 5 runs (~1 h)"
bash "$KIT/bench/run_campaign.sh" N1 S1 --schemes aesgcm-hw,chacha-hw --runs 5
RC=$?; summarize "$DATA/sitl" > "$WORK/summary_after_stage3.txt"
stage "stage 3 finished (rc=$RC)"

# ---- 4. link sweep -------------------------------------------------------
for P in N0 N2; do
    stage "STAGE 4/4 link sweep: profile $P x S1,S4 x 5 treatments x 5 runs (~3.3 h)"
    bash "$KIT/bench/run_campaign.sh" "$P" S1 S4 --schemes "$SCHEMES" --runs 5
    RC=$?; summarize "$DATA/sitl" > "$WORK/summary_after_$P.txt"
    stage "sweep $P finished (rc=$RC)"
done

ip netns del uav 2>/dev/null; ip link del veth-gcs 2>/dev/null
stage "ALL_DONE"
echo ALL_DONE >> "$STATUS"
