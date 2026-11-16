#!/bin/bash
# Automated campaign: runs bench_e2e.sh over every (scheme, scenario) pair for a
# given network profile, 5 runs each, alternating treatment order between runs
# (counterbalancing). Must run as root (bench_e2e.sh uses network namespaces).
#
#   sudo bash bench/run_campaign.sh <profile> <scenario...> [--schemes a,b,c] [--runs N]
#
# Examples:
#   sudo bash bench/run_campaign.sh N1 S1                      # 5 schemes x 5 runs
#   sudo bash bench/run_campaign.sh N1 S1 S2 S3 S4 --schemes plain,ascon
#   sudo bash bench/run_campaign.sh N1 S1 S4 --runs 5           # network sweep uses this too
#
# Each run is logged on stdout (laboratory-log style); failures do
# not stop the campaign (a scheme/scenario pair can fail without losing the
# rest), but are summarized at the end with a non-zero exit code.
set -u
KIT=$(cd -P "$(dirname "$0")/.." && pwd -P)
PROFILE=$1; shift
SCHEMES="plain,ascon,aesgcm,chacha,dtls"
RUNS=5
FIRST=1   # first run number; --first 6 --runs 5 produces run06..run10 (confirmatory phase)
SCENARIOS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --schemes) SCHEMES=$2; shift 2 ;;
        --runs) RUNS=$2; shift 2 ;;
        --first) FIRST=$2; shift 2 ;;
        S*) SCENARIOS="$SCENARIOS $1"; shift ;;
        *) echo "unknown argument $1"; exit 2 ;;
    esac
done
[ -n "$SCENARIOS" ] || { echo "usage: run_campaign.sh <profile> <S1 [S2 ...]> [--schemes a,b,c] [--runs N]"; exit 2; }

IFS=',' read -r -a SCHEME_ARR <<< "$SCHEMES"
PASS=0; FAIL=0; FAILED_LIST=""; RETRIED_LIST=""
T0=$(date +%s)

# The thesis states fixed host conditions: AC power and the Ultimate
# Performance plan. This runs on a Windows laptop through WSL2, so the check
# goes through powershell.exe. If either condition is lost the campaign waits
# (and says so) instead of collecting data under a different configuration;
# if powershell.exe is not reachable it warns once and carries on.
PS_WARNED=0
wait_for_host_conditions() {
    local state paused=0
    while true; do
        state=$(timeout 30 powershell.exe -NoProfile -Command \
            "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus; powercfg /getactivescheme" \
            2>/dev/null | tr -d '\r')
        if [ -z "$state" ]; then
            [ $PS_WARNED = 0 ] && echo "### WARNING: cannot query Windows power state from WSL; host conditions NOT being checked ###"
            PS_WARNED=1; return 0
        fi
        if echo "$state" | grep -q '^Online' && echo "$state" | grep -q 'Ultimate Performance'; then
            [ $paused = 1 ] && echo "### $(date '+%F %T') host conditions restored, resuming ###"
            return 0
        fi
        [ $paused = 0 ] && echo "### $(date '+%F %T') PAUSED: need AC power + Ultimate Performance, got: $(echo "$state" | tr '\n' ' ') ###"
        paused=1
        sleep 30
    done
}

for run in $(seq -f "%02g" "$FIRST" $((FIRST + RUNS - 1))); do
    # counterbalance: reverse the treatment order on even-numbered runs
    if [ $((10#$run % 2)) -eq 0 ]; then
        order=()
        for ((i=${#SCHEME_ARR[@]}-1; i>=0; i--)); do order+=("${SCHEME_ARR[$i]}"); done
    else
        order=("${SCHEME_ARR[@]}")
    fi
    for sch in "${order[@]}"; do
        for sc in $SCENARIOS; do
            wait_for_host_conditions
            echo "### $(date '+%F %T') campaign: run=$run scheme=$sch scenario=$sc profile=$PROFILE ###"
            ip netns del uav 2>/dev/null; ip link del veth-gcs 2>/dev/null
            if bash "$KIT/tests/bench_e2e.sh" "$sch" "$PROFILE" "$sc" "$run"; then
                PASS=$((PASS + 1))
            else
                # one retry: a transient failure (e.g. a port still in use after the
                # previous run) must not leave a hole in a balanced design. The retry
                # overwrites the failed run's files; a second failure is recorded.
                echo "### $(date '+%F %T') run failed, retrying once ###"
                wait_for_host_conditions
                ip netns del uav 2>/dev/null; ip link del veth-gcs 2>/dev/null
                sleep 5
                if bash "$KIT/tests/bench_e2e.sh" "$sch" "$PROFILE" "$sc" "$run"; then
                    PASS=$((PASS + 1)); RETRIED_LIST="$RETRIED_LIST ${sc}_${PROFILE}_${sch}_run${run}"
                else
                    FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST ${sc}_${PROFILE}_${sch}_run${run}"
                fi
            fi
        done
    done
done

ip netns del uav 2>/dev/null; ip link del veth-gcs 2>/dev/null
DT=$(($(date +%s) - T0))
echo "=== campaign done in ${DT}s: $PASS passed, $FAIL failed ==="
[ -n "$RETRIED_LIST" ] && echo "passed only on retry:$RETRIED_LIST"
[ -n "$FAILED_LIST" ] && echo "failed:$FAILED_LIST"
exit $([ $FAIL -eq 0 ] && echo 0 || echo 1)
