#!/bin/sh
# End-to-end run against SITL: ArduCopter binary -> UDP -> secure_proxy -> tools.
#
#   sh tests/sitl_e2e.sh <arducopter binary> <plain|ascon> <scenario> <run> [tamper_every]
#
# Scenarios (same as the workload table of the thesis):
#   S0 smoke   1 Hz,   50 probes at 5/s,   60 s     (+ parameter download check)
#   S1 replica 1 Hz, 1000 probes at 5/s,  300 s
#   S2 high   10 Hz, 1000 probes at 5/s,  300 s
#   S3 stress 50 Hz, 1000 probes at 5/s,  120 s
#   S4 cmds    1 Hz, 2000 probes at 20/s, 120 s
#   T0 tamper  1 Hz,  300 probes at 5/s,   60 s     (use with tamper_every, e.g. 10)
# Output: $OUT (default <repo>/data/sitl)/<scenario>_<scheme>_run<NN>_{latency,throughput,proxy,ram}.csv
# Environment: ARDUPILOT (default ~/ardupilot), OUT, SETTLE (s after first
# telemetry before measuring, default 20), KEEP_TMP=1 to keep SITL logs.

set -u
[ $# -ge 4 ] || { sed -n '2,17p' "$0"; exit 2; }
KIT=$(cd -P "$(dirname "$0")/.." && pwd -P)
BIN=$(readlink -f "$1")
SCHEME=$2
SC=$3
RUN=$4
TAMPER=${5:-0}
AP=${ARDUPILOT:-$HOME/ardupilot}
OUT=${OUT:-$KIT/../data/sitl}

case $SC in
    S0) HZ=1;  N=50;   RATE=5;  DUR=60 ;;
    S1) HZ=1;  N=1000; RATE=5;  DUR=300 ;;
    S2) HZ=10; N=1000; RATE=5;  DUR=300 ;;
    S3) HZ=50; N=1000; RATE=5;  DUR=120 ;;
    S4) HZ=1;  N=2000; RATE=20; DUR=120 ;;
    T0) HZ=1;  N=300;  RATE=5;  DUR=60 ;;
    *) echo "unknown scenario $SC"; exit 2 ;;
esac
[ -x "$BIN" ] || { echo "binary not found: $BIN"; exit 2; }
mkdir -p "$OUT"
OUT=$(cd -P "$OUT" && pwd -P) || exit 2
P="$OUT/${SC}_${SCHEME}_run${RUN}"
TMP=$(mktemp -d)
HOST=$(python3 -c "import sys; sys.path.insert(0, '$KIT/gcs'); import mavcrypt; print(mavcrypt.local_host())")
echo "== $SC $SCHEME run$RUN  ($(basename "$BIN"), md5 $(md5sum < "$BIN" | cut -c1-12), tamper=$TAMPER, host $HOST)"

cleanup() {
    [ -n "${PROXY_PID:-}" ] && kill -INT "$PROXY_PID" 2>/dev/null
    [ -n "${SITL_PID:-}" ] && kill "$SITL_PID" 2>/dev/null
    wait 2>/dev/null
    [ "${KEEP_TMP:-0}" = 1 ] && echo "   logs kept in $TMP" || rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

# 1. SITL with SERIAL0 sending UDP to the proxy, like a UDP radio link
(cd "$TMP" && exec "$BIN" -w --model + --speedup 1 -I0 \
    --defaults "$AP/Tools/autotest/default_params/copter.parm" \
    --home=-35.363261,149.165230,584,353 \
    --serial0 "udpclient:$HOST:14550" > sitl.log 2>&1) &
SITL_PID=$!

# 2. proxy
TARG=""
[ "$TAMPER" -gt 0 ] && TARG="--tamper-every $TAMPER"
python3 "$KIT/gcs/secure_proxy.py" --mode "$SCHEME" --key "$KIT/keys/ascon.key" \
    --log "${P}_proxy.csv" $TARG > "$TMP/proxy.log" 2>&1 &
PROXY_PID=$!

i=0
until grep -q "drone at" "$TMP/proxy.log" 2>/dev/null; do
    i=$((i + 1))
    if [ $i -gt 60 ]; then
        echo "   no telemetry from SITL after 60 s"; tail -5 "$TMP/sitl.log"; exit 1
    fi
    sleep 1
done
echo "   $(grep -m1 "drone at" "$TMP/proxy.log")"
# let the vehicle finish booting (EKF, sensors) before measuring, as on a real vehicle
SETTLE=${SETTLE:-20}
sleep "$SETTLE"

# 3. instruments in parallel
sh "$KIT/drone/ram_monitor.sh" "${P}_ram.csv" "$DUR" "$(basename "$BIN")" 2>/dev/null &
RAM_PID=$!
python3 "$KIT/gcs/stream_monitor.py" --hz "$HZ" --duration "$DUR" --out "${P}_throughput.csv" &
THR_PID=$!
sleep 2
python3 "$KIT/gcs/latency_timesync.py" --n "$N" --rate "$RATE" --out "${P}_latency.csv"
wait $THR_PID
wait $RAM_PID 2>/dev/null

PARAM_OK=0
if [ "$SC" = S0 ]; then
    python3 "$KIT/gcs/param_fetch.py" && PARAM_OK=1
fi

kill -INT "$PROXY_PID"; wait "$PROXY_PID" 2>/dev/null; PROXY_PID=""
tail -n 1 "$TMP/proxy.log" | sed 's/^/   /'

# 4. validation
python3 "$KIT/tests/check_run.py" "$OUT" "$SC" "$SCHEME" "$RUN" --tamper "$TAMPER"
RC=$?
gzip -f "${P}_proxy.csv"   # per-datagram log: ~10x smaller; summarize.py reads .csv.gz
if [ "$SC" = S0 ] && [ $PARAM_OK -ne 1 ]; then
    echo "   [FAIL] parameter download through the proxy"; RC=1
fi
exit $RC
