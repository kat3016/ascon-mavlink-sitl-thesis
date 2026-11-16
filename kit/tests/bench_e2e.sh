#!/bin/bash
# End-to-end run against SITL, inside the netns/netem bench, with core pinning.
# Run as root (netns exec needs CAP_SYS_ADMIN).
#
#   bash tests/bench_e2e.sh <scheme> <profile> <scenario> <run> [tamper_every]
#
#   scheme:   plain | ascon | aesgcm | chacha | dtls | aesgcm-hw | chacha-hw
#             (-hw = same binary and key as aesgcm/chacha but with OpenSSL's
#             hardware acceleration left ON; every other scheme runs with it
#             masked, see OPENSSL_ia32cap below)
#   profile:  N0 | N1 | N2 | N3   (kit/bench/netbench.sh)
#   scenario: S0 | S1 | S2 | S3 | S4 | T0   (same definitions as sitl_e2e.sh)
#
# Output: $OUT (default <repo>/data/sitl)/<scenario>_<profile>_<scheme>_run<NN>_{latency,throughput,proxy,ram}.csv
# For dtls also <...>_ram_tunnel.csv (RSS/CPU of the UAV-side tunnel, the DTLS
# counterpart of the in-firmware cipher) and <...>_dtls.txt (handshake time,
# negotiated version/suite, tunnel counters, wire bytes per datagram).
#
# dtls runs the *unencrypted* arducopter_plain_sitl binary, exactly like the
# plain baseline over the same UDP transport; protection is added around it by
# a DTLS 1.3 tunnel pair (kit/bench/dtls_tunnel.c, wolfSSL):
#   SITL --udp--> 127.0.0.1:14551 [tunnel server, uav ns] ==DTLS 1.3==>
#   [tunnel client, root ns] --udp--> secure_proxy --mode plain
# so dtls - plain isolates the cost of DTLS 1.3 with no change of transport.
# Build it once with: bash bench/build_wolfssl.sh && sh bench/gen_tls_cert.sh
#
# Core pinning: tools 1, SITL 2, proxy 3, UAV-side tunnel 4, GCS-side tunnel 5.
#
# Environment: ARDUPILOT (default ~/ardupilot), KIT_BUILD (default kit/build),
# OUT, SETTLE (s after first telemetry before measuring, default 20),
# KEEP_TMP=1 to keep SITL/proxy/tunnel logs.
set -u
[ $# -ge 4 ] || { sed -n '2,32p' "$0"; exit 2; }
KIT=$(cd -P "$(dirname "$0")/.." && pwd -P)
SCHEME=$1
PROFILE=$2
SC=$3
RUN=$4
TAMPER=${5:-0}
AP=${ARDUPILOT:-$HOME/ardupilot}
BUILD=${KIT_BUILD:-$KIT/build}
OUT=${OUT:-$KIT/../data/sitl}
# this script runs as root (netns exec needs CAP_SYS_ADMIN), but pymavlink /
# scipy / the cryptography package may live in a virtual environment: set PY
PY=${PY:-$HOME/venv-ardupilot/bin/python3}
[ -x "$PY" ] || PY=python3
UAV_IP=10.10.0.2
GCS_IP=10.10.0.1
DTLS_PORT=5762
CERT_NAME=uav.mavcrypt.local

case $SC in
    S0) HZ=1;  N=50;   RATE=5;  DUR=60 ;;
    S1) HZ=1;  N=1000; RATE=5;  DUR=300 ;;
    S2) HZ=10; N=1000; RATE=5;  DUR=300 ;;
    S3) HZ=50; N=1000; RATE=5;  DUR=120 ;;
    S4) HZ=1;  N=2000; RATE=20; DUR=120 ;;
    T0) HZ=1;  N=300;  RATE=5;  DUR=60 ;;
    *) echo "unknown scenario $SC"; exit 2 ;;
esac
case $PROFILE in N0|N1|N2|N3) ;; *) echo "unknown profile $PROFILE"; exit 2 ;; esac

DTLS=0
HW=0
case $SCHEME in
    plain)               BIN=$BUILD/arducopter_plain_sitl; PROXY_MODE=plain ;;
    ascon|aesgcm|chacha) BIN=$BUILD/arducopter_${SCHEME}_sitl; PROXY_MODE=$SCHEME ;;
    aesgcm-hw|chacha-hw) BASE=${SCHEME%-hw}; BIN=$BUILD/arducopter_${BASE}_sitl; PROXY_MODE=$BASE; HW=1 ;;
    dtls)                BIN=$BUILD/arducopter_plain_sitl; PROXY_MODE=plain; DTLS=1 ;;
    *) echo "unknown scheme $SCHEME"; exit 2 ;;
esac
# Scalar OpenSSL for every treatment except the explicit *-hw ones: the mask
# clears AES-NI, PCLMULQDQ, SSSE3 and AVX so the host does not favour AES-GCM
# over the Cortex-A9 it stands in for. It is exported here, not left to the
# caller, so it reaches SITL, the proxy and the tools of every run (children
# inherit it through taskset and ip netns exec). dtls uses wolfSSL, which has
# no such acceleration compiled in.
if [ $HW = 1 ]; then
    unset OPENSSL_ia32cap
else
    export OPENSSL_ia32cap="~0x1200020200000000:0"
fi
echo "   openssl acceleration: $([ $HW = 1 ] && echo 'ENABLED (hw treatment)' || echo "masked, OPENSSL_ia32cap=$OPENSSL_ia32cap")"
[ -x "$BIN" ] || { echo "binary not found: $BIN (did you run drone/build_all.sh sitl?)"; exit 2; }
if [ $DTLS = 1 ]; then
    [ -x "$BUILD/dtls_tunnel" ] || { echo "missing $BUILD/dtls_tunnel: run  bash bench/build_wolfssl.sh"; exit 2; }
    [ -f "$KIT/bench/uav.pem" ] || { echo "missing kit/bench/uav.pem: run  sh bench/gen_tls_cert.sh"; exit 2; }
    [ "$TAMPER" -gt 0 ] && { echo "tamper_every does not apply to dtls (the proxy sees clear frames; DTLS rejects altered records inside the tunnel)"; exit 2; }
fi
mkdir -p "$OUT"
OUT=$(cd -P "$OUT" && pwd -P) || exit 2
P="$OUT/${SC}_${PROFILE}_${SCHEME}_run${RUN}"
TMP=$(mktemp -d)
echo "== $SC $PROFILE $SCHEME run$RUN ($(basename "$BIN"), md5 $(md5sum < "$BIN" | cut -c1-12), tamper=$TAMPER)"

PIDS=""
cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    ip netns exec uav tc qdisc del dev veth-uav root 2>/dev/null
    tc qdisc del dev veth-gcs root 2>/dev/null
    [ "${KEEP_TMP:-0}" = 1 ] && echo "   logs kept in $TMP" || rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

# 1. network bench: namespaces + veth (idempotent) + the requested profile
if ! ip netns list 2>/dev/null | grep -q '^uav'; then
    sh "$KIT/bench/netbench.sh" up
fi
sh "$KIT/bench/netbench.sh" "$PROFILE"

# 2. UAV-side DTLS endpoint (dtls only), then SITL inside the uav namespace
#    pinned to core 2. With dtls the firmware talks clear UDP to the local
#    tunnel instead of to the GCS.
if [ $DTLS = 1 ]; then
    HOST=$($PY -c "import sys; sys.path.insert(0, '$KIT/gcs'); import mavcrypt; print(mavcrypt.local_host())")
    ip netns exec uav taskset -c 4 "$BUILD/dtls_tunnel" --role server \
        --dtls-addr "$UAV_IP:$DTLS_PORT" --plain-bind 127.0.0.1:14551 \
        --cert "$KIT/bench/uav.pem" --key "$KIT/bench/uav.key" \
        --stats "$TMP/dtls_server.stats" > "$TMP/dtls_server.log" 2>&1 &
    UAV_TUN_PID=$!; PIDS="$PIDS $UAV_TUN_PID"
    SERIAL0="udpclient:127.0.0.1:14551"
else
    SERIAL0="udpclient:$GCS_IP:14550"
fi
# SITL is started in SITL_CWD, prepared by bench/sitl_nostorage.sh: default
# parameters in memory and no persistent parameter storage, the simulator state
# of every run of the thesis (checked by bench/check_sitl_state.py).
SITL_DIR=${SITL_CWD:-$PWD}
(cd "$SITL_DIR" && exec ip netns exec uav taskset -c 2 "$BIN" -w --model + --speedup 1 -I0 \
    --defaults "$AP/Tools/autotest/default_params/copter.parm" \
    --home=-35.363261,149.165230,584,353 \
    --serial0 "$SERIAL0") > "$TMP/sitl.log" 2>&1 &
SITL_PID=$!; PIDS="$PIDS $SITL_PID"

# 3. proxy, pinned to core 3. --mode only selects the key file: the shared
#    library (algorithm, key/nonce sizes) must be picked explicitly, since
#    mavcrypt.py defaults to build/libmavcrypt.so (built for ascon).
case $PROXY_MODE in
    aesgcm|chacha) export MAVCRYPT_LIB="$BUILD/libmavcrypt_${PROXY_MODE}.so" ;;
    *) unset MAVCRYPT_LIB ;;
esac
[ -n "${MAVCRYPT_LIB:-}" ] && [ ! -f "$MAVCRYPT_LIB" ] && {
    echo "   missing $MAVCRYPT_LIB (build it: see kit/tests/build_and_test.sh step for the OpenSSL backend, or kit/README.md)"; exit 2; }
TARG=""
[ "$TAMPER" -gt 0 ] && TARG="--tamper-every $TAMPER"
taskset -c 3 $PY "$KIT/gcs/secure_proxy.py" --mode "$PROXY_MODE" \
    --log "${P}_proxy.csv" $TARG > "$TMP/proxy.log" 2>&1 &
PROXY_PID=$!; PIDS="$PIDS $PROXY_PID"

# GCS-side DTLS endpoint: decrypted datagrams go to the proxy's "drone" port,
# on the same local address the proxy/tools use (mavcrypt.local_host)
if [ $DTLS = 1 ]; then
    sleep 1  # the proxy must be bound before the first decrypted datagram
    taskset -c 5 "$BUILD/dtls_tunnel" --role client \
        --dtls-addr "$UAV_IP:$DTLS_PORT" --plain-bind "$HOST:0" --plain-peer "$HOST:14550" \
        --ca "$KIT/bench/uav.pem" --name "$CERT_NAME" \
        --stats "$TMP/dtls_client.stats" > "$TMP/dtls_client.log" 2>&1 &
    GCS_TUN_PID=$!; PIDS="$PIDS $GCS_TUN_PID"
fi

i=0
until grep -qE "^drone at" "$TMP/proxy.log" 2>/dev/null; do
    i=$((i + 1))
    if [ $i -gt 60 ] || { [ $DTLS = 1 ] && ! kill -0 "$GCS_TUN_PID" 2>/dev/null; }; then
        echo "   no telemetry after $i s"; tail -n 5 "$TMP/sitl.log" "$TMP/proxy.log"
        [ $DTLS = 1 ] && tail -n 8 "$TMP"/dtls_*.log
        exit 1
    fi
    sleep 1
done
echo "   $(grep -E -m 1 "^drone at" "$TMP/proxy.log")"
[ $DTLS = 1 ] && grep -h "handshake_ms" "$TMP"/dtls_*.log | sed 's/^/   /'
SETTLE=${SETTLE:-20}
sleep "$SETTLE"

# 4. instruments in parallel, tools pinned to core 1; capture on the real
#    interface the protected traffic crosses (veth-gcs), not "any"
tcpdump -i veth-gcs -w "${P}_capture.pcap" -U > "$TMP/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!; PIDS="$PIDS $TCPDUMP_PID"
sh "$KIT/drone/ram_monitor.sh" "${P}_ram.csv" "$DUR" "$(basename "$BIN")" 2>/dev/null &
RAM_PID=$!; PIDS="$PIDS $RAM_PID"
if [ $DTLS = 1 ]; then
    sh "$KIT/drone/ram_monitor.sh" "${P}_ram_tunnel.csv" "$DUR" dtls_tunnel "$UAV_TUN_PID" 2>/dev/null &
    RAMT_PID=$!; PIDS="$PIDS $RAMT_PID"
fi
taskset -c 1 $PY "$KIT/gcs/stream_monitor.py" --hz "$HZ" --duration "$DUR" --out "${P}_throughput.csv" &
THR_PID=$!; PIDS="$PIDS $THR_PID"
sleep 2
taskset -c 1 $PY "$KIT/gcs/latency_timesync.py" --n "$N" --rate "$RATE" --out "${P}_latency.csv"
wait $THR_PID
wait $RAM_PID 2>/dev/null
[ $DTLS = 1 ] && wait $RAMT_PID 2>/dev/null

PARAM_OK=0
if [ "$SC" = S0 ]; then
    taskset -c 1 $PY "$KIT/gcs/param_fetch.py" && PARAM_OK=1
fi

kill -INT "$PROXY_PID"; wait "$PROXY_PID" 2>/dev/null
tail -n 1 "$TMP/proxy.log" | sed 's/^/   /'

if [ $DTLS = 1 ]; then
    # stop the tunnels (they write their counters on SIGTERM) and the capture,
    # then keep handshake time, counters and wire bytes per datagram
    kill "$GCS_TUN_PID" "$UAV_TUN_PID" 2>/dev/null; wait "$GCS_TUN_PID" "$UAV_TUN_PID" 2>/dev/null
    kill "$TCPDUMP_PID" 2>/dev/null; wait "$TCPDUMP_PID" 2>/dev/null
    {
        echo "# GCS-side tunnel (client)"; cat "$TMP/dtls_client.stats" 2>/dev/null
        echo "# UAV-side tunnel (server)"; cat "$TMP/dtls_server.stats" 2>/dev/null
        echo "# wire bytes per datagram on veth-gcs"
        $PY "$KIT/gcs/pcap_overhead.py" "${P}_capture.pcap" --uav-ip "$UAV_IP" --port "$DTLS_PORT" \
            --stats "$TMP/dtls_server.stats" --client-stats "$TMP/dtls_client.stats"
        echo "# tunnel log lines other than the handshake report (errors, alerts)"
        grep -h -v "handshake_ms\|waiting on" "$TMP/dtls_client.log" "$TMP/dtls_server.log" 2>/dev/null
    } > "${P}_dtls.txt" 2>&1
    sed 's/^/   /' "${P}_dtls.txt" | tail -n 8
fi

# 5. validation (reuses check_run.py: auth_fail/replay/loss/tamper thresholds)
$PY "$KIT/tests/check_run.py" "$OUT" "${SC}_${PROFILE}" "$SCHEME" "$RUN" --tamper "$TAMPER"
RC=$?
gzip -f "${P}_proxy.csv"
if [ "$SC" = S0 ] && [ $PARAM_OK -ne 1 ]; then
    echo "   [FAIL] parameter download through the proxy"; RC=1
fi
exit $RC
