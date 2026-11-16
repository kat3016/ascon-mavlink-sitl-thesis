#!/bin/bash
# Quick standalone check of the DTLS 1.3 tunnel (about 5 seconds, no SITL, no
# campaign data written): run it ONCE after building and BEFORE any campaign.
#
#   sudo bash bench/dtls_selfcheck.sh
#
# It sends a few UDP datagrams through a server/client tunnel pair over the
# loopback interface and checks that they arrive intact in both directions,
# that the session is DTLSv1.3 with TLS_AES_128_GCM_SHA256, and that the
# client rejects a server whose certificate does not match the expected name.
set -u
KIT=$(cd -P "$(dirname "$0")/.." && pwd -P)
DT=$KIT/build/dtls_tunnel
T=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$T"' EXIT
[ -x "$DT" ] || { echo "missing $DT: run  bash bench/build_wolfssl.sh"; exit 2; }
[ -f "$KIT/bench/uav.pem" ] || { echo "missing uav.pem: run  sh bench/gen_tls_cert.sh"; exit 2; }
PY=${PY:-$HOME/venv-ardupilot/bin/python3}; [ -x "$PY" ] || PY=python3

# server: DTLS on 127.0.0.1:25762, clear side on :25771 (stands in for the SITL's target)
"$DT" --role server --dtls-addr 127.0.0.1:25762 --plain-bind 127.0.0.1:25771 \
      --cert "$KIT/bench/uav.pem" --key "$KIT/bench/uav.key" --stats "$T/server.stats" 2> "$T/server.log" &
SRV=$!
sleep 0.5
# client: clear side on :25772, decrypted datagrams go to :25773 (stands in for the proxy)
"$DT" --role client --dtls-addr 127.0.0.1:25762 --plain-bind 127.0.0.1:25772 \
      --plain-peer 127.0.0.1:25773 --ca "$KIT/bench/uav.pem" --name uav.mavcrypt.local \
      --stats "$T/client.stats" 2> "$T/client.log" &
CLI=$!

$PY - <<'PYEOF'
import socket, sys, time
sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sink.bind(("127.0.0.1", 25773)); sink.settimeout(5)
src = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); src.bind(("127.0.0.1", 0))
# downlink: a datagram "from the SITL" into the server's clear side
deadline = time.time() + 10
msg = bytes(range(60))
got = None
while time.time() < deadline and got is None:       # keep sending until the handshake is up
    src.sendto(msg, ("127.0.0.1", 25771))
    sink.settimeout(0.5)
    try:
        got = sink.recvfrom(2048)
    except socket.timeout:
        pass
if got is None or got[0] != msg:
    print("FAIL: downlink datagram did not arrive intact"); sys.exit(1)
print("ok: downlink datagram arrived intact (%d bytes)" % len(got[0]))
# uplink: a datagram "from the proxy" back through the client's clear side;
# the server forwards it to the last source it saw on its clear side (our src socket)
back_msg = b"uplink" * 10
src.settimeout(3)
sink.sendto(back_msg, got[1])                        # got[1] = the client's clear-side address
try:
    data, _ = src.recvfrom(2048)
except socket.timeout:
    print("FAIL: uplink datagram did not arrive"); sys.exit(1)
if data != back_msg:
    print("FAIL: uplink datagram corrupted"); sys.exit(1)
print("ok: uplink datagram arrived intact (%d bytes)" % len(data))
PYEOF
RC=$?
grep -h handshake_ms "$T"/server.log "$T"/client.log | sed 's/^/  /'
grep -q "version=DTLSv1.3 suite=TLS_AES_128_GCM_SHA256" "$T/client.log" \
    && echo "ok: DTLSv1.3 / TLS_AES_128_GCM_SHA256" || { echo "FAIL: wrong version or suite"; RC=1; }
kill "$CLI" "$SRV" 2>/dev/null; wait 2>/dev/null

# negative check: wrong expected host name must make the client refuse
"$DT" --role server --dtls-addr 127.0.0.1:25764 --plain-bind 127.0.0.1:25774 \
      --cert "$KIT/bench/uav.pem" --key "$KIT/bench/uav.key" 2> "$T/server2.log" &
sleep 0.5
if timeout 40 "$DT" --role client --dtls-addr 127.0.0.1:25764 --plain-bind 127.0.0.1:25775 \
      --plain-peer 127.0.0.1:25776 --ca "$KIT/bench/uav.pem" --name wrong.example.org 2> "$T/client2.log"; then
    echo "FAIL: client accepted a certificate for the wrong host name"; RC=1
else
    echo "ok: client refused a certificate that does not match the expected name"
fi
[ $RC -eq 0 ] && echo "DTLS SELF-CHECK PASSED" || echo "DTLS SELF-CHECK FAILED (logs in $T are removed on exit; rerun with bash -x)"
exit $RC
