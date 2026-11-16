#!/bin/sh
# Self-signed ECDSA P-256 certificate for the UAV-side DTLS endpoint
# (dtls_tunnel --role server). The GCS side pins it as its only trust anchor
# and checks the host name, so no CA is involved. Run once; kit/bench/uav.pem
# and uav.key are gitignored.
set -e
cd "$(dirname "$0")"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
    -keyout uav.key -out uav.pem -subj "/CN=uav.mavcrypt.local" \
    -addext "subjectAltName=DNS:uav.mavcrypt.local" 2>/dev/null
chmod 600 uav.key
echo "[ok] kit/bench/uav.pem + uav.key (ECDSA P-256, SAN uav.mavcrypt.local)"
