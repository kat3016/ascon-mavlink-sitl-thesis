#!/bin/bash
# Cost of one seal / one open on the host, per algorithm, OpenSSL configuration
# and payload size (36 B: typical telemetry; 255 B: MAVLink maximum). Each
# figure is the median over 5 repetitions of the tool's own median of 20000
# operations. Run it on an idle host (after the campaign), pinned to one core.
#
#   bash bench/host_microbench.sh > data/microbench_host.csv
set -u
KIT=$(cd -P "$(dirname "$0")/.." && pwd -P)
CORE=${CORE:-15}
echo "alg,config,payload,op,median_ns"
for spec in "ascon:$KIT/build/mavcrypt_tool:scalar (no OpenSSL)" \
            "aesgcm:$KIT/build/mavcrypt_tool_aesgcm:scalar mask" \
            "aesgcm:$KIT/build/mavcrypt_tool_aesgcm:accelerated" \
            "chacha:$KIT/build/mavcrypt_tool_chacha:scalar mask" \
            "chacha:$KIT/build/mavcrypt_tool_chacha:accelerated"; do
    IFS=: read -r alg tool cfg <<< "$spec"
    for payload in 36 255; do
        for op in seal open; do
            vals=()
            for rep in 1 2 3 4 5; do
                if [ "$cfg" = "accelerated" ]; then
                    v=$(env -u OPENSSL_ia32cap taskset -c "$CORE" "$tool" bench "$payload" 20000 "$op")
                else
                    v=$(OPENSSL_ia32cap="~0x1200020200000000:0" taskset -c "$CORE" "$tool" bench "$payload" 20000 "$op")
                fi
                vals+=("$(echo "$v" | grep -o "${op}_ns_median=[0-9]*" | cut -d= -f2)")
            done
            med=$(printf '%s\n' "${vals[@]}" | sort -n | sed -n 3p)
            echo "$alg,$cfg,$payload,$op,$med"
        done
    done
done
