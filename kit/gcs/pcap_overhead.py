#!/usr/bin/env python3
"""UDP payload sizes in a tcpdump capture of the veth link.

    python3 pcap_overhead.py capture.pcap --uav-ip 10.10.0.2 --port 5762 \
            [--stats dtls_server.stats]

Counts the datagrams of one UDP port in each direction ("down" = from the UAV
address, "up" = to it) and reports their payload sizes. Only datagrams whose
first byte has the DTLS 1.3 unified-header form (bits 001xxxxx, RFC 9147
Section 4) are counted, which leaves out the handshake flights (first byte
0x16 / 0x01) but keeps the small ACK records of the first seconds; they are a
handful of datagrams per run.

With --stats (UAV-side dtls_tunnel counters, sender of the downlink) and
--client-stats (GCS-side counters, sender of the uplink) it also prints the
DTLS overhead per datagram in each direction as a difference of means:

    overhead = mean UDP payload on the wire - mean clear datagram of the sender

The two means are used, and not total bytes over a datagram count, because the
capture starts after the settling period while the tunnel counts from the
handshake: totals taken over different windows would be biased.

RFC 9147 predicts 19 to 22 bytes (1 flag byte + 1 or 2 sequence bytes + 0 or 2
length bytes + 1 inner content type byte + 16-byte tag). Reads classic pcap
files with Ethernet framing (what tcpdump writes on a veth) using only the
standard library.
"""
import argparse
import socket
import statistics
import struct
import sys


def packets(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise ValueError("not a pcap file (too short)")
        if gh[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            end = "<"
        elif gh[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            end = ">"
        else:
            raise ValueError("not a classic pcap file (is it pcapng?)")
        if struct.unpack(end + "I", gh[20:24])[0] != 1:
            raise ValueError("only Ethernet captures (linktype 1) are supported")
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            incl = struct.unpack(end + "I", rh[8:12])[0]
            data = f.read(incl)
            if len(data) < incl:  # capture killed mid-packet
                return
            yield data


def udp_datagrams(path, port):
    """(src_ip, dst_ip, payload_len, first_byte) of every UDP datagram of `port`."""
    for d in packets(path):
        if len(d) < 42 or d[12:14] != b"\x08\x00":
            continue
        ihl = (d[14] & 0x0F) * 4
        if d[23] != 17 or len(d) < 14 + ihl + 8:
            continue
        sport, dport, ulen = struct.unpack("!HHH", d[14 + ihl:14 + ihl + 6])
        if port not in (sport, dport):
            continue
        payload = d[14 + ihl + 8:14 + ihl + ulen]
        yield (socket.inet_ntoa(d[26:30]), socket.inet_ntoa(d[30:34]), ulen - 8,
               payload[0] if payload else -1)


def read_stats(path):
    out = {}
    with open(path) as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                out[k] = v
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("pcap")
    ap.add_argument("--uav-ip", default="10.10.0.2")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--stats", help="UAV-side dtls_tunnel --stats file (downlink sender)")
    ap.add_argument("--client-stats", help="GCS-side dtls_tunnel --stats file (uplink sender)")
    args = ap.parse_args()

    sizes = {"down": [], "up": []}
    for src, _dst, n, first in udp_datagrams(args.pcap, args.port):
        if first >= 0 and (first & 0xE0) == 0x20:  # DTLS 1.3 unified header
            sizes["down" if src == args.uav_ip else "up"].append(n)

    for d, v in sizes.items():
        if not v:
            print(f"{d}_datagrams=0")
            continue
        print(f"{d}_datagrams={len(v)}")
        print(f"{d}_wire_bytes_total={sum(v)}")
        print(f"{d}_wire_bytes_mean={statistics.fmean(v):.2f}")
        print(f"{d}_wire_bytes_median={statistics.median(v)}")
        print(f"{d}_wire_bytes_min={min(v)}")
        print(f"{d}_wire_bytes_max={max(v)}")

    for direction, path in (("down", args.stats), ("up", args.client_stats)):
        if not path or not sizes[direction]:
            continue
        st = read_stats(path)
        clear_dgrams = int(st["plain_to_dtls_dgrams"])
        if clear_dgrams:
            clear_mean = int(st["plain_to_dtls_bytes"]) / clear_dgrams
            wire_mean = statistics.fmean(sizes[direction])
            print(f"{direction}_clear_bytes_mean={clear_mean:.2f}")
            print(f"{direction}_dtls_overhead_bytes_per_datagram={wire_mean - clear_mean:.2f}")
            print(f"{direction}_datagrams_wire_vs_tunnel={len(sizes[direction])}/{clear_dgrams}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as e:
        sys.exit(f"pcap_overhead: {e}")
