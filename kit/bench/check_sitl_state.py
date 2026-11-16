#!/usr/bin/env python3
"""Check that a plain-mode capture shows the declared simulator state.

Every run of the thesis starts SITL with its default parameters in memory and
without persistent parameter storage (bench/sitl_nostorage.sh). In that state
ArduPilot reports it with STATUSTEXT "PreArm: Param storage failed" (about every
31 s) and sends no TERRAIN_REQUEST (msgid 133), so the telemetry workload is
the declared one. The S0 gate runs this check before any measured run:

    python3 check_sitl_state.py <plain capture.pcap>   -> exit 0 if the state is the declared one

Standard library only (runs with the system python3 as root).
"""
import struct
import sys

UAV = '10.10.0.2'


def frames(path):
    with open(path, 'rb') as f:
        gh = f.read(24)
        magic = struct.unpack('<I', gh[:4])[0]
        e = '<' if magic in (0xa1b2c3d4, 0xa1b23c4d) else '>'
        linktype = struct.unpack(e + 'I', gh[20:24])[0]
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            incl = struct.unpack(e + 'IIII', h)[2]
            pkt = f.read(incl)
            off = 14 if linktype == 1 else (16 if linktype == 113 else 0)
            ip = pkt[off:]
            if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 17:
                continue
            ihl = (ip[0] & 15) * 4
            yield '.'.join(map(str, ip[12:16])), ip[ihl + 8:]


def main(path):
    storage_failed = 0
    terrain_req = 0
    for src, p in frames(path):
        if src != UAV or len(p) < 10 or p[0] != 0xFD:
            continue
        msgid = p[7] | (p[8] << 8) | (p[9] << 16)
        if msgid == 133:
            terrain_req += 1
        elif msgid == 253 and b'Param storage failed' in p:
            storage_failed += 1
    ok = storage_failed > 0 and terrain_req == 0
    print(f'{path}: Param-storage-failed={storage_failed} TERRAIN_REQUEST={terrain_req} '
          f'-> {"declared state" if ok else "DIFFERS from the declared state"}')
    return 0 if ok else 1


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
