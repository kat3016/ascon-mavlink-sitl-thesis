#!/usr/bin/env python3
"""Ground-station proxy between the drone link and the GCS tools.

    drone (UDP 14550)  <-->  secure_proxy  <-->  <local>:14560  <-->  tools
                              plain | ascon        (MAVProxy, pymavlink scripts)

<local> is 127.0.0.1, or the Linux-only address of dev lo when WSL2 mirrored
networking routes 127.0.0.1 through Windows (see mavcrypt.local_host); the
proxy prints the address to use, e.g. mavproxy.py --master udpout:<local>:14560

--mode plain   forwards bytes unchanged (baseline: same proxy, no crypto)
--mode ascon   downlink: verify + decrypt (Ascon-AEAD128); uplink: encrypt
--mode aesgcm  same, with AES-128-GCM (needs a libmavcrypt.so built with
               AP_MAVCRYPT_ALG=2, e.g. MAVCRYPT_LIB=build/libmavcrypt_aesgcm.so)
--mode chacha  same, with ChaCha20-Poly1305 (AP_MAVCRYPT_ALG=3, 32-byte key)

--log FILE writes one CSV row per datagram:
    t_ns,dir,wire_bytes,frames,frame_bytes,plain_bytes,crypto_ns,auth_fail,replay
wire_bytes = UDP payload on the air (may hold partial frames);
frame_bytes = on-air size of the complete frames recovered from it;
plain_bytes = clear MAVLink bytes of those frames;
crypto_ns = time spent in decrypt (down) or encrypt (up) for that datagram.

--tamper-every N flips one bit in every Nth uplink frame after protection
(validation: the drone must drop those frames).

For the dtls treatment the proxy runs --mode plain: the DTLS 1.3 tunnel
(kit/bench/dtls_tunnel.c) sits between the firmware and this proxy and hands
it clear UDP datagrams exactly as the plain baseline would receive them.
"""
import argparse
import os
import selectors
import signal
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mavcrypt  # noqa: E402

CLIENT_TIMEOUT_S = 30


def parse_addr(s):
    host, port = s.rsplit(":", 1)
    return host, int(port)


def main():
    ap = argparse.ArgumentParser(description="MAVLink plain/Ascon proxy")
    ap.add_argument("--mode", choices=["plain", "ascon", "aesgcm", "chacha"], required=True)
    ap.add_argument("--key", default=None,
                    help="default: keys/<mode>.key (ignored for --mode plain)")
    ap.add_argument("--drone-bind", default="0.0.0.0:14550",
                    help="where the drone's telemetry arrives (default 0.0.0.0:14550)")
    ap.add_argument("--drone-addr", default=None,
                    help="fixed drone address ip:port (default: learnt from the first datagram)")
    ap.add_argument("--gcs-bind", default=f"{mavcrypt.local_host()}:14560",
                    help="where the GCS tools connect (default <local host>:14560, "
                         "see mavcrypt.local_host)")
    ap.add_argument("--log", default=None, help="per-datagram CSV log")
    ap.add_argument("--tamper-every", type=int, default=0)
    ap.add_argument("--stats-every", type=float, default=5.0)
    ap.add_argument("--debug-seq", action="store_true",
                    help="print MAVLink sequence jumps in the downlink as delivered to the tools")
    args = ap.parse_args()
    dbg_seq = [None]

    ascon = args.mode != "plain"  # name kept for minimal diff; covers ascon/aesgcm/chacha
    if ascon:
        key_path = args.key or os.path.join(mavcrypt.KIT, "keys", f"{args.mode}.key")
        key = mavcrypt.load_key(key_path)
        # mavcrypt.lib() defaults to build/libmavcrypt.so (built for ascon);
        # --mode only picks the key file, so a mismatched MAVCRYPT_LIB would
        # silently load the wrong algorithm and produce auth_fail on every
        # frame instead of a clear error. Catch it here.
        want_alg = {"ascon": 1, "aesgcm": 2, "chacha": 3}[args.mode]
        got_alg = mavcrypt.lib().mc_alg_id()
        if got_alg != want_alg:
            sys.exit(f"--mode {args.mode} needs a libmavcrypt.so built with AP_MAVCRYPT_ALG={want_alg}, "
                      f"but {mavcrypt.LIB_PATH} was built with AP_MAVCRYPT_ALG={got_alg}. "
                      f"Set MAVCRYPT_LIB to the matching build/libmavcrypt_{args.mode}.so.")
        opener = mavcrypt.Opener(key, mavcrypt.ROLE_GCS)
        sealer = mavcrypt.Sealer(key, mavcrypt.ROLE_GCS)

    drone_addr = parse_addr(args.drone_addr) if args.drone_addr else None
    drone_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    drone_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    drone_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    drone_sock.bind(parse_addr(args.drone_bind))
    gcs_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    gcs_sock.bind(parse_addr(args.gcs_bind))

    sel = selectors.DefaultSelector()
    sel.register(drone_sock, selectors.EVENT_READ, "drone")
    sel.register(gcs_sock, selectors.EVENT_READ, "gcs")
    clients = {}  # addr -> (last_seen, FrameSplitter)
    down_split = mavcrypt.FrameSplitter()  # plain mode frame counting
    log = None
    if args.log:
        os.makedirs(os.path.dirname(os.path.abspath(args.log)), exist_ok=True)
        log = open(args.log, "w", buffering=1 << 16)
        log.write("t_ns,dir,wire_bytes,frames,frame_bytes,plain_bytes,crypto_ns,auth_fail,replay\n")

    st = {"down_dgrams": 0, "down_frames": 0, "up_frames": 0, "up_dropped": 0, "tampered": 0}
    up_count = 0
    t_start = time.monotonic_ns()
    next_stats = time.monotonic() + args.stats_every
    running = [True]

    def stop(*_):
        running[0] = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    def counters():
        if ascon:
            s = opener.stats
            return s["auth_fail"], s["replay"], s["bad_dir"]
        return 0, 0, 0

    def report(final=False):
        af, rp, bd = counters()
        print(f"{'FINAL ' if final else ''}mode={args.mode} drone at {drone_addr} "
              f"down_frames={st['down_frames']} up_frames={st['up_frames']} "
              f"auth_fail={af} replay={rp} bad_dir={bd} tampered={st['tampered']} "
              f"clients={len(clients)}", flush=True)

    print(f"secure_proxy mode={args.mode} drone side {args.drone_bind}, "
          f"GCS side {args.gcs_bind}", flush=True)
    while running[0]:
        for skey, _ in sel.select(timeout=0.2):
            sock = skey.fileobj
            try:
                data, addr = sock.recvfrom(65535)
            except OSError:
                continue
            now = time.monotonic_ns() - t_start
            if skey.data == "drone":
                if drone_addr != addr and not args.drone_addr:
                    drone_addr = addr
                    print(f"drone at {addr}", flush=True)
                st["down_dgrams"] += 1
                if ascon:
                    t0 = time.perf_counter_ns()
                    frames, plain = opener.feed(data)
                    dt = time.perf_counter_ns() - t0
                    plain_len = len(plain)
                    frame_bytes = plain_len + mavcrypt.OVERHEAD * frames
                else:
                    fr = down_split.feed(data)  # only to count frames
                    frames, plain, dt = len(fr), data, 0
                    plain_len = frame_bytes = sum(len(f) for f in fr)
                st["down_frames"] += frames
                if args.debug_seq and plain:
                    for f in mavcrypt.FrameSplitter().feed(plain):
                        seq = f[4] if f[0] == 0xFD else f[2]
                        if dbg_seq[0] is not None and seq != (dbg_seq[0] + 1) % 256:
                            print(f"debug-seq: {dbg_seq[0]} -> {seq} in datagram of "
                                  f"{len(data)} B, {frames} frames", flush=True)
                        dbg_seq[0] = seq
                if plain:
                    for c in list(clients):
                        gcs_sock.sendto(plain, c)
                if log:
                    af, rp, _ = counters()
                    log.write(f"{now},down,{len(data)},{frames},{frame_bytes},{plain_len},"
                              f"{dt},{af},{rp}\n")
            else:
                if addr not in clients:
                    print(f"GCS tool connected from {addr}", flush=True)
                    clients[addr] = [0, mavcrypt.FrameSplitter()]
                clients[addr][0] = time.monotonic()
                frames = clients[addr][1].feed(data)
                if not frames:
                    continue
                if drone_addr is None:
                    st["up_dropped"] += len(frames)
                    continue
                out = bytearray()
                plain_bytes = 0
                t0 = time.perf_counter_ns()
                for f in frames:
                    plain_bytes += len(f)
                    p = bytearray(sealer.seal(f)) if ascon else bytearray(f)
                    up_count += 1
                    if args.tamper_every and up_count % args.tamper_every == 0:
                        hl = 10 if p[0] == 0xFD else 6
                        p[min(hl, len(p) - 1)] ^= 0x01  # first byte after the header
                        st["tampered"] += 1
                    out += p
                dt = (time.perf_counter_ns() - t0) if ascon else 0
                st["up_frames"] += len(frames)
                drone_sock.sendto(bytes(out), drone_addr)
                if log:
                    af, rp, _ = counters()
                    log.write(f"{now},up,{len(out)},{len(frames)},{len(out)},{plain_bytes},"
                              f"{dt},{af},{rp}\n")
        if time.monotonic() >= next_stats:
            next_stats += args.stats_every
            tnow = time.monotonic()
            for c in [c for c, v in clients.items() if tnow - v[0] > CLIENT_TIMEOUT_S]:
                del clients[c]
            report()
    report(final=True)
    if log:
        log.close()


if __name__ == "__main__":
    main()
