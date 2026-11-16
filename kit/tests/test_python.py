#!/usr/bin/env python3
"""PC-side tests.

1. pyascon (independent Python reference by the Ascon designers) reproduces
   the official SP 800-232 KAT file.
2. The C core used by drone and proxy (via ctypes) produces exactly the frame
   that an independent Python implementation of the format (pyascon) produces,
   and each side opens the other's frames.
3. Real MAVLink frames from pymavlink (v1, v2, signed) survive seal/open and
   pymavlink decodes them.
4. Stream reassembly with arbitrary datagram splits.
5. Optional: the mavcrypt_tool binary (PC or ARM under qemu) gives the same
   bytes as the library (--tool, --tool-runner).
"""
import argparse
import os
import random
import struct
import subprocess
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(KIT, "gcs"))
sys.path.insert(0, os.path.join(KIT, "third_party", "pyascon"))

import ascon  # noqa: E402  (pyascon)
import mavcrypt  # noqa: E402
from pymavlink.dialects.v20 import ardupilotmega as mav2  # noqa: E402

checks = 0
failures = 0


def check(cond, msg):
    global checks, failures
    checks += 1
    if not cond:
        failures += 1
        print(f"  FAIL: {msg}")


def kat_entries(path):
    entry = {}
    for line in open(path):
        line = line.strip()
        if not line:
            if entry:
                yield entry
            entry = {}
            continue
        k, _, v = line.partition("=")
        entry[k.strip()] = v.strip()
    if entry:
        yield entry


def test_pyascon_kat():
    print("[test] pyascon vs official LWC_AEAD_KAT_128_128.txt")
    n = bad = 0
    for e in kat_entries(os.path.join(KIT, "third_party", "ascon-c", "LWC_AEAD_KAT_128_128.txt")):
        k, nonce = bytes.fromhex(e["Key"]), bytes.fromhex(e["Nonce"])
        pt, ad, ct = bytes.fromhex(e["PT"]), bytes.fromhex(e["AD"]), bytes.fromhex(e["CT"])
        n += 1
        if ascon.ascon_encrypt(k, nonce, ad, pt) != ct or ascon.ascon_decrypt(k, nonce, ad, ct) != pt:
            bad += 1
    check(n == 1089 and bad == 0, f"{bad} of {n} KAT vectors differ")


def py_seal(key, prefix, role, counter, frame):
    """Independent implementation of the protected-frame format with pyascon."""
    hl = 10 if frame[0] == 0xFD else 6
    p = bytes([(prefix[0] & 0x7F) | (role << 7)]) + prefix[1:]
    nonce = p + struct.pack(">Q", counter)
    ct_tag = ascon.ascon_encrypt(key, nonce, frame[:hl], frame[hl:])
    return frame[:hl] + ct_tag[:-16] + nonce + ct_tag[-16:]


def py_open(key, prot):
    hl = 10 if prot[0] == 0xFD else 6
    nonce, tag = prot[-32:-16], prot[-16:]
    pt = ascon.ascon_decrypt(key, nonce, prot[:hl], prot[hl:-32] + tag)
    return None if pt is None else prot[:hl] + pt


def random_frame(rng, v2, signed):
    plen = rng.randrange(0, 256)
    body = bytes(rng.randrange(256) for _ in range(plen + 2))
    if v2:
        hdr = bytes([0xFD, plen, 1 if signed else 0, 0, rng.randrange(256), 1, 1, 33, 0, 0])
        return hdr + body + (bytes(rng.randrange(256) for _ in range(13)) if signed else b"")
    return bytes([0xFE, plen, rng.randrange(256), 1, 1, 33]) + body


def test_c_vs_python(rng):
    print("[test] C core (ctypes) == independent Python implementation (pyascon), 300 frames")
    key = bytes(rng.randrange(256) for _ in range(16))
    prefix = bytes(rng.randrange(256) for _ in range(8))
    sealer = mavcrypt.Sealer(key, mavcrypt.ROLE_DRONE, prefix)
    opener = mavcrypt.Opener(key, mavcrypt.ROLE_GCS)
    same = opened = py_opened = 0
    for i in range(300):
        f = random_frame(rng, v2=i % 3 != 0, signed=i % 3 == 2)
        c = sealer.seal(f)
        p = py_seal(key, prefix, mavcrypt.ROLE_DRONE, i + 1, f)
        same += c == p
        py_opened += py_open(key, c) == f
        try:
            opened += opener.open(p) == f
        except ValueError:
            pass
    check(same == 300, f"identical protected frames: {same}/300")
    check(py_opened == 300, f"pyascon opens C frames: {py_opened}/300")
    check(opened == 300, f"C opens pyascon frames: {opened}/300")
    # overhead is exactly 32 bytes
    f = random_frame(rng, True, False)
    check(len(sealer.seal(f)) == len(f) + 32, "32-byte overhead")
    # tampering, wrong key, replay
    prot = bytearray(sealer.seal(f))
    prot[12] ^= 1
    try:
        opener.open(bytes(prot))
        check(False, "tampered frame accepted")
    except ValueError as e:
        check(str(e) == "auth", f"tampered frame -> {e}")
    good = sealer.seal(f)
    opener.open(good)
    try:
        opener.open(good)
        check(False, "replayed frame accepted")
    except ValueError as e:
        check(str(e) == "replay", f"replay -> {e}")
    other = mavcrypt.Opener(bytes(16), mavcrypt.ROLE_GCS)
    try:
        other.open(sealer.seal(f))
        check(False, "wrong key accepted")
    except ValueError as e:
        check(str(e) == "auth", f"wrong key -> {e}")


def test_pymavlink_frames(rng):
    print("[test] real pymavlink frames (v1, v2, signed) through seal/open")
    key = bytes(range(16))
    sealer = mavcrypt.Sealer(key, mavcrypt.ROLE_DRONE)
    opener = mavcrypt.Opener(key, mavcrypt.ROLE_GCS)

    class Sink:
        def write(self, b):
            pass

    msgs = [
        mav2.MAVLink_heartbeat_message(2, 3, 81, 0, 3, 3),
        mav2.MAVLink_attitude_message(1234, 0.1, -0.2, 1.5, 0.01, 0.02, 0.03),
        mav2.MAVLink_param_value_message(b"ARMING_CHECK", 1.0, 9, 900, 12),
        mav2.MAVLink_statustext_message(6, b"Ascon-AEAD128 test message", 0, 0),
        mav2.MAVLink_timesync_message(0, 123456789),
    ]
    for variant in ("v2", "v1", "signed"):
        enc = mav2.MAVLink(Sink(), srcSystem=1, srcComponent=1)
        dec = mav2.MAVLink(Sink())
        if variant == "v1":
            enc.WIRE_PROTOCOL_VERSION = "1.0"
        if variant == "signed":
            secret = bytes(range(32))
            enc.signing.secret_key = secret
            enc.signing.link_id = 0
            enc.signing.timestamp = 1
            enc.signing.sign_outgoing = True
            dec.signing.secret_key = secret
            dec.signing.sign_outgoing = False
        for m in msgs:
            if variant == "v1" and m.get_msgId() > 255:
                continue
            raw = m.pack(enc)
            if variant == "v1":
                raw = m.pack(enc, force_mavlink1=True)
            prot = sealer.seal(raw)
            plain = opener.open(prot)
            out = dec.parse_buffer(plain) or []
            ok = len(out) == 1 and out[0].get_type() == m.get_type()
            check(ok, f"{variant} {m.get_type()} decoded after seal/open")
            if variant == "signed":
                check(len(raw) == 10 + raw[1] + 2 + 13, "signed frame carries signature")


def test_stream(rng):
    print("[test] stream reassembly across random datagram splits")
    key = bytes(range(16))
    sealer = mavcrypt.Sealer(key, mavcrypt.ROLE_DRONE)
    opener = mavcrypt.Opener(key, mavcrypt.ROLE_GCS)
    frames = [random_frame(rng, i % 4 != 0, i % 5 == 0) for i in range(200)]
    stream = b"".join(sealer.seal(f) for f in frames)
    got = b""
    total = 0
    pos = 0
    while pos < len(stream):
        n = rng.randrange(1, 700)
        k, plain = opener.feed(stream[pos:pos + n])
        total += k
        got += plain
        pos += n
    check(total == 200 and got == b"".join(frames), f"recovered {total}/200 frames")
    split = mavcrypt.FrameSplitter()
    clear = b"".join(frames)
    out = []
    pos = 0
    while pos < len(clear):
        n = rng.randrange(1, 300)
        out += split.feed(clear[pos:pos + n])
        pos += n
    check(out == frames, f"FrameSplitter recovered {len(out)}/200 clear frames")


def test_tool(rng, tool, runner):
    print(f"[test] {os.path.basename(tool)} (seal/open CLI) == library")
    key = bytes(rng.randrange(256) for _ in range(16))
    prefix = bytes(rng.randrange(256) for _ in range(8))
    sealer = mavcrypt.Sealer(key, mavcrypt.ROLE_DRONE, prefix)
    ok = 0
    for i in range(20):
        f = random_frame(rng, i % 2 == 0, i % 4 == 0)
        lib_out = sealer.seal(f, counter=1000 + i)
        cmd = runner + [tool, "seal", key.hex(), prefix.hex(), str(1000 + i), "0", f.hex()]
        cli = subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
        back = subprocess.run(runner + [tool, "open", key.hex(), "1", cli],
                              capture_output=True, text=True).stdout.strip()
        ok += cli == lib_out.hex() and back == f.hex()
    check(ok == 20, f"{ok}/20 frames identical")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", action="append", default=[],
                    help="mavcrypt_tool binary to cross-check (repeatable)")
    ap.add_argument("--tool-runner", action="append", default=[],
                    help="runner for the matching --tool, e.g. qemu-arm ('' = none)")
    args = ap.parse_args()
    rng = random.Random(20261006)
    test_pyascon_kat()
    test_c_vs_python(rng)
    test_pymavlink_frames(rng)
    test_stream(rng)
    for i, tool in enumerate(args.tool):
        runner = args.tool_runner[i].split() if i < len(args.tool_runner) else []
        test_tool(rng, tool, runner)
    print(f"{checks} checks, {failures} failures")
    if failures:
        sys.exit(1)
    print("PYTHON TESTS PASSED")


if __name__ == "__main__":
    main()
