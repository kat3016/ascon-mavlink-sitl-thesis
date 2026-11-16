#!/usr/bin/env python3
"""Install AP_MAVCrypt (Ascon-AEAD128 for MAVLink) into an ArduPilot tree.

    python3 drone/apply_mavcrypt.py ~/ardupilot           # install / update
    python3 drone/apply_mavcrypt.py ~/ardupilot --check   # only report
    python3 drone/apply_mavcrypt.py ~/ardupilot --revert  # undo (git checkout)

Every change is guarded by #if AP_MAVCRYPT_ENABLED, so the patched tree builds
both binaries from the same source:
    ./waf configure --board sitl                                  -> plain
    ./waf configure --board sitl --define AP_MAVCRYPT_ENABLED=1   -> ascon

The script is idempotent. Each step prints [ok] (applied now), [ok*] (was
already applied) or [FAIL]; on [FAIL] it prints the block to insert by hand.
Tested on ArduPilot master cafe674 (2 Oct 2026).
"""
import argparse
import os
import shutil
import subprocess
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MARK = "MAVCRYPT"

# ---------------------------------------------------------------------------
# text patches: (relative file, description, anchor, replacement)
# the replacement always contains the anchor plus lines tagged with MAVCRYPT
# ---------------------------------------------------------------------------
PATCHES = [
    (
        "Tools/ardupilotwaf/boards.py",
        "link libcrypto (needed by AP_MAVCRYPT_ALG=2/3, harmless otherwise)",
        "        env.LIB += [\n"
        "            'm',\n"
        "        ]\n",
        "        env.LIB += [\n"
        "            'm',\n"
        "            'crypto',  # MAVCRYPT: AES-GCM / ChaCha20-Poly1305 via OpenSSL\n"
        "        ]\n",
    ),
    (
        "Tools/ardupilotwaf/ardupilotwaf.py",
        "build AP_MAVCrypt with every vehicle",
        "    'GCS_MAVLink',\n",
        "    'GCS_MAVLink',\n    'AP_MAVCrypt',  # MAVCRYPT\n",
    ),
    (
        "libraries/GCS_MAVLink/GCS_MAVLink.cpp",
        "include AP_MAVCrypt",
        "#include <AP_HAL/AP_HAL.h>\n",
        "#include <AP_HAL/AP_HAL.h>\n#include <AP_MAVCrypt/AP_MAVCrypt.h>  // MAVCRYPT\n",
    ),
    (
        "libraries/GCS_MAVLink/GCS_MAVLink.cpp",
        "comm_send_buffer(): capture the frame instead of writing it",
        "    const size_t written = mavlink_comm_port[chan]->write(buf, len);\n",
        "#if AP_MAVCRYPT_ENABLED  // MAVCRYPT\n"
        "    if (mavcrypt_tx_capturing(chan)) {\n"
        "        mavcrypt_tx_append(chan, buf, len);\n"
        "        return;\n"
        "    }\n"
        "#endif  // MAVCRYPT\n"
        "    const size_t written = mavlink_comm_port[chan]->write(buf, len);\n",
    ),
    (
        "libraries/GCS_MAVLink/GCS_MAVLink.cpp",
        "comm_send_lock(): reserve 32 bytes and start capturing",
        "    chan_locks[chan].take_blocking();\n"
        "    if (mavlink_comm_port[chan]->txspace() < size) {\n",
        "    chan_locks[chan].take_blocking();\n"
        "#if AP_MAVCRYPT_ENABLED  // MAVCRYPT\n"
        "    size += MAVCRYPT_TX_OVERHEAD;\n"
        "    mavcrypt_tx_begin(chan);\n"
        "#endif  // MAVCRYPT\n"
        "    if (mavlink_comm_port[chan]->txspace() < size) {\n",
    ),
    (
        "libraries/GCS_MAVLink/GCS_MAVLink.cpp",
        "comm_send_unlock(): seal the whole frame and write it once",
        "void comm_send_unlock(mavlink_channel_t chan_m)\n"
        "{\n"
        "    const uint8_t chan = uint8_t(chan_m);\n",
        "void comm_send_unlock(mavlink_channel_t chan_m)\n"
        "{\n"
        "    const uint8_t chan = uint8_t(chan_m);\n"
        "#if AP_MAVCRYPT_ENABLED  // MAVCRYPT\n"
        "    {\n"
        "        const uint8_t *mavcrypt_out = nullptr;\n"
        "        const uint16_t mavcrypt_n = mavcrypt_tx_end(chan, &mavcrypt_out);\n"
        "        if (mavcrypt_n > 0 && !chan_discard[chan] && mavlink_comm_port[chan] != nullptr) {\n"
        "            mavlink_comm_port[chan]->write(mavcrypt_out, mavcrypt_n);\n"
        "        }\n"
        "    }\n"
        "#endif  // MAVCRYPT\n",
    ),
    (
        "libraries/GCS_MAVLink/GCS_Signing.cpp",
        "include AP_MAVCrypt",
        '#include "GCS.h"\n',
        '#include "GCS.h"\n#include <AP_MAVCrypt/AP_MAVCrypt.h>  // MAVCRYPT\n',
    ),
    (
        "libraries/GCS_MAVLink/GCS_Signing.cpp",
        "packet_overhead_chan(): count the 32 bytes (signed frames)",
        "        return MAVLINK_NUM_NON_PAYLOAD_BYTES + MAVLINK_SIGNATURE_BLOCK_LEN + reserved_space;\n",
        "        return MAVLINK_NUM_NON_PAYLOAD_BYTES + MAVLINK_SIGNATURE_BLOCK_LEN + reserved_space + MAVCRYPT_PACKET_EXTRA;  // MAVCRYPT\n",
    ),
    (
        "libraries/GCS_MAVLink/GCS_Signing.cpp",
        "packet_overhead_chan(): count the 32 bytes",
        "    return MAVLINK_NUM_NON_PAYLOAD_BYTES + reserved_space;\n",
        "    return MAVLINK_NUM_NON_PAYLOAD_BYTES + reserved_space + MAVCRYPT_PACKET_EXTRA;  // MAVCRYPT\n",
    ),
    (
        "libraries/GCS_MAVLink/GCS_Common.cpp",
        "include AP_MAVCrypt",
        '#include "GCS.h"\n',
        '#include "GCS.h"\n#include <AP_MAVCrypt/AP_MAVCrypt.h>  // MAVCRYPT\n',
    ),
    (
        "libraries/GCS_MAVLink/GCS_Common.cpp",
        "update_receive(): decrypt before the MAVLink parser (start of loop)",
        "        bool parsed_packet = false;\n"
        "\n"
        "        // Try to get a new message\n"
        "        const uint8_t framing = mavlink_frame_char_buffer(channel_buffer(), channel_status(), c, &msg, &status);\n",
        "        bool parsed_packet = false;\n"
        "\n"
        "#if AP_MAVCRYPT_ENABLED  // MAVCRYPT\n"
        "        // only authentic, fresh frames reach the MAVLink parser\n"
        "        uint8_t mavcrypt_plain[MAVCRYPT_MAX_PLAIN];\n"
        "        uint16_t mavcrypt_n = mavcrypt_rx_push(chan, c, mavcrypt_plain);\n"
        "        while (mavcrypt_n > 0) {\n"
        "        for (uint16_t mavcrypt_i = 0; mavcrypt_i < mavcrypt_n; mavcrypt_i++) {\n"
        "        const uint8_t parse_c = mavcrypt_plain[mavcrypt_i];\n"
        "#else\n"
        "        const uint8_t parse_c = c;\n"
        "#endif  // MAVCRYPT\n"
        "\n"
        "        // Try to get a new message\n"
        "        const uint8_t framing = mavlink_frame_char_buffer(channel_buffer(), channel_status(), parse_c, &msg, &status);\n",
    ),
    (
        "libraries/GCS_MAVLink/GCS_Common.cpp",
        "update_receive(): decrypt before the MAVLink parser (end of loop)",
        "                scripting->handle_message(msg, chan);\n"
        "            }\n"
        "        }\n"
        "#endif // AP_SCRIPTING_ENABLED\n",
        "                scripting->handle_message(msg, chan);\n"
        "            }\n"
        "        }\n"
        "#endif // AP_SCRIPTING_ENABLED\n"
        "#if AP_MAVCRYPT_ENABLED  // MAVCRYPT\n"
        "        }\n"
        "        mavcrypt_n = mavcrypt_rx_poll(chan, mavcrypt_plain);\n"
        "        }\n"
        "#endif  // MAVCRYPT\n",
    ),
    # The UDP UART drivers of SITL and Linux "packetise": they look
    # for MAVLink frames in the write buffer to send one frame per datagram.
    # Without the extra 32 bytes they misalign on protected frames, take
    # random nonce/tag bytes for an STX and hold data back until more traffic
    # arrives (observed: 200-400 ms stalls in SITL).
    (
        "libraries/AP_HAL/utility/packetise.cpp",
        "include AP_MAVCrypt",
        "#include <GCS_MAVLink/GCS_MAVLink.h>\n",
        "#include <GCS_MAVLink/GCS_MAVLink.h>\n#include <AP_MAVCrypt/AP_MAVCrypt.h>  // MAVCRYPT\n",
    ),
    (
        "libraries/AP_HAL/utility/packetise.cpp",
        "mavlink_packetise(): protected frames are 32 bytes longer",
        "    uint8_t min_length = (b == MAVLINK_STX_MAVLINK1)?8:12;\n",
        "    uint8_t min_length = (b == MAVLINK_STX_MAVLINK1)?8:12;\n"
        "#if AP_MAVCRYPT_ENABLED  // MAVCRYPT\n"
        "    // protected frames carry nonce + tag after the MAVLink frame\n"
        "    min_length += MAVCRYPT_TX_OVERHEAD;\n"
        "#endif  // MAVCRYPT\n",
    ),
]

PATCHED_FILES = sorted({p[0] for p in PATCHES})


def library_files():
    """(source, destination relative to libraries/AP_MAVCrypt)"""
    files = []
    drone = os.path.join(KIT, "drone", "AP_MAVCrypt")
    for name in sorted(os.listdir(drone)):
        files.append((os.path.join(drone, name), name))
    files.append((os.path.join(KIT, "common", "mavcrypt_core.h"), "mavcrypt_core.h"))
    files.append((os.path.join(KIT, "common", "mavcrypt_core.c"), "mavcrypt_core.c"))
    opt32 = os.path.join(KIT, "third_party", "ascon-c", "opt32")
    for name in sorted(os.listdir(opt32)):
        files.append((os.path.join(opt32, name), os.path.join("ascon", name)))
    files.append((os.path.join(KIT, "third_party", "ascon-c", "tests", "crypto_aead.h"),
                  os.path.join("ascon", "crypto_aead.h")))
    files.append((os.path.join(KIT, "third_party", "ascon-c", "LICENSE"),
                  os.path.join("ascon", "LICENSE")))
    files.append((os.path.join(KIT, "keys", "mavcrypt_key.h"), "mavcrypt_key.h"))
    return files


def install_library(ap, check_only):
    dest = os.path.join(ap, "libraries", "AP_MAVCrypt")
    ok = True
    key = os.path.join(KIT, "keys", "mavcrypt_key.h")
    if not os.path.exists(key):
        print("[FAIL] keys/mavcrypt_key.h not found: run  python3 gen_key.py  first")
        return False
    for src, rel in library_files():
        dst = os.path.join(dest, rel)
        data = open(src, "rb").read()
        if rel == "mavcrypt_core.c":
            # compile the core only in the Ascon binary
            data = (b"/* copied from kit/common by apply_mavcrypt.py */\n"
                    b"#if defined(AP_MAVCRYPT_ENABLED) && AP_MAVCRYPT_ENABLED\n"
                    + data + b"\n#endif\n")
        same = os.path.exists(dst) and open(dst, "rb").read() == data
        if check_only:
            if not same:
                print(f"[FAIL] library file out of date: {rel}")
                ok = False
            continue
        if not same:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(data)
    print(f"[{'ok' if ok else 'FAIL'}] libraries/AP_MAVCrypt ({len(library_files())} files)")
    return ok


def apply_patches(ap, check_only):
    ok = True
    for rel, desc, anchor, repl in PATCHES:
        path = os.path.join(ap, rel)
        text = open(path, encoding="utf-8").read()
        if repl in text:
            print(f"[ok*] {rel}: {desc}")
            continue
        if text.count(anchor) < 1:
            ok = False
            print(f"[FAIL] {rel}: {desc}")
            print("       anchor not found; insert by hand, in the equivalent place:")
            for line in repl.splitlines():
                print("       | " + line)
            continue
        if check_only:
            ok = False
            print(f"[FAIL] {rel}: {desc} (not applied)")
            continue
        text = text.replace(anchor, repl, 1)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print(f"[ok]  {rel}: {desc}")
    return ok


def revert(ap):
    subprocess.check_call(["git", "-C", ap, "checkout", "--"] + PATCHED_FILES)
    shutil.rmtree(os.path.join(ap, "libraries", "AP_MAVCrypt"), ignore_errors=True)
    print("[ok] reverted: " + ", ".join(PATCHED_FILES) + " and libraries/AP_MAVCrypt removed")


def main():
    ap_ = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap_.add_argument("ardupilot", help="path to the ArduPilot tree")
    ap_.add_argument("--check", action="store_true", help="report only, change nothing")
    ap_.add_argument("--revert", action="store_true", help="undo the patch")
    args = ap_.parse_args()
    ap = os.path.abspath(os.path.expanduser(args.ardupilot))
    if not os.path.exists(os.path.join(ap, "libraries", "GCS_MAVLink", "GCS_Common.cpp")):
        sys.exit(f"{ap} does not look like an ArduPilot tree")
    if args.revert:
        revert(ap)
        return
    try:
        head = subprocess.check_output(["git", "-C", ap, "rev-parse", "--short", "HEAD"],
                                       text=True).strip()
        print(f"ArduPilot tree: {ap} (HEAD {head})")
    except (OSError, subprocess.CalledProcessError):
        pass
    ok = install_library(ap, args.check)
    ok = apply_patches(ap, args.check) and ok
    if ok:
        print("ALL STEPS OK")
    else:
        print("SOME STEPS FAILED (see [FAIL] above)")
        sys.exit(1)


if __name__ == "__main__":
    main()
