"""Python binding (ctypes) to kit/common/mavcrypt_core.c.

The PC uses exactly the same C code as the drone (core + ascon-c opt32), built
as build/libmavcrypt.so by tests/build_and_test.sh. An independent check
against pyascon is done in tests/test_python.py.
"""
import ctypes
import os

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB_PATH = os.environ.get("MAVCRYPT_LIB", os.path.join(KIT, "build", "libmavcrypt.so"))

ROLE_DRONE = 0
ROLE_GCS = 1
ERRORS = {-1: "malformed", -2: "auth", -3: "replay", -4: "direction"}

_u8 = ctypes.c_uint8

# Set once _load() has queried the loaded library (depends on which algorithm
# it was built for: Ascon-AEAD128, AES-128-GCM or ChaCha20-Poly1305 all share
# this binding, but with different key/prefix/nonce sizes, see mavcrypt_core.h).
KEY_LEN = None
PREFIX_LEN = None
OVERHEAD = None
MAX_PLAIN_FRAME = 280
MAX_FRAME = None
ALG_NAMES = {1: "ascon", 2: "aesgcm", 3: "chacha"}


def _make_structs(key_len, prefix_len, max_frame):
    class _Tx(ctypes.Structure):
        _fields_ = [("key", _u8 * key_len), ("prefix", _u8 * prefix_len),
                   ("counter", ctypes.c_uint64)]

    class _Rx(ctypes.Structure):
        _fields_ = [
            ("key", _u8 * key_len),
            ("role", _u8),
            ("have_peer", _u8),
            ("peer_prefix", _u8 * prefix_len),
            ("highest", ctypes.c_uint64),
            ("window", ctypes.c_uint64),
            ("buf", _u8 * max_frame),
            ("len", ctypes.c_uint16),
            ("need", ctypes.c_uint16),
            ("ok", ctypes.c_uint32),
            ("auth_fail", ctypes.c_uint32),
            ("replay", ctypes.c_uint32),
            ("bad_dir", ctypes.c_uint32),
            ("skipped", ctypes.c_uint32),
        ]

    return _Tx, _Rx


def _load():
    global KEY_LEN, PREFIX_LEN, OVERHEAD, MAX_FRAME, _Tx, _Rx
    if not os.path.exists(LIB_PATH):
        raise RuntimeError(f"{LIB_PATH} not found: run  sh tests/build_and_test.sh  first")
    lib = ctypes.CDLL(LIB_PATH)
    for name in ("mc_key_len", "mc_prefix_len", "mc_overhead", "mc_max_frame", "mc_alg_id"):
        getattr(lib, name).restype = ctypes.c_uint
    KEY_LEN = lib.mc_key_len()
    PREFIX_LEN = lib.mc_prefix_len()
    OVERHEAD = lib.mc_overhead()
    MAX_FRAME = lib.mc_max_frame()
    _Tx, _Rx = _make_structs(KEY_LEN, PREFIX_LEN, MAX_FRAME)
    if lib.mc_sizeof_tx() != ctypes.sizeof(_Tx) or lib.mc_sizeof_rx() != ctypes.sizeof(_Rx):
        raise RuntimeError("libmavcrypt.so struct layout does not match mavcrypt.py")
    P = ctypes.POINTER
    lib.mc_tx_init.argtypes = [P(_Tx), ctypes.c_char_p, ctypes.c_char_p, _u8]
    lib.mc_seal.argtypes = [P(_Tx), ctypes.c_char_p, ctypes.c_uint16, ctypes.c_char_p]
    lib.mc_seal.restype = ctypes.c_int
    lib.mc_seal_with_counter.argtypes = [P(_Tx), ctypes.c_uint64, ctypes.c_char_p,
                                         ctypes.c_uint16, ctypes.c_char_p]
    lib.mc_seal_with_counter.restype = ctypes.c_int
    lib.mc_rx_init.argtypes = [P(_Rx), ctypes.c_char_p, _u8]
    lib.mc_open.argtypes = [P(_Rx), ctypes.c_char_p, ctypes.c_uint16, ctypes.c_char_p]
    lib.mc_open.restype = ctypes.c_int
    lib.mc_rx_feed.argtypes = [P(_Rx), ctypes.c_char_p, ctypes.c_uint32, ctypes.c_char_p,
                               ctypes.c_uint32, P(ctypes.c_uint32)]
    lib.mc_rx_feed.restype = ctypes.c_int
    return lib


_lib = None
_Tx = None
_Rx = None


def lib():
    global _lib
    if _lib is None:
        _lib = _load()
    return _lib


def local_host():
    """Address for proxy <-> tools (and SITL) traffic on this PC.

    With WSL2 networkingMode=mirrored, 127.0.0.1 is routed through Windows
    (dev loopback0), which was measured to reorder and drop UDP datagrams
    (87 reorderings in 20000). In that case use the address that is really
    local to Linux (on dev lo). Override with the MAVCRYPT_HOST variable."""
    env = os.environ.get("MAVCRYPT_HOST")
    if env:
        return env
    import subprocess
    try:
        route = subprocess.run(["ip", "-4", "route", "get", "127.0.0.1"],
                               capture_output=True, text=True, timeout=2).stdout
        if "loopback0" not in route:
            return "127.0.0.1"
        addrs = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", "lo"],
                               capture_output=True, text=True, timeout=2).stdout
        for line in addrs.splitlines():
            ip = line.split()[3].split("/")[0]
            if not ip.startswith("127."):
                return ip
    except (OSError, IndexError, subprocess.SubprocessError):
        pass
    return "127.0.0.1"


def load_key(path):
    lib()  # populate KEY_LEN from the loaded library (depends on its algorithm)
    key = bytes.fromhex(open(path).read().strip())
    if len(key) != KEY_LEN:
        raise ValueError(f"{path}: the key must be {KEY_LEN} bytes ({KEY_LEN * 2} hex characters)")
    return key


class Sealer:
    """Protects clear MAVLink frames (one sender session)."""

    def __init__(self, key, role, prefix=None):
        lib()
        if len(key) != KEY_LEN:
            raise ValueError(f"key must be {KEY_LEN} bytes, got {len(key)}")
        self._tx = _Tx()
        self._out = ctypes.create_string_buffer(MAX_FRAME)
        lib().mc_tx_init(ctypes.byref(self._tx), bytes(key), prefix or os.urandom(PREFIX_LEN), role)

    @property
    def counter(self):
        return self._tx.counter

    def seal(self, frame, counter=None):
        frame = bytes(frame)
        if counter is None:
            n = lib().mc_seal(ctypes.byref(self._tx), frame, len(frame), self._out)
        else:
            n = lib().mc_seal_with_counter(ctypes.byref(self._tx), counter, frame,
                                           len(frame), self._out)
        if n < 0:
            raise ValueError(f"seal failed: {ERRORS.get(n, n)}")
        return self._out.raw[:n]


class Opener:
    """Verifies/decrypts protected frames, single frames or a byte stream."""

    def __init__(self, key, role):
        lib()
        if len(key) != KEY_LEN:
            raise ValueError(f"key must be {KEY_LEN} bytes, got {len(key)}")
        self._rx = _Rx()
        self._out = ctypes.create_string_buffer(65536)
        self._one = ctypes.create_string_buffer(MAX_FRAME)
        self._olen = ctypes.c_uint32(0)
        lib().mc_rx_init(ctypes.byref(self._rx), bytes(key), role)

    def open(self, data):
        """One complete protected frame -> clear frame, or raises ValueError."""
        data = bytes(data)
        n = lib().mc_open(ctypes.byref(self._rx), data, len(data), self._one)
        if n < 0:
            raise ValueError(ERRORS.get(n, str(n)))
        return self._one.raw[:n]

    def feed(self, data):
        """Stream input (e.g. one datagram) -> (frames, concatenated clear frames)."""
        data = bytes(data)
        frames = lib().mc_rx_feed(ctypes.byref(self._rx), data, len(data), self._out,
                                  len(self._out), ctypes.byref(self._olen))
        return frames, self._out.raw[: self._olen.value]

    @property
    def stats(self):
        r = self._rx
        return {"ok": r.ok, "auth_fail": r.auth_fail, "replay": r.replay,
                "bad_dir": r.bad_dir, "skipped": r.skipped}


def plain_frame_len(buf, i=0):
    """Length of the clear MAVLink frame starting at buf[i] (needs 3 bytes), 0 if no STX."""
    stx = buf[i]
    if stx == 0xFD:
        return 10 + buf[i + 1] + 2 + (13 if buf[i + 2] & 0x01 else 0)
    if stx == 0xFE:
        return 6 + buf[i + 1] + 2
    return 0


class FrameSplitter:
    """Splits a byte stream of clear MAVLink frames into frames (no CRC check)."""

    def __init__(self):
        self.buf = bytearray()
        self.skipped = 0

    def feed(self, data):
        self.buf += data
        frames = []
        i = 0
        b = self.buf
        while i < len(b):
            if b[i] not in (0xFD, 0xFE):
                i += 1
                self.skipped += 1
                continue
            if len(b) - i < 3:
                break
            n = plain_frame_len(b, i)
            if len(b) - i < n:
                break
            frames.append(bytes(b[i:i + n]))
            i += n
        del self.buf[:i]
        return frames
