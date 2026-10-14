"""
Wire format shared by every node.

Canonical, length-prefixed encoding so that every MAC/signature input is
unambiguous (see Handbook Chapter 9.1). Nothing here is cryptographic;
it just turns a list of byte-strings into one byte-string and back.
"""
import struct
import time
from enum import IntEnum


PROTO_VERSION = {"v1": b"\x01", "v2": b"\x02"}


class MT(IntEnum):
    AUTH_REQ = 1
    AUTH_RESP = 2
    AUTH_CONF = 3
    AUTH_ACK = 4
    AUTHZ_REQ = 10
    AUTHZ_GRANT = 11
    PKG = 20
    STATUS = 30


def pack(fields):
    """Length-prefixed concatenation of a list of byte-strings."""
    out = bytearray(struct.pack(">H", len(fields)))
    for f in fields:
        if isinstance(f, int):
            f = f.to_bytes(8, "big")
        if isinstance(f, str):
            f = f.encode()
        out += struct.pack(">I", len(f)) + f
    return bytes(out)


def unpack(buf):
    n, = struct.unpack_from(">H", buf, 0)
    off = 2
    out = []
    for _ in range(n):
        ln, = struct.unpack_from(">I", buf, off)
        off += 4
        out.append(buf[off:off + ln])
        off += ln
    return out


def now_ms():
    return int(time.time() * 1000)


def ts_from(b):
    return int.from_bytes(b, "big")


class ProtocolError(Exception):
    """Every rejection in the protocol raises this. In v2 the message is
    deliberately uninformative to an external observer (Handbook 6.9,
    9.4); callers are responsible for not leaking more than this string
    across a real network boundary."""
    pass


class Header:
    """Update package header: version, product type, target ECU id(s)."""

    def __init__(self, version, product, targets, sec_version=None):
        self.version = version
        self.product = product
        self.targets = list(targets)
        # sec_version is the ANTI-ROLLBACK counter used by v2 (Ch. 17/18,
        # Finding F2). v1 has no such field -- it is not part of the
        # paper's design, which is exactly the point.
        self.sec_version = sec_version if sec_version is not None else version

    def encode(self):
        return pack([
            str(self.version), str(self.product),
            ",".join(self.targets), str(self.sec_version),
        ])

    @staticmethod
    def decode(buf):
        v, prod, targets, secv = unpack(buf)
        return Header(int(v), prod.decode(),
                      targets.decode().split(",") if targets else [],
                      int(secv))

    def __eq__(self, other):
        return isinstance(other, Header) and self.encode() == other.encode()

    def __repr__(self):
        return f"Header(v={self.version}, product={self.product!r}, " \
               f"targets={self.targets}, sec_version={self.sec_version})"
