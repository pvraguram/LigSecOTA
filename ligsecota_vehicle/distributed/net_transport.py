"""Length-prefixed JSON transport for the two-computer V1 demo.

This is a demo transport over a trusted LAN, not a production network stack.
Protocol message bodies remain the V1 project's binary wire payloads and are
base64-wrapped only for transport framing.
"""
import base64
import json
import socket
import struct
import threading
from common.audit import log, fp
from common.wire import MT

_MSG_NAMES = {int(v): v.name for v in MT}

def _describe(src, dst, mtype, body_len, frame_len=None):
    name = _MSG_NAMES.get(int(mtype), f"UNKNOWN_{mtype}")
    fields = {"route": f"{src} -> {dst}", "message": name, "type_id": int(mtype), "protocol_body_bytes": body_len}
    if frame_len is not None:
        fields["tcp_frame_payload_bytes"] = frame_len
    log("TCP", "FRAME", **fields)

MAX_FRAME = 10 * 1024 * 1024


def _recv_exact(sock, count):
    chunks = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("peer disconnected")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send_frame(sock, lock, src, dst, mtype, body):
    payload = json.dumps({
        "src": src,
        "dst": dst,
        "mtype": int(mtype),
        "body": base64.b64encode(body).decode("ascii"),
    }, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_FRAME:
        raise ValueError("message exceeds maximum demo frame size")
    with lock:
        sock.sendall(struct.pack(">I", len(payload)) + payload)
    _describe(src, dst, mtype, len(body), len(payload))


def _read_frame(sock):
    size = struct.unpack(">I", _recv_exact(sock, 4))[0]
    if size <= 0 or size > MAX_FRAME:
        raise ValueError(f"invalid network frame size: {size}")
    data = json.loads(_recv_exact(sock, size).decode("utf-8"))
    src, dst, mtype = str(data["src"]), str(data["dst"]), int(data["mtype"])
    body = base64.b64decode(data["body"], validate=True)
    _describe(src, dst, mtype, len(body), size)
    return src, dst, mtype, body


class ServerNetworkBus:
    """Server-side bus: all node-to-vehicle messages use one TCP connection."""
    def __init__(self, sock):
        self.sock = sock
        self.nodes = {}
        self.journal = []
        self.send_lock = threading.Lock()
        self.forward_status_to_server = False
        self.error = None
        self._closed = threading.Event()

    def register(self, name, node):
        self.nodes[name] = node
        node.bus = self
        node.name = name

    def send(self, src, dst, mtype, body):
        self.journal.append((src, dst, int(mtype), body))
        _send_frame(self.sock, self.send_lock, src, dst, mtype, body)

    def start_reader(self):
        thread = threading.Thread(target=self._read_loop, daemon=True,
                                  name="ligsecota-server-reader")
        thread.start()
        return thread

    def _read_loop(self):
        try:
            while not self._closed.is_set():
                src, dst, mtype, body = _read_frame(self.sock)
                if dst != "server" or src != "gateway":
                    raise ValueError(f"unexpected remote route {src} -> {dst}")
                self.journal.append((src, dst, mtype, body))
                self.nodes["server"].receive(src, mtype, body)
        except Exception as exc:
            if not self._closed.is_set():
                self.error = exc
                if not (isinstance(exc, ConnectionError) and
                        str(exc) == "peer disconnected"):
                    print(f"[network] connection ended: {exc}")

    def close(self):
        self._closed.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class VehicleNetworkBus:
    """Vehicle-side bus: gateway/ECU are local; server is reached over TCP."""
    def __init__(self, sock):
        self.sock = sock
        self.nodes = {}
        self.journal = []
        self.send_lock = threading.Lock()
        self.forward_status_to_server = True
        self.error = None
        self._closed = threading.Event()

    def register(self, name, node):
        self.nodes[name] = node
        node.bus = self
        node.name = name

    def send(self, src, dst, mtype, body):
        self.journal.append((src, dst, int(mtype), body))
        if dst in self.nodes:
            self.nodes[dst].receive(src, mtype, body)
        else:
            if dst != "server":
                raise ValueError(f"unknown local destination: {dst}")
            _send_frame(self.sock, self.send_lock, src, dst, mtype, body)

    def start_reader(self):
        thread = threading.Thread(target=self._read_loop, daemon=True,
                                  name="ligsecota-vehicle-reader")
        thread.start()
        return thread

    def _read_loop(self):
        try:
            while not self._closed.is_set():
                src, dst, mtype, body = _read_frame(self.sock)
                if src != "server" or dst not in self.nodes:
                    raise ValueError(f"unexpected remote route {src} -> {dst}")
                self.journal.append((src, dst, mtype, body))
                self.nodes[dst].receive(src, mtype, body)
        except Exception as exc:
            if not self._closed.is_set():
                self.error = exc
                if not (isinstance(exc, ConnectionError) and
                        str(exc) == "peer disconnected"):
                    print(f"[network] connection ended: {exc}")

    def close(self):
        self._closed.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
