"""Readable demo audit logs. Never prints raw private/session key material."""
from datetime import datetime, timezone
import hashlib
import threading

_lock = threading.Lock()

def log(component, event, **fields):
    stamp = datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S.%f")[:-3]
    details = " | ".join(f"{k}={v}" for k, v in fields.items())
    with _lock:
        print(f"[{stamp}] [{component}] {event}" + (f" | {details}" if details else ""), flush=True)

def fp(data: bytes, chars=16):
    """Short SHA-256 fingerprint for identifying key material without revealing it."""
    return hashlib.sha256(data).hexdigest()[:chars]

def key_label(key: bytes):
    return f"{len(key)*8}-bit key; sha256={fp(key)}"
