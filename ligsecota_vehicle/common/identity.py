"""Common machinery every node (server, gateway, ECU) needs."""
import json

from common.certs import certificate_to_dict, certificate_from_dict

from common.wire import now_ms


class Node:
    def __init__(self, ca, suite="v1", fingerprint=None):
        self.ca = ca
        self.suite = suite
        self.clock_skew_ms = 0          # attack lever for A3 (Handbook 14.2)
        self.bus = None
        self.name = None
        if suite == "v1":
            from common.crypto import v1_keypair
            self.priv, self.pub = v1_keypair(bits=2048)
        else:
            from common.crypto import v2_keypair
            self.priv, self.pub = v2_keypair()
        self.fingerprint = fingerprint  # only set for ECUs

    def now(self):
        return now_ms() + self.clock_skew_ms

    def enroll(self, subject):
        self.cert = self.ca.issue(subject, self.pub, fingerprint=self.fingerprint)
        return self.cert

    def cert_bytes(self):
        # Safe JSON serialization: never unpickle a certificate received over
        # the network. Public certificate fields and signature are hex encoded.
        return json.dumps(certificate_to_dict(self.cert), sort_keys=True,
                          separators=(",", ":")).encode("utf-8")

    @staticmethod
    def load_cert(buf):
        return certificate_from_dict(json.loads(buf.decode("utf-8")))
