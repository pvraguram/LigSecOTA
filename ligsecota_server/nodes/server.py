"""
OTA cloud server -- requests authorization, then distributes the package
directly to the ECU once the gateway has approved it (Handbook 4.4 /
Figure 4.3 / Figure 13.6-13.7).
"""
from common.crypto import v1_protect, v1_unprotect, v2_protect, v2_unprotect, hkdf
from common.protocol import ProtocolNode, DELTA_T_MS
from common.wire import MT, pack, unpack, ProtocolError, ts_from, PROTO_VERSION


class Server(ProtocolNode):
    def __init__(self, ca, suite="v1"):
        super().__init__(ca, suite=suite)
        self.k_dist = {}   # gateway_name -> global distribution key
        self.statuses = {} # ecu_name -> final status (distributed demo)

    def on_other_message(self, src, mtype, body):
        if mtype == MT.AUTHZ_GRANT:
            return self._on_authz_grant(src, body)
        if mtype == MT.STATUS:
            ecu_b, status_b = unpack(body)
            self.statuses[ecu_b.decode()] = status_b.decode()
            return
        raise ProtocolError(f"server: unexpected message type {mtype}")

    def request_authorization(self, gateway_name, header):
        p = self._peer(gateway_name)
        payload = pack([self.name, header.encode(), self.now()])
        if self.suite == "v1":
            blob, tag = v1_protect(p.auth_key, payload)
            msg = pack([blob, tag])
        else:
            ct, nonce = v2_protect(p.auth_key, payload,
                                   aad=b"authz-req:" + self.name.encode(),
                                   counter=p.next_nonce())
            msg = pack([ct, nonce])
        self.bus.send(self.name, gateway_name, MT.AUTHZ_REQ, msg)

    def _on_authz_grant(self, src, body):
        p = self._peer(src)
        if self.suite == "v1":
            blob, tag = unpack(body)
            pt = v1_unprotect(p.auth_key, blob, tag)
        else:
            ct, nonce = unpack(body)
            pt = v2_unprotect(p.auth_key, ct,
                              aad=b"authz-grant:" + self.name.encode(),
                              nonce=nonce)
        k_dist, hdr_b, t_g_b = unpack(pt)
        if abs(self.now() - ts_from(t_g_b)) >= DELTA_T_MS:
            raise ProtocolError("stale AUTHZ_GRANT")
        self.k_dist[src] = k_dist
        self._pending_header = hdr_b

    def distribute_package(self, ecu_name, firmware: bytes, gateway_name,
                           header, counter=0, ts=None):
        """`ts` defaults to "now", but callers distributing the SAME
        package to several targets in one logical distribution event
        (Handbook 4.4's one-to-many case) should pass an explicit shared
        timestamp -- otherwise two calls a millisecond apart embed
        different timestamps in the v1 MACed payload and happen to
        produce different tags for a reason that has nothing to do with
        Finding F8/A6 (identical plaintext -> identical tag under a
        shared key with no nonce). harness.Deployment.run_full_update
        does this correctly; see also attack/scenarios.py a6."""
        k_global = self.k_dist[gateway_name]
        hdr_b = header.encode()
        ts = self.now() if ts is None else ts
        # NOTE on `counter` here (v2 branch below): k_ecu is derived from a
        # freshly-generated random k_global minted once per authorization
        # (nodes/gateway.py `_on_authz_req`), so counter=0 is safe as long
        # as distribute_package is called at most once per authorization
        # per target. A production implementation that supports retries
        # under the same key should still track this defensively, the way
        # PeerState.next_nonce() does for the long-lived auth_key above.
        if self.suite == "v1":
            # F8 lives here too: every ECU gets a package protected under
            # the SAME k_global.
            payload = pack([firmware, hdr_b, ts])
            blob, tag = v1_protect(k_global, payload)
            self.bus.send(self.name, ecu_name, MT.PKG, pack([blob, tag]))
        else:
            k_ecu = hkdf(k_global,
                        b"ligsecota/v2/distribution-key:" + ecu_name.encode())
            aad = pack([PROTO_VERSION["v2"], bytes([MT.PKG]),
                       self.name, ecu_name, hdr_b])
            ct, nonce = v2_protect(k_ecu, firmware, aad=aad, counter=counter)
            self.bus.send(self.name, ecu_name, MT.PKG,
                          pack([ct, nonce, aad]))
