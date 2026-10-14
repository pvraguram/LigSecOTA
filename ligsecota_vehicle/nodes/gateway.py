"""
Gateway -- Stage 2 (Handbook 4.3 / Figure 4.2 / Figure 13.5).

Acts as the trusted hub: authenticates everyone (inherited from
ProtocolNode), vets every proposed update against the installation
version manifest, and mints the per-package distribution key.

v2 adds two things that do not exist in the paper:
  * a live bit-time fingerprint check during authentication (Handbook
    8.4 / 17.4, the fix for Finding F1)
  * per-ECU derivation of the distribution key, closing the shared-key
    sibling-forgery gap (Finding F8)
"""
import os

from common.crypto import (v1_protect, v1_unprotect, v2_protect,
                           v2_unprotect, hkdf, MonotonicCounter)
from common.manifest import Manifest
from common.protocol import ProtocolNode, DELTA_T_MS
from common.wire import MT, pack, unpack, ProtocolError, ts_from, Header
from common.audit import log, fp, key_label


class Gateway(ProtocolNode):
    def __init__(self, ca, suite="v1"):
        super().__init__(ca, suite=suite)
        self.manifest = Manifest()
        self.alarms = []
        self.counter = MonotonicCounter()
        # optional live-fingerprint configuration (v2 only); set externally
        self.fp_oscillators = {}      # ecu_name -> SimulatedOscillator
        self.fp_enrolled = {}         # ecu_name -> enrolled feature vector
        self.fp_threshold = 0.0
        self.status_forwarded = False

    # ------------------------------------------------- fingerprint hook
    def on_authenticated(self, peer_name):
        if self.suite != "v2" or peer_name not in self.fp_oscillators:
            return
        from common.fingerprint import live_check
        osc = self.fp_oscillators[peer_name]
        enrolled = self.fp_enrolled[peer_name]
        if not live_check(osc, enrolled, self.fp_threshold):
            raise ProtocolError(
                f"fingerprint mismatch for {peer_name}: key is valid but "
                f"the measured oscillator does not match the enrolled one "
                f"(Finding F1 -- this is exactly what v1 never checks)")

    # ------------------------------------------------- stage 2 : server
    def on_other_message(self, src, mtype, body):
        if mtype == MT.AUTHZ_REQ:
            return self._on_authz_req(src, body)
        if mtype == MT.STATUS:
            return self._on_status(src, body)
        raise ProtocolError(f"gateway: unexpected message type {mtype}")

    def _on_authz_req(self, src, body):
        p = self._peer(src)
        if self.suite == "v1":
            blob, tag = unpack(body)
            pt = v1_unprotect(p.auth_key, blob, tag)
        else:
            ct, nonce = unpack(body)
            pt = v2_unprotect(p.auth_key, ct, aad=b"authz-req:" + src.encode(),
                              nonce=nonce)
        id_s, hdr_b, t_s_b = unpack(pt)
        header = Header.decode(hdr_b)
        log(self.name or "gateway", "AUTHZ_REQUEST_DECRYPTED", requester=id_s.decode() if isinstance(id_s, bytes) else id_s, product=header.product, targets=header.targets, version=header.version, protection="AES-CBC + HMAC-MD5 under K_auth")

        if abs(self.now() - ts_from(t_s_b)) >= DELTA_T_MS:
            raise ProtocolError("stale AUTHZ_REQ")

        if not self.manifest.is_reasonable(header):
            self.alarms.append(header)
            return   # paper: "an alarm will be triggered" -- no grant sent

        k_dist = os.urandom(32)
        log(self.name or "gateway", "AUTHORIZATION_GRANTED", requester=src, targets=header.targets, product=header.product, version=header.version)
        log(self.name or "gateway", "DISTRIBUTION_KEY_CREATED", key="K_dist", details=key_label(k_dist), scope="V1 shared key delivered to server and target ECU", raw_key="NOT logged")
        t_g = self.now()
        self.manifest.record(header)

        for who in [src] + header.targets:
            peer = self._peer(who)
            if self.suite == "v1":
                # F8: every target gets the IDENTICAL key -- intentional,
                # faithful to the paper.
                key_for_who = k_dist
                payload = pack([key_for_who, hdr_b, t_g])
                blob, tag = v1_protect(peer.auth_key, payload)
                msg = pack([blob, tag])
            else:
                # fix for F8: per-recipient derived key. The server derives
                # the same per-ECU key independently at send time (see
                # server.py), so no extra round trip is needed.
                key_for_who = k_dist if who == src else \
                    hkdf(k_dist, b"ligsecota/v2/distribution-key:" + who.encode())
                payload = pack([key_for_who, hdr_b, t_g])
                ct, nonce = v2_protect(peer.auth_key, payload,
                                       aad=b"authz-grant:" + who.encode(),
                                       counter=peer.next_nonce())
                msg = pack([ct, nonce])
            peer.k_dist = key_for_who
            peer.expected_header = header
            log(self.name or "gateway", "AUTHZ_GRANT_PROTECTED", recipient=who, protection="AES-CBC + HMAC-MD5 under recipient K_auth", carries="K_dist + update header + gateway timestamp", distribution_key_fingerprint=fp(key_for_who))
            self.bus.send(self.name, who, MT.AUTHZ_GRANT, msg)

    def _on_status(self, src, body):
        status, = unpack(body)
        log(self.name or "gateway", "ECU_STATUS", ecu=src, status=status.decode(errors="replace"))
        if status != b"success":
            self.alarms.append(("status", src, status))
        # In the distributed demonstration the cloud server also receives the
        # ECU's result through the gateway. The original in-process harness is
        # unchanged unless its bus explicitly enables this option.
        if getattr(self.bus, "forward_status_to_server", False):
            self.bus.send(self.name, "server", MT.STATUS,
                          pack([src.encode(), status]))
            self.status_forwarded = True
