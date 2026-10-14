"""
ECU -- the update target. Stage 2 reception and Stage 3 installation
(Handbook 4.3-4.4 / Figure 4.3-4.4 / Figure 13.6, 17.1).

v1 freshness: a timestamp inside the encrypted payload, checked against
DELTA_T_MS (Finding F2 -- replayable inside the window, needs synchronised
clocks).
v2 freshness: a monotonic per-ECU counter standing in for a fuse-backed
anti-rollback register (Handbook 7.5) -- an old `sec_version` is refused
permanently, independent of any clock.
"""
from common.crypto import (v1_protect, v1_unprotect, v2_unprotect,
                           MonotonicCounter, IntegrityError,
                           PaddingOracleError)
from common.protocol import ProtocolNode, DELTA_T_MS
from common.wire import MT, pack, unpack, ProtocolError, ts_from, Header
from common.audit import log, fp, key_label


class ECU(ProtocolNode):
    def __init__(self, ca, suite="v1", fingerprint=None):
        super().__init__(ca, suite=suite, fingerprint=fingerprint)
        self.k_dist = None
        self.expected_header = None
        self.gateway_name = None
        self.installed_version = None
        self.installed_sec_version = None
        self.secure_boot_ok = True            # flip False to test rollback
        self.rollback_counter = MonotonicCounter()   # fuse stand-in
        self.last_status = None

    def on_other_message(self, src, mtype, body):
        if mtype == MT.AUTHZ_GRANT:
            return self._on_authz_grant(src, body)
        if mtype == MT.PKG:
            return self._on_package(src, body)
        raise ProtocolError(f"ecu: unexpected message type {mtype}")

    def _on_authz_grant(self, src, body):
        p = self._peer(src)      # src == gateway name
        self.gateway_name = src
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
        self.k_dist = k_dist
        self.expected_header = Header.decode(hdr_b)
        log(self.name or "ecu", "AUTHZ_GRANT_ACCEPTED", gateway=src, decision="authorized", product=self.expected_header.product, targets=self.expected_header.targets, version=self.expected_header.version, distribution_key="K_dist received inside AES-CBC + HMAC-MD5 protected grant", key_details=key_label(k_dist), raw_key="NOT logged")

    def _on_package(self, src, body):
        if self.k_dist is None:
            raise ProtocolError("package received before authorization")

        if self.suite == "v1":
            blob, tag = unpack(body)
            # PaddingOracleError and IntegrityError are DIFFERENT exception
            # types in v1 -- that distinguishability is Finding F4/A5. A
            # production system must collapse these into one response; this
            # reference implementation deliberately does not, so the
            # attacker harness can demonstrate the oracle.
            log(self.name or "ecu", "PACKAGE_RECEIVED", sender=src, protected_body_bytes=len(body), protection="AES-CBC + HMAC-MD5", key="K_dist", key_fingerprint=fp(self.k_dist))
            pt = v1_unprotect(self.k_dist, blob, tag)
            log(self.name or "ecu", "PACKAGE_INTEGRITY_VERIFIED", algorithm="HMAC-MD5 (V1)", result="valid; ciphertext decrypted with AES-CBC")
            pkt, hdr_b, t_s_b = unpack(pt)
            if Header.decode(hdr_b) != self.expected_header:
                raise ProtocolError("version mismatch")
            if abs(self.now() - ts_from(t_s_b)) >= DELTA_T_MS:
                raise ProtocolError("stale package")
        else:
            ct, nonce, aad = unpack(body)
            aad_fields = unpack(aad)
            hdr_b = aad_fields[-1]
            if Header.decode(hdr_b) != self.expected_header:
                raise ProtocolError("version mismatch")
            # ONE call: tag (covering ciphertext + aad) verified before a
            # single plaintext byte is returned. No padding oracle can
            # exist here (Handbook 17.3).
            try:
                pkt = v2_unprotect(self.k_dist, ct, aad=aad, nonce=nonce)
            except IntegrityError:
                raise ProtocolError("package rejected")  # uniform failure

            # anti-rollback: a permanent high-water mark, not a time window
            if self.expected_header.sec_version < self.rollback_counter.read(self.name):
                raise ProtocolError("package rejected")  # same message as above

        log(self.name or "ecu", "PACKAGE_METADATA_VERIFIED", firmware_bytes=len(pkt), firmware_sha256=fp(pkt, 64), product=self.expected_header.product, version=self.expected_header.version, target=self.name, timestamp="freshness check passed")
        self._install(pkt, self.expected_header)

    def _install(self, firmware: bytes, header: Header):
        self._staged = firmware
        log(self.name or "ecu", "INSTALL_START", destination="simulated ECU firmware slot", bytes=len(firmware), version=header.version, physical_flash="NO — simulation only")
        if self.secure_boot_ok:
            self.installed_version = header.version
            self.installed_sec_version = header.sec_version
            if self.suite == "v2":
                self.rollback_counter.bump(self.name, header.sec_version)
            self.last_status = "success"
            log(self.name or "ecu", "INSTALL_COMPLETE", result="success", installed_version=self.installed_version, firmware_sha256=fp(firmware, 64))
        else:
            self.last_status = "failure"   # rollback to previous slot
        if self.gateway_name and self.bus:
            self.bus.send(self.name, self.gateway_name, MT.STATUS,
                          pack([self.last_status.encode()]))
