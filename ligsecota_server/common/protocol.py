"""
Stage 1 -- Authentication (Handbook 4.2 / Figure 4.1), generic across any
pair of nodes, in both suites:

  v1  RSA key transport, exactly Figure 6 of the paper. No forward
      secrecy (Finding F5).
  v2  Signed ephemeral ECDH. Ephemeral private keys are discarded after
      the session, so a later compromise of a long-term signing key does
      not expose past sessions (Handbook 6.7, 17.2).

Both variants end with every pair of nodes sharing a fresh, random
"authorization key" (Kauth) and with each side holding the other's
verified certificate. Stages 2 and 3 live in gateway.py / server.py /
ecu.py because they are genuinely role-specific.
"""
import os

from common.crypto import (v1_protect, v1_unprotect, v1_rsa_wrap,
                           v1_rsa_unwrap, v1_sign, v1_verify,
                           v2_ephemeral, v2_ecdh, hkdf, v2_sign, v2_verify)
from common.certs import load_pubkey, CertError
from common.identity import Node
from common.wire import MT, pack, unpack, ProtocolError, ts_from
from common.audit import log, fp, key_label

DELTA_T_MS = 5000   # the paper never states this value (Handbook 5.5/18);
                     # made explicit and tunable here, see bench/dt_sweep.py


class PeerState:
    def __init__(self):
        self.state = "IDLE"
        self.auth_key = None
        self.k_dist = None
        self.expected_header = None
        self.pkg_counter = 0
        self.peer_cert = None
        self._pending_eph = None     # v2 only, discarded once the
                                      # handshake completes -> forward secrecy
        self._nonce_ctr = 0

    def next_nonce(self):
        """auth_key is long-lived -- it is reused across every AUTHZ_REQ
        and AUTHZ_GRANT for as long as the session lasts, potentially many
        updates. A GCM nonce must never repeat under one key (Handbook
        6.4), so every v2_protect call keyed by auth_key MUST draw its
        counter from here rather than hardcoding 0. (An earlier draft of
        this reference implementation hardcoded 0 at every call site --
        a real nonce-reuse bug, found by running A3/A7 and seeing k_dist
        from two different updates get authenticated under colliding
        nonces. Left as a cautionary comment rather than erased.)"""
        n = self._nonce_ctr
        self._nonce_ctr += 1
        return n


class ProtocolNode(Node):
    def __init__(self, ca, suite="v1", fingerprint=None,
                 check_revocation=None):
        super().__init__(ca, suite=suite, fingerprint=fingerprint)
        self.peers = {}
        # F6: v1 never checks revocation even if a CRL exists; v2 does.
        self.check_revocation = (suite == "v2") if check_revocation is None \
            else check_revocation

    def _peer(self, name):
        return self.peers.setdefault(name, PeerState())

    # ----------------------------------------------------------- initiate
    def start_authentication(self, peer_name):
        p = self._peer(peer_name)
        # Set the state before sending. In an in-process bus, send() can
        # synchronously deliver AUTH_RESP/AUTH_CONF before it returns; setting
        # AUTH_SENT afterward would overwrite the completed state.
        p.state = "AUTH_SENT"
        if self.suite == "v1":
            cert = self.cert_bytes()
            log(self.name, "AUTH_START", peer=peer_name, suite="V1", certificate_bytes=len(cert), certificate_sha256=fp(cert), certificate="CA-signed RSA-2048 public key")
            self.bus.send(self.name, peer_name, MT.AUTH_REQ, pack([cert]))
        else:
            eph_priv, eph_pub = v2_ephemeral()
            p._pending_eph = eph_priv
            from cryptography.hazmat.primitives import serialization
            eph_pub_b = eph_pub.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint)
            sig = v2_sign(self.priv, eph_pub_b)
            self.bus.send(self.name, peer_name, MT.AUTH_REQ,
                          pack([self.cert_bytes(), eph_pub_b, sig]))

    # ----------------------------------------------------------- dispatch
    def receive(self, src, mtype, body):
        handler = {
            MT.AUTH_REQ: self._on_auth_req,
            MT.AUTH_RESP: self._on_auth_resp,
            MT.AUTH_CONF: self._on_auth_conf,
        }.get(mtype)
        if handler is None:
            return self.on_other_message(src, mtype, body)
        handler(src, body)

    def on_other_message(self, src, mtype, body):
        """Stage 2/3 messages. Overridden by Gateway/Server/ECU."""
        raise ProtocolError(f"{self.name}: unhandled message type {mtype}")

    # ----------------------------------------------------------- v1 + v2
    def _verify_peer_cert(self, cert_bytes):
        cert = Node.load_cert(cert_bytes)
        log(self.name or "node", "CERT_RECEIVED", subject=cert.subject, serial=cert.serial, certificate_bytes=len(cert_bytes), certificate_sha256=fp(cert_bytes), public_key="RSA-2048 (V1)")
        self.ca.verify(cert, check_revocation=self.check_revocation)
        log(self.name or "node", "CERT_VERIFIED", subject=cert.subject, result="valid CA signature and validity checks passed", revocation_check=self.check_revocation)
        return cert

    def _on_auth_req(self, src, body):
        p = self._peer(src)
        if self.suite == "v1":
            cert_b, = unpack(body)
            peer_cert = self._verify_peer_cert(cert_b)
            p.peer_cert = peer_cert
            peer_pub = load_pubkey(peer_cert)

            t = self.now()
            k_auth = os.urandom(32)
            log(self.name, "AUTH_KEY_CREATED", peer=src, key="K_auth", details=key_label(k_auth), raw_key="NOT logged")
            cipher = v1_rsa_wrap(peer_pub, pack([t, k_auth]))
            log(self.name, "KEY_TRANSPORT", peer=src, algorithm="RSA-OAEP with SHA-256", plaintext_fields="timestamp + 256-bit K_auth", encrypted_blob_bytes=len(cipher), recipient_public_key="RSA-2048")
            sig = v1_sign(self.priv, k_auth)
            log(self.name, "KEY_SIGNATURE_CREATED", algorithm="RSA-PKCS1v1.5 + SHA-256", signed_data="K_auth", signature_bytes=len(sig))
            p.auth_key = k_auth
            p.state = "AWAITING_CONF"
            self.bus.send(self.name, src, MT.AUTH_RESP,
                          pack([cipher, sig, self.cert_bytes()]))
        else:
            cert_b, eph_pub_b, sig = unpack(body)
            peer_cert = self._verify_peer_cert(cert_b)
            p.peer_cert = peer_cert
            peer_longterm_pub = load_pubkey(peer_cert)
            v2_verify(peer_longterm_pub, sig, eph_pub_b)

            from cryptography.hazmat.primitives.asymmetric import ec
            peer_eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), eph_pub_b)

            eph_priv, eph_pub = v2_ephemeral()
            from cryptography.hazmat.primitives import serialization
            my_eph_pub_b = eph_pub.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint)
            my_sig = v2_sign(self.priv, my_eph_pub_b + eph_pub_b)

            shared = v2_ecdh(eph_priv, peer_eph_pub)
            k_auth = hkdf(shared, b"ligsecota/v2/authorization-key:" +
                          self.name.encode() + b":" + src.encode())
            del eph_priv     # forward secrecy: nothing left to recover it

            p.auth_key = k_auth
            p.state = "AWAITING_CONF"
            self.bus.send(self.name, src, MT.AUTH_RESP,
                          pack([self.cert_bytes(), my_eph_pub_b, my_sig]))

    def _on_auth_resp(self, src, body):
        p = self._peer(src)
        if self.suite == "v1":
            cipher, sig, cert_g = unpack(body)
            peer_cert = self._verify_peer_cert(cert_g)
            p.peer_cert = peer_cert
            peer_pub = load_pubkey(peer_cert)

            unwrapped = v1_rsa_unwrap(self.priv, cipher)
            t_b, k_auth = unpack(unwrapped)
            log(self.name, "KEY_TRANSPORT_DECRYPTED", peer=src, algorithm="RSA-OAEP with SHA-256", result="timestamp and K_auth recovered with recipient private key", encrypted_blob_bytes=len(cipher))
            if abs(self.now() - ts_from(t_b)) >= DELTA_T_MS:
                raise ProtocolError("stale AUTH_RESP")
            v1_verify(peer_pub, sig, k_auth)
            log(self.name, "KEY_SIGNATURE_VERIFIED", peer=src, algorithm="RSA-PKCS1v1.5 + SHA-256", result="valid")
            p.auth_key = k_auth
            log(self.name, "AUTH_KEY_READY", peer=src, key="K_auth", details=key_label(k_auth), raw_key="NOT logged")

            blob, tag = v1_protect(k_auth, self.now().to_bytes(8, "big"))
            log(self.name, "AUTH_CONFIRM_PROTECTED", peer=src, encryption="AES-CBC", integrity="HMAC-MD5 (V1 design)", ciphertext_bytes=len(blob), mac_bytes=len(tag))
            self.bus.send(self.name, src, MT.AUTH_CONF, pack([blob, tag]))
        else:
            cert_g, eph_pub_b, sig = unpack(body)
            peer_cert = self._verify_peer_cert(cert_g)
            p.peer_cert = peer_cert
            peer_longterm_pub = load_pubkey(peer_cert)

            from cryptography.hazmat.primitives import serialization
            my_eph_pub_b = p._pending_eph.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint)
            v2_verify(peer_longterm_pub, sig, eph_pub_b + my_eph_pub_b)

            from cryptography.hazmat.primitives.asymmetric import ec
            peer_eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), eph_pub_b)
            shared = v2_ecdh(p._pending_eph, peer_eph_pub)
            k_auth = hkdf(shared, b"ligsecota/v2/authorization-key:" +
                          src.encode() + b":" + self.name.encode())
            del p._pending_eph      # forward secrecy

            p.auth_key = k_auth
            from common.crypto import v2_protect
            ct, nonce = v2_protect(k_auth, self.now().to_bytes(8, "big"),
                                   aad=b"auth-confirm", counter=p.next_nonce())
            self.bus.send(self.name, src, MT.AUTH_CONF, pack([ct, nonce]))

        p.state = "AUTHENTICATED"
        self.on_authenticated(src)

    def _on_auth_conf(self, src, body):
        p = self._peer(src)
        if self.suite == "v1":
            blob, tag = unpack(body)
            pt = v1_unprotect(p.auth_key, blob, tag)
            log(self.name, "AUTH_CONFIRM_VERIFIED", peer=src, encryption="AES-CBC", integrity="HMAC-MD5", result="valid")
            if abs(self.now() - ts_from(pt)) >= DELTA_T_MS:
                raise ProtocolError("stale AUTH_CONF")
        else:
            ct, nonce = unpack(body)
            from common.crypto import v2_unprotect
            pt = v2_unprotect(p.auth_key, ct, aad=b"auth-confirm", nonce=nonce)
            if abs(self.now() - ts_from(pt)) >= DELTA_T_MS:
                raise ProtocolError("stale AUTH_CONF")
        p.state = "AUTHENTICATED"
        self.on_authenticated(src)

    def on_authenticated(self, peer_name):
        """Hook for subclasses; default does nothing."""
        pass
