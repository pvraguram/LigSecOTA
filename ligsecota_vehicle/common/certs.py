"""
A minimal one-machine-one-certificate CA (Handbook Chapter 3 / 8).

Certificates are simplified to a signed dict rather than full X.509, so
the protocol logic stays readable; the OpenSSL commands for a real X.509v3
certificate with a fingerprint extension are in Handbook Appendix B.1.
What matters for the protocol -- subject identity, public key, a validity
period, a CA signature, and (for the ECU) the bit-time fingerprint that
was supposedly bound at enrolment -- is all present.
"""
import json
import time

from common.crypto import v1_sign, v1_verify, v2_sign, v2_verify
from common.wire import ProtocolError


class CertError(ProtocolError):
    pass


def _pub_bytes(pub, suite):
    from cryptography.hazmat.primitives import serialization
    if suite == "v1":
        return pub.public_bytes(serialization.Encoding.DER,
                                 serialization.PublicFormat.SubjectPublicKeyInfo)
    return pub.public_bytes(serialization.Encoding.Raw,
                             serialization.PublicFormat.Raw)


class Certificate:
    def __init__(self, subject, pub_bytes, fingerprint, not_after, serial, sig,
                 suite):
        self.subject = subject
        self.pub_bytes = pub_bytes
        self.fingerprint = fingerprint       # None for non-ECU subjects
        self.not_after = not_after
        self.serial = serial
        self.sig = sig
        self.suite = suite

    def tbs(self):
        """'To be signed' bytes -- everything except the signature."""
        return json.dumps({
            "subject": self.subject,
            "pub": self.pub_bytes.hex(),
            "fingerprint": self.fingerprint,
            "not_after": self.not_after,
            "serial": self.serial,
        }, sort_keys=True).encode()


def certificate_to_dict(cert: Certificate):
    """JSON-safe representation used for provisioning and network transfer."""
    return {
        "subject": cert.subject,
        "pub_bytes": cert.pub_bytes.hex(),
        "fingerprint": cert.fingerprint,
        "not_after": cert.not_after,
        "serial": cert.serial,
        "sig": cert.sig.hex(),
        "suite": cert.suite,
    }


def certificate_from_dict(data):
    return Certificate(
        subject=data["subject"],
        pub_bytes=bytes.fromhex(data["pub_bytes"]),
        fingerprint=data.get("fingerprint"),
        not_after=float(data["not_after"]),
        serial=int(data["serial"]),
        sig=bytes.fromhex(data["sig"]),
        suite=data["suite"],
    )


class CA:
    def __init__(self, suite="v1"):
        self.suite = suite
        if suite == "v1":
            from common.crypto import v1_keypair
            self.priv, self.pub = v1_keypair(bits=2048)
        else:
            from common.crypto import v2_keypair
            self.priv, self.pub = v2_keypair()
        self._serial = 0
        self.revoked = set()          # v2 checks this; v1 never does

    def issue(self, subject, pub, fingerprint=None, days=3650):
        self._serial += 1
        cert = Certificate(
            subject=subject, pub_bytes=_pub_bytes(pub, self.suite),
            fingerprint=fingerprint,
            not_after=time.time() + days * 86400,
            serial=self._serial, sig=None, suite=self.suite)
        sign = v1_sign if self.suite == "v1" else v2_sign
        cert.sig = sign(self.priv, cert.tbs())
        return cert

    def revoke(self, serial):
        self.revoked.add(serial)

    def verify(self, cert: Certificate, check_revocation=False):
        verify = v1_verify if self.suite == "v1" else v2_verify
        try:
            verify(self.pub, cert.sig, cert.tbs())
        except Exception as e:
            raise CertError(f"bad certificate signature: {e}") from e
        if time.time() > cert.not_after:
            raise CertError("certificate expired")
        # --- F6: the paper claims revocation but never checks it. v1
        # intentionally skips this even when a CRL exists; v2 enforces it.
        if check_revocation and cert.serial in self.revoked:
            raise CertError("certificate revoked")
        return cert


def load_pubkey(cert: Certificate):
    """Reconstruct a usable public-key object from the stored bytes."""
    if cert.suite == "v1":
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        return load_der_public_key(cert.pub_bytes)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PublicKey
    return Ed25519PublicKey.from_public_bytes(cert.pub_bytes)
