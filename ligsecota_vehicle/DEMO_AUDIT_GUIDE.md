# LigSecOTA V1 — Verbose Demonstration / Audit Guide

This build adds timestamped console events to make the normal V1 workflow observable. It does not change the protocol decisions or add attack scenarios.

## What the output proves

- `TCP_CONNECTED`: the vehicle process established a TCP connection to the server laptop.
- `TCP FRAME`: the actual application frame was sent or received; logs include sender, receiver, protocol message type and byte counts.
- `CERT_RECEIVED` / `CERT_VERIFIED`: a certificate was received and its CA signature/validity checks passed.
- `KEY_TRANSPORT`: the V1 responder created a random 256-bit `K_auth`, wrapped the timestamp and key for the initiator using RSA-OAEP with SHA-256, and signed `K_auth` using RSA-PKCS#1 v1.5 with SHA-256.
- `AUTH_KEY_READY`: the recipient decrypted and verified the key. The SHA-256 fingerprint should match on both ends of the same authenticated pair.
- `DISTRIBUTION_KEY_CREATED`: the gateway created a random 256-bit `K_dist` after authorizing the requested update.
- `AUTHZ_GRANT_PROTECTED` / `AUTHZ_GRANT_ACCEPTED`: the gateway delivered `K_dist`, the update header and a timestamp to the server and ECU, protected with each recipient's `K_auth` using the V1 AES-CBC + HMAC-MD5 construction. The `K_dist` fingerprint should match at the gateway, server and ECU.
- `FIRMWARE_LOADED` / `PACKAGE_SENT` / `PACKAGE_RECEIVED`: show firmware byte count and SHA-256 fingerprint. The fingerprint logged after decryption by the ECU should match the one logged by the server.
- `PACKAGE_INTEGRITY_VERIFIED`: the ECU's V1 AES-CBC/HMAC-MD5 verification completed.
- `INSTALL_COMPLETE`: the ECU software model recorded the version as installed and returned a status.

## V1 cryptography shown by this implementation

| Operation | V1 implementation |
|---|---|
| Node identity public/private keys | RSA-2048 |
| Authentication key transport | RSA-OAEP with SHA-256 |
| Signature over `K_auth` | RSA-PKCS#1 v1.5 with SHA-256 |
| Authentication confirmation and protected protocol messages | AES-CBC + HMAC-MD5 |
| Distribution key | Random 256-bit `K_dist`, shared across recipients in V1 |
| Firmware package protection | AES-CBC + HMAC-MD5 under `K_dist` |
| Update metadata | Product, target ECU, version and timestamp inside the protected payload |

## Key-logging safety

The demo prints key lengths and truncated SHA-256 fingerprints only. It deliberately does **not** print raw private keys, raw `K_auth`, or raw `K_dist`. This still lets the presenter show that both endpoints have matching key material without exposing secrets in screenshots or terminal recordings.

## Data path

- Server ↔ gateway protocol messages cross the LAN TCP connection.
- The firmware package is routed over that same TCP connection directly to the logical `ecu1` endpoint in this distributed demo after gateway authorization.
- Gateway ↔ ECU authentication and status messages are delivered locally between software objects inside the VM; they are not sent over physical CAN/CAN-FD.
- Firmware installation is simulated. No physical ECU is flashed.

## Security caveat

These algorithm labels describe the V1 implementation being demonstrated, not a recommendation for new production systems. AES-CBC + HMAC-MD5 and the reference protocol's key-sharing choices retain known limitations; do not expose this demo service to the public internet.
