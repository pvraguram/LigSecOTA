#!/usr/bin/env python3
"""Generate one CA and role-specific V1 identities for the two laptops.

Run once on the server laptop. Share server.json only with the server runtime
and vehicle.json only with the friend's Ubuntu VM. Never regenerate one side
independently; both files must come from the same run.
"""
import argparse
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from common.certs import CA, certificate_to_dict
from common.identity import Node


def private_pem(priv):
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode("ascii")


def public_pem(pub):
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def identity_record(node, name):
    cert = node.enroll(name)
    return {
        "name": name,
        "private_key_pem": private_pem(node.priv),
        "certificate": certificate_to_dict(cert),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="provisioning_out",
                        help="output directory (default: provisioning_out)")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if (out / "server.json").exists() or (out / "vehicle.json").exists():
        parser.error(f"{out} already contains identity files; choose a new empty directory")

    ca = CA(suite="v1")
    ca_pem = public_pem(ca.pub)
    server = Node(ca, suite="v1")
    gateway = Node(ca, suite="v1")
    ecu = Node(ca, suite="v1")

    server_doc = {
        "role": "server",
        "suite": "v1",
        "ca_public_key_pem": ca_pem,
        "identity": identity_record(server, "server"),
    }
    vehicle_doc = {
        "role": "vehicle",
        "suite": "v1",
        "ca_public_key_pem": ca_pem,
        "identities": {
            "gateway": identity_record(gateway, "gateway"),
            "ecu1": identity_record(ecu, "ecu1"),
        },
    }
    for filename, data in (("server.json", server_doc),
                           ("vehicle.json", vehicle_doc)):
        path = out / filename
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    print(f"Created {out / 'server.json'}")
    print(f"Created {out / 'vehicle.json'}")
    print("Copy server.json to the server laptop only.")
    print("Copy vehicle.json to the friend's Ubuntu VM only.")
    print("These files contain private keys. Do not upload them publicly.")


if __name__ == "__main__":
    main()
