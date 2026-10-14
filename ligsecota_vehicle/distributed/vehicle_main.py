#!/usr/bin/env python3
"""Run the vehicle gateway and ECU inside the friend's Ubuntu VM."""
import argparse
import socket
import time

from common.provisioning import apply_identity, load_bundle, load_public_only_ca
from distributed.net_transport import VehicleNetworkBus
from nodes.ecu import ECU
from nodes.gateway import Gateway
from common.audit import log, fp


def wait_until(predicate, description, timeout=20.0, bus=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        if bus is not None and bus.error is not None:
            raise RuntimeError(f"network reader failed: {bus.error}")
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {description}")


def main():
    parser = argparse.ArgumentParser(description="LigSecOTA V1 vehicle VM")
    parser.add_argument("--identity", default="vehicle.json")
    parser.add_argument("--server-ip", required=True,
                        help="LAN IP address of the server laptop")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    bundle = load_bundle(args.identity)
    if bundle.get("role") != "vehicle" or bundle.get("suite") != "v1":
        raise SystemExit("Expected a V1 vehicle identity bundle from tools/provision.py")
    ca = load_public_only_ca(bundle["ca_public_key_pem"])
    identities = bundle["identities"]
    gateway = apply_identity(Gateway(ca, suite="v1"), identities["gateway"])
    ecu = apply_identity(ECU(ca, suite="v1"), identities["ecu1"])

    # First authenticate the local gateway and ECU using the original V1
    # protocol classes. Their messages remain local to the VM.
    bus = None
    print("\n=== LigSecOTA V1 — VEHICLE VM ===", flush=True)
    log("VEHICLE", "CRYPTO_PROFILE", suite="V1", certificates="RSA-2048 public-key certificates", key_transport="RSA-OAEP/SHA-256", signatures="RSA-PKCS1v1.5/SHA-256", message_protection="AES-CBC + HMAC-MD5", private_keys="kept local; never logged")
    print("\n[1/4] AUTHENTICATION — gateway <-> ECU (local VM)", flush=True)
    # Connect before creating the bus, then register both local roles.
    log("VEHICLE", "TCP_CONNECTING", server_ip=args.server_ip, server_port=args.port)
    sock = socket.create_connection((args.server_ip, args.port), timeout=15.0)
    sock.settimeout(None)
    log("VEHICLE", "TCP_CONNECTED", server_ip=args.server_ip, server_port=args.port, transport="TCP", note="actual network connection established")
    bus = VehicleNetworkBus(sock)
    bus.register("gateway", gateway)
    bus.register("ecu1", ecu)
    gateway.start_authentication("ecu1")
    wait_until(lambda: gateway._peer("ecu1").state == "AUTHENTICATED" and
                        ecu._peer("gateway").state == "AUTHENTICATED",
               "gateway/ECU authentication", bus=bus)
    log("VEHICLE", "LOCAL_AUTHENTICATION_COMPLETE", peers="gateway <-> ecu1", result="success")

    bus.start_reader()
    try:
        print("\n[2/4] AUTHENTICATION — cloud server <-> vehicle gateway", flush=True)
        wait_until(lambda: gateway._peer("server").state == "AUTHENTICATED",
                   "server/gateway authentication", timeout=30.0, bus=bus)
        log("VEHICLE", "REMOTE_AUTHENTICATION_COMPLETE", peers="server <-> gateway", result="success")
        print("\n[3/4] AUTHORIZATION + PACKAGE RECEPTION", flush=True)
        wait_until(lambda: ecu.last_status is not None and
                            gateway.status_forwarded,
                   "ECU installation and status forwarding",
                   timeout=60.0, bus=bus)
        print("\n[4/4] INSTALLATION RESULT", flush=True)
        print(f"      installed_version={ecu.installed_version}")
        print(f"      status={ecu.last_status}")
    finally:
        bus.close()


if __name__ == "__main__":
    main()
