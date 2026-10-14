#!/usr/bin/env python3
"""Run the V1 OTA server on the user's laptop."""
import argparse
import socket
import time
from pathlib import Path

from common.provisioning import apply_identity, load_bundle, load_public_only_ca
from common.wire import Header
from distributed.net_transport import ServerNetworkBus
from nodes.server import Server
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
    parser = argparse.ArgumentParser(description="LigSecOTA V1 server laptop")
    parser.add_argument("--identity", default="provisioning_out/server.json")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--version", type=int, default=1)
    parser.add_argument("--firmware", default="firmware/demo_firmware.bin")
    args = parser.parse_args()

    bundle = load_bundle(args.identity)
    if bundle.get("role") != "server" or bundle.get("suite") != "v1":
        raise SystemExit("Expected a V1 server identity bundle from tools/provision.py")
    ca = load_public_only_ca(bundle["ca_public_key_pem"])
    server = apply_identity(Server(ca, suite="v1"), bundle["identity"])

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, args.port))
    listener.listen(1)
    print("\n=== LigSecOTA V1 — CLOUD OTA SERVER ===", flush=True)
    log("SERVER", "CONFIG", suite="V1", bind=f"{args.bind}:{args.port}", firmware_path=args.firmware, target="ecu1", requested_version=args.version)
    log("SERVER", "CRYPTO_PROFILE", authentication="RSA-2048 certificates", key_transport="RSA-OAEP/SHA-256", signatures="RSA-PKCS1v1.5/SHA-256", message_protection="AES-CBC + HMAC-MD5", note="V1 demonstration; raw private/session keys are never printed")
    print(f"Listening on {args.bind}:{args.port}; start vehicle_main.py on the VM now.", flush=True)
    conn, address = listener.accept()
    log("SERVER", "TCP_CONNECTED", peer_ip=address[0], peer_port=address[1], transport="TCP", socket_port=args.port)
    bus = ServerNetworkBus(conn)
    bus.register("server", server)
    bus.start_reader()

    try:
        print("\n[1/5] AUTHENTICATION — server <-> gateway", flush=True)
        server.start_authentication("gateway")
        wait_until(lambda: server._peer("gateway").state == "AUTHENTICATED",
                   "server/gateway authentication", bus=bus)
        log("SERVER", "AUTHENTICATION_COMPLETE", peer="gateway", result="success")

        firmware_path = Path(args.firmware)
        if not firmware_path.is_file():
            raise FileNotFoundError(f"firmware file not found: {firmware_path}")
        firmware = firmware_path.read_bytes()
        log("SERVER", "FIRMWARE_LOADED", file=str(firmware_path), bytes=len(firmware), sha256=fp(firmware, 64), payload_type="demo firmware binary")
        header = Header(version=args.version, product="ecu-fw",
                        targets=["ecu1"])

        print("\n[2/5] AUTHORIZATION — request update permission", flush=True)
        log("SERVER", "UPDATE_METADATA", product=header.product, target_ecus=header.targets, firmware_version=header.version, security_version=header.sec_version, firmware_bytes=len(firmware))
        server.request_authorization("gateway", header)
        wait_until(lambda: "gateway" in server.k_dist and
                            getattr(server, "_pending_header", None) is not None,
                   "authorization grant", bus=bus)
        log("SERVER", "AUTHORIZATION_RESULT", decision="GRANTED", gateway="gateway", distribution_key="K_dist received inside protected AUTHZ_GRANT; raw key not logged")
        log("SERVER", "DISTRIBUTION_KEY_READY", key="K_dist", bits=len(server.k_dist["gateway"])*8, sha256=fp(server.k_dist["gateway"]), raw_key="NOT logged")

        print("\n[3/5] FIRMWARE DISTRIBUTION — server -> ECU (gateway authorized the update)", flush=True)
        log("SERVER", "PACKAGE_PROTECTION", encryption="AES-CBC", integrity="HMAC-MD5", key="K_dist (256-bit)", header="version=1; product=ecu-fw; target=ecu1; timestamp included inside protected payload")
        server.distribute_package("ecu1", firmware, "gateway", header,
                                  counter=0, ts=server.now())
        log("SERVER", "PACKAGE_SENT", firmware_plaintext_bytes=len(firmware), firmware_sha256=fp(firmware, 64), note="TCP frame logs below show encoded protocol message sizes; protected package is larger due to header, timestamp, padding and MAC")

        print("\n[4/5] WAITING FOR ECU STATUS", flush=True)
        wait_until(lambda: "ecu1" in server.statuses,
                   "ECU status", timeout=30.0, bus=bus)
        status = server.statuses["ecu1"]
        log("SERVER", "ECU_STATUS_RECEIVED", ecu="ecu1", status=status)
        if status == "success":
            print(f"RESULT: installed_version={args.version} status=success")
        else:
            raise SystemExit("ECU reported update failure")
    finally:
        bus.close()
        listener.close()


if __name__ == "__main__":
    main()
