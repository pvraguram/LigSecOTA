# LigSecOTA V1 — Two-Computer Demonstration

This adds a **V1-only distributed demo** to the existing reference implementation:

- **Your laptop:** cloud OTA server.
- **Friend's Ubuntu VM:** vehicle gateway and one ECU (`ecu1`).
- **Network:** one TCP connection over a trusted local network.
- **Protocol:** existing V1 authentication, authorization, AES-CBC + HMAC-MD5 package protection, and simulated installation.

The V1 local reference implementation remains in the project. The distributed demo does not run the V2 suite or attack harness. The ECU payload is a harmless text file, not executable firmware. CAN-FD and bit-time fingerprinting are not implemented as physical hardware in this demo.

## 0. Requirements

- Python 3.10 or newer on both machines.
- Your laptop and the VM must be able to reach each other over the same trusted LAN, or through a deliberate port-forwarding configuration.
- Keep both machines' clocks synchronized; V1 rejects timestamps outside its 5-second freshness window.
- Allow TCP port `8765` on your laptop's local firewall for the trusted LAN only. Do **not** expose it to the public internet.

## 1. Get the code onto both machines

Extract the same project ZIP on both machines. Open a terminal in the extracted `ligsecota` project directory.

### On both machines (Linux / Ubuntu)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows, use `.venv\\Scripts\\Activate.ps1` to activate the environment.

## 2. Generate the V1 identities — on your laptop only

Run this **once** from the project root on your laptop:

```bash
python -m tools.provision --out provisioning_out
```

This creates:

- `provisioning_out/server.json` — the server's private key and certificate.
- `provisioning_out/vehicle.json` — the gateway and ECU private keys and certificates.

The CA private key is not distributed. The generated identity files contain private keys, so do not upload them publicly or commit them to source control. Keep `server.json` on your laptop and securely copy **only** `vehicle.json` to your friend's Ubuntu VM. Do not run provisioning independently on each machine.

## 3. Find your laptop's LAN IP

On your laptop, run:

```bash
ip -br addr
```

Use the LAN address for the interface connected to your Wi-Fi/Ethernet network (often something like `192.168.x.x` or `10.x.x.x`). Do not use `127.0.0.1`; that address only refers to the same machine.

From the friend's VM, test basic reachability with `ping YOUR_LAPTOP_LAN_IP` if ICMP is permitted. Ping success alone does not prove that TCP port 8765 is reachable.

## 4. Start the server — your laptop

From the project root, with the virtual environment activated:

```bash
python -m distributed.server_main --identity provisioning_out/server.json --bind 0.0.0.0 --port 8765
```

Leave this terminal open. It waits for the vehicle VM to connect.

If your firewall is enabled, allow inbound TCP port 8765 from your trusted local network only. For example, review your firewall rules rather than disabling the firewall entirely.

## 5. Start the vehicle — friend's Ubuntu VM

Place `vehicle.json` in the VM (for example, in the project root). From the project root, with its virtual environment activated, run:

```bash
python -m distributed.vehicle_main --identity vehicle.json --server-ip YOUR_LAPTOP_LAN_IP --port 8765
```

Replace `YOUR_LAPTOP_LAN_IP` with the real LAN IP from step 3. Start the server first, then the vehicle process. The server demo accepts one vehicle connection per run; restart the server process before another run.

## 6. Expected result

Your laptop should show the server/gateway authentication, authorization grant, package send, and final status, ending with output similar to:

```text
RESULT: installed_version=1 status=success
```

The VM should show local gateway/ECU authentication and end with:

```text
installed_version=1
status=success
```

The exact byte counts and timings can differ.

## What this demonstrates (and what it does not)

It demonstrates the normal V1 update flow across two computers: server/gateway authentication, gateway/ECU authentication, authorization, protected package transfer, package verification, and simulated installation. It does not demonstrate real cloud hosting, physical CAN-FD, a physical ECU, actual oscillator fingerprint measurements, or production-grade network security. The TCP transport is intended for a trusted LAN classroom demo; V1's own cryptographic design has known limitations described in the original handbook.

## Troubleshooting

- **Connection refused / timeout:** check the server is running, the IP is correct, and TCP 8765 is permitted by the laptop firewall and VM network mode.
- **Authentication times out:** ensure the vehicle process is connected and both machines' clocks are synchronized.
- **Stale timestamp error:** synchronize the clocks on both operating systems/VM and rerun.
- **Identity/certificate error:** regenerate both identity files together using the provisioning command, then copy each matching file to its correct machine. Do not combine files from different provisioning runs.
- **Run the correct entry points:** use `python -m distributed.server_main` and `python -m distributed.vehicle_main` from the project root. The old `python run_demo.py` is a local comparison/benchmark entry point and is not the two-computer demo.

DEMO AUDIT OUTPUT
The updated build prints timestamped stage logs, message types and byte counts for TCP frames, certificate subject/serial/fingerprint, cryptographic algorithm names, firmware size/SHA-256, and short SHA-256 fingerprints for K_auth/K_dist. It deliberately NEVER prints raw private keys or raw session/distribution keys. In V1, K_auth is transported as RSA-OAEP/SHA-256-protected material and signed using RSA-PKCS1v1.5/SHA-256; AUTHZ_GRANT carries K_dist under AES-CBC + HMAC-MD5 protection; the firmware package uses AES-CBC + HMAC-MD5 with K_dist. This remains a demonstration implementation, not a production-secure transport.
