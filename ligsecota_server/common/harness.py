"""
Builds a complete {server, gateway, ECU...} deployment for one suite and
drives a full update through all three stages (Handbook 13.8, 14.1).
"""
from common.bus import Bus
from common.certs import CA
from common.wire import Header
from nodes.server import Server
from nodes.gateway import Gateway
from nodes.ecu import ECU


class Deployment:
    def __init__(self, suite="v1", ecu_names=("ecu1",), fingerprints=None):
        self.suite = suite
        self.bus = Bus()
        self.ca = CA(suite=suite)

        self.server = Server(self.ca, suite=suite)
        self.gateway = Gateway(self.ca, suite=suite)
        self.ecus = {}
        fingerprints = fingerprints or {}
        for name in ecu_names:
            self.ecus[name] = ECU(self.ca, suite=suite,
                                  fingerprint=fingerprints.get(name))

        self.bus.register("server", self.server)
        self.bus.register("gateway", self.gateway)
        for name, ecu in self.ecus.items():
            self.bus.register(name, ecu)

        self.server.enroll("server")
        self.gateway.enroll("gateway")
        for name, ecu in self.ecus.items():
            ecu.enroll(name)

    def authenticate_all(self):
        self.server.start_authentication("gateway")
        for name in self.ecus:
            self.gateway.start_authentication(name)

    def run_full_update(self, version=1, sec_version=None, targets=None,
                        firmware=b"FIRMWARE-BYTES", product="ecu-fw"):
        targets = targets or list(self.ecus.keys())
        header = Header(version=version, product=product, targets=targets,
                        sec_version=sec_version)
        self.server.request_authorization("gateway", header)
        ts = self.server.now()   # one shared timestamp for the whole
                                 # distribution event -- see server.py's
                                 # distribute_package docstring
        for i, t in enumerate(targets):
            self.server.distribute_package(t, firmware, "gateway", header,
                                           counter=i, ts=ts)
        return header
