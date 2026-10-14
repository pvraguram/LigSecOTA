"""
The installation version manifest (Handbook 4.3, 13.6).

The paper specifies the FIELDS (version, status, timestamp, dependencies)
but never the acceptance RULE. This is our interpretation, stated
explicitly so nobody mistakes it for the paper's own specification:
an update is "reasonable" if it is the first install for that target, or
if its version is strictly greater than what is currently recorded.
"""


class Manifest:
    def __init__(self):
        self.installed = {}   # ecu_id -> {"version": int, "sec_version": int}

    def is_reasonable(self, header) -> bool:
        cur = self.installed.get(tuple(header.targets))
        if cur is None:
            return True
        return header.version > cur["version"]

    def record(self, header):
        self.installed[tuple(header.targets)] = {
            "version": header.version, "sec_version": header.sec_version,
        }
