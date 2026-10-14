"""
A simulated network (Handbook 14.1). Every message between nodes passes
through here, so this is the single place an attacker policy needs to
hook to get full Dolev-Yao control: read everything, drop, tamper, or
inject (Handbook 11.1). Replays are done by scenarios pulling a raw
message straight out of the journal and calling `inject`.
"""
from collections import namedtuple

Msg = namedtuple("Msg", "src dst mtype body")


class Bus:
    def __init__(self):
        self.nodes = {}
        self.journal = []
        self.policy = None   # callable(src,dst,mtype,body,journal) -> action

    def register(self, name, node):
        self.nodes[name] = node
        node.bus = self
        node.name = name

    def send(self, src, dst, mtype, body):
        self.journal.append(Msg(src, dst, mtype, body))
        action = ("forward",)
        if self.policy is not None:
            action = self.policy(src, dst, mtype, body, self.journal) \
                or ("forward",)
        if action[0] == "drop":
            return
        if action[0] == "tamper":
            body = action[1]
        self.nodes[dst].receive(src, mtype, body)

    def inject(self, dst, mtype, body, src="attacker"):
        """Deliver a message the attacker manufactured or replayed,
        bypassing the normal sender entirely."""
        self.nodes[dst].receive(src, mtype, body)

    def reset_policy(self):
        self.policy = None
