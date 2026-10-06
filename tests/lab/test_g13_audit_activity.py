"""G13 modeled risk observations from protected KAG gateway audits."""

from decimal import Decimal
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest

from lab.campaign_bridge import Bridge


FIELDS = ("Kind", "ID", "Binding", "Outcome", "Previous", "Hash", "ReplayID", "UnixNS", "Budget", "SpacingNS")
NOW = 1_800_000_000_000_000_000


def request(replay, actor="agent-1"):
    return dict(binding_digest="a" * 64, operation_digest="b" * 64,
                replay_id=replay, actor_id=actor, tenant_id="lab-tenant",
                operation_id="lab.set_marker")


def status(replay, actor="agent-2"):
    return request(replay, actor) | {"operation_id": "lab.read_status"}


def row(kind, *, previous="", replay="", binding="", outcome="", ident="", now=0, budget=0):
    value = dict.fromkeys(FIELDS, "")
    value.update(Kind=kind, ID=ident, Binding=binding, Outcome=outcome,
                 Previous=previous, ReplayID=replay, UnixNS=now,
                 Budget=budget, SpacingNS=0)
    value["Hash"] = sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()
    return value


def policy():
    return row("policy", binding="audit-v1", budget=1000)


def effect(rows, replay, now):
    binding = "a" * 64
    first = row("audit", previous=rows[-1]["Hash"], replay=replay,
                binding=binding, outcome="pre_dispatch:reserved_rechecked",
                ident=sha256((replay + "pre").encode()).hexdigest()[:32], now=now - 1)
    second = row("audit", previous=first["Hash"], replay=replay,
                 binding=binding, outcome="permit:target_known",
                 ident=sha256((replay + "done").encode()).hexdigest()[:32], now=now)
    rows.extend((first, second))


class G13AuditActivityTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()
        self.audits = (base / "gateway-1.audit", base / "gateway-2.audit")
        self.ledger = base / "decisions.jsonl"
        for path in self.audits:
            self.write(path, [policy()])

    def write(self, path, rows):
        path.write_bytes(b"".join(json.dumps(r, separators=(",", ":")).encode() + b"\n" for r in rows))
        os.chmod(path, 0o600)

    def bridge(self):
        return Bridge(self.ledger, divergence=Decimal("0.249"),
                      divergence_mode="audit-activity", activity_audits=self.audits)

    def test_other_gateway_activity_reduces_even_after_actor_rotation(self):
        bridge = self.bridge()
        self.assertTrue(bridge.decide(status("e" * 32), NOW + 30_000_000_000)["allow"])
        rows = [policy()]
        effect(rows, "e" * 32, NOW + 30_000_000_000)
        self.write(self.audits[1], rows)
        rotated = bridge.decide(request("2" * 32, "agent-1"), NOW + 31_000_000_000)
        self.assertFalse(rotated["allow"])
        self.assertIn("insufficient_charge", rotated["reasons"])
        self.assertEqual(json.loads(self.ledger.read_text().splitlines()[-1])["divergence"], "0.9")

    def test_own_recent_attempt_reduces_without_gateway_success(self):
        bridge = self.bridge()
        self.assertTrue(bridge.decide(request("1" * 32), NOW)["allow"])
        self.assertFalse(bridge.decide(request("2" * 32, "agent-2"), NOW + 1_000_000_000)["allow"])

    def test_own_status_read_does_not_create_a_peer_risk_signal(self):
        bridge = self.bridge()
        self.assertTrue(bridge.decide(status("e" * 32, "agent-1"), NOW)["allow"])
        rows = [policy()]
        effect(rows, "e" * 32, NOW + 1_000_000_000)
        self.write(self.audits[0], rows)
        self.assertTrue(bridge.decide(request("1" * 32), NOW + 2_000_000_000)["allow"])

    def test_delayed_peer_audit_success_is_observed_after_attempt_window(self):
        bridge = self.bridge()
        self.assertTrue(bridge.decide(status("e" * 32), NOW - 300_000_000_000)["allow"])
        rows = [policy()]
        effect(rows, "e" * 32, NOW - 1_000_000_000)
        self.write(self.audits[1], rows)
        self.assertFalse(bridge.decide(request("1" * 32), NOW)["allow"])

    def test_same_replay_keeps_first_signal_after_activity_changes(self):
        bridge = self.bridge()
        first = request("1" * 32)
        self.assertTrue(bridge.decide(first, NOW)["allow"])
        self.assertTrue(bridge.decide(status("e" * 32), NOW + 1_000_000_000)["allow"])
        rows = [policy()]
        effect(rows, "e" * 32, NOW + 1_000_000_000)
        self.write(self.audits[1], rows)
        self.assertTrue(bridge.decide(first, NOW + 2_000_000_000)["allow"])

    def test_missing_corrupt_and_rolled_back_audit_fail_closed(self):
        bridge = self.bridge()
        first = request("1" * 32)
        self.assertTrue(bridge.decide(first, NOW)["allow"])
        self.assertTrue(bridge.decide(status("e" * 32), NOW + 1_000_000_000)["allow"])
        rows = [policy()]
        effect(rows, "e" * 32, NOW + 1_000_000_000)
        self.write(self.audits[1], rows)
        self.assertFalse(bridge.decide(request("2" * 32), NOW + 2_000_000_000)["allow"])
        self.write(self.audits[1], [policy()])
        with self.assertRaises(ValueError):
            bridge.decide(request("3" * 32), NOW + 3_000_000_000)
        self.audits[1].unlink()
        with self.assertRaises(OSError):
            bridge.decide(first, NOW + 4_000_000_000)

    def test_partial_audit_never_returns_permit(self):
        self.audits[0].write_bytes(self.audits[0].read_bytes()[:-1])
        with self.assertRaises(ValueError):
            self.bridge().decide(request("1" * 32), NOW)

    def test_owner_mode_marker_audit_is_valid_but_earns_no_status_credit(self):
        bridge = self.bridge()
        self.assertTrue(bridge.decide(request("1" * 32), NOW)["allow"])
        rows = [policy()]
        replay = "1" * 32
        reservation = "c" * 32
        owner_policy = "d" * 64
        first = row("audit", previous=rows[-1]["Hash"], replay=replay,
                    binding="a" * 64,
                    outcome="pre_dispatch:reserved_rechecked:" + reservation + ":" + owner_policy,
                    ident="e" * 32, now=NOW + 1_000_000_000)
        rows.append(first)
        rows.append(row("audit", previous=first["Hash"], replay=replay,
                        binding="a" * 64, outcome="permit:target_known",
                        ident="f" * 32, now=NOW + 2_000_000_000))
        self.write(self.audits[0], rows)
        later = bridge.decide(request("2" * 32, "agent-2"), NOW + 35_000_000_000)
        self.assertTrue(later["allow"])
        self.assertEqual(json.loads(self.ledger.read_text().splitlines()[-1])["divergence"], "0.249")

    def test_audit_mode_requires_distinct_absolute_paths(self):
        with self.assertRaises(ValueError):
            Bridge(self.ledger, divergence_mode="audit-activity", activity_audits=())
        with self.assertRaises(ValueError):
            Bridge(self.ledger, divergence_mode="audit-activity", activity_audits=(self.audits[0], self.audits[0]))
        with self.assertRaises(ValueError):
            Bridge(self.ledger, divergence_mode="audit-activity", activity_audits=(Path("relative.audit"),))


if __name__ == "__main__":
    unittest.main()
