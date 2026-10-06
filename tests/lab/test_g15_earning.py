from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest

from lab.g15_earning import read_earned_receipts
from lab.campaign_bridge import Bridge


FIELDS = ("Kind", "ID", "Binding", "Outcome", "Previous", "Hash", "ReplayID", "UnixNS", "Budget", "SpacingNS")


def row(kind, *, previous="", replay="", binding="", outcome="", ident="", now=0, budget=0):
    value = dict.fromkeys(FIELDS, "")
    value.update(Kind=kind, ID=ident, Binding=binding, Outcome=outcome,
                 Previous=previous, ReplayID=replay, UnixNS=now,
                 Budget=budget, SpacingNS=0)
    wire = json.dumps(value, separators=(",", ":")).encode()
    value["Hash"] = sha256(wire).hexdigest()
    return value


def audit_rows(replay="a" * 32, binding="b" * 64):
    first = row("policy", binding="audit-v1", budget=1000)
    second = row("audit", previous=first["Hash"], replay=replay, binding=binding,
                 outcome="pre_dispatch:reserved_rechecked", ident="c" * 32, now=1)
    third = row("audit", previous=second["Hash"], replay=replay, binding=binding,
                outcome="permit:target_known", ident="d" * 32, now=2)
    return [first, second, third]


class G15EarningTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.audit = Path(self.temp.name) / "gateway.jsonl.audit"
        self.replay = "a" * 32
        self.binding = "b" * 64
        self.decision = dict(replay_id=self.replay, binding_digest=self.binding,
                             actor_id="agent-1", operation_id="lab.read_status", allow=True)

    def write(self, rows):
        self.audit.write_bytes(b"".join(json.dumps(r, separators=(",", ":")).encode() + b"\n" for r in rows))
        os.chmod(self.audit, 0o600)

    def test_only_attributable_completed_status_read_earns(self):
        self.write(audit_rows())
        earned = read_earned_receipts(self.audit, [self.decision, self.decision])
        self.assertEqual(len(earned["agent-1"]), 1)
        self.assertEqual(earned.get("agent-2", ()), ())
        self.assertEqual(earned["agent-1"][0].replay_id, self.replay)

    def test_attempt_without_known_outcome_does_not_earn(self):
        self.write(audit_rows()[:2])
        self.assertEqual(read_earned_receipts(self.audit, [self.decision]), {})

    def test_unknown_outcome_does_not_earn(self):
        rows = audit_rows()
        rows[-1] = row("audit", previous=rows[-2]["Hash"], replay=self.replay,
                       binding=self.binding, outcome="unknown:target_outcome_unknown",
                       ident="d" * 32, now=2)
        self.write(rows)
        self.assertEqual(read_earned_receipts(self.audit, [self.decision]), {})

    def test_unknown_followed_by_permit_is_conflicting_evidence(self):
        rows = audit_rows()[:2]
        unknown = row("audit", previous=rows[-1]["Hash"], replay=self.replay,
                      binding=self.binding, outcome="unknown:target_outcome_unknown",
                      ident="d" * 32, now=2)
        rows.append(unknown)
        rows.append(row("audit", previous=unknown["Hash"], replay=self.replay,
                        binding=self.binding, outcome="permit:target_known",
                        ident="e" * 32, now=3))
        self.write(rows)
        with self.assertRaises(ValueError):
            read_earned_receipts(self.audit, [self.decision])

    def test_terminal_then_new_pre_dispatch_cannot_reopen_replay(self):
        rows = audit_rows()[:2]
        terminal = row("audit", previous=rows[-1]["Hash"], replay=self.replay,
                       binding=self.binding, outcome="unknown:target_outcome_unknown",
                       ident="d" * 32, now=2)
        rows.append(terminal)
        reopened = row("audit", previous=terminal["Hash"], replay=self.replay,
                       binding=self.binding, outcome="pre_dispatch:reserved_rechecked",
                       ident="e" * 32, now=3)
        rows.append(reopened)
        rows.append(row("audit", previous=reopened["Hash"], replay=self.replay,
                        binding=self.binding, outcome="permit:target_known",
                        ident="f" * 32, now=4))
        self.write(rows)
        with self.assertRaises(ValueError):
            read_earned_receipts(self.audit, [self.decision])

    def test_binding_or_operation_mismatch_does_not_earn(self):
        self.write(audit_rows())
        for change in ({"binding_digest": "f" * 64}, {"operation_id": "lab.set_marker"}, {"allow": False}):
            with self.subTest(change=change):
                self.assertEqual(read_earned_receipts(self.audit, [self.decision | change]), {})

    def test_missing_truncated_or_tampered_audit_fails_closed(self):
        with self.assertRaises(OSError):
            read_earned_receipts(self.audit, [self.decision])
        self.write(audit_rows())
        self.audit.write_bytes(self.audit.read_bytes()[:-1])
        with self.assertRaises(ValueError):
            read_earned_receipts(self.audit, [self.decision])
        self.write(audit_rows())
        self.audit.write_bytes(self.audit.read_bytes().replace(b"permit:target_known", b"permit:target_knowX"))
        with self.assertRaises(ValueError):
            read_earned_receipts(self.audit, [self.decision])

    def test_bridge_requires_five_completed_reads_before_marker(self):
        self.write(audit_rows()[:1])
        bridge = Bridge(Path(self.temp.name).resolve() / "kil.jsonl", earning_audit=self.audit)
        marker = {k: v for k, v in self.decision.items() if k != "allow"}
        marker.update(operation_id="lab.set_marker", operation_digest="d" * 64,
                      tenant_id="lab-tenant")
        self.assertFalse(bridge.decide(marker, 1_800_000_000_000_000_000)["allow"])
        rows = audit_rows()[:1]
        for index in range(5):
            replay = f"{index + 1:032x}"
            binding = f"{index + 1:064x}"
            read = {k: v for k, v in self.decision.items() if k != "allow"}
            read.update(replay_id=replay, binding_digest=binding,
                        operation_digest="e" * 64, tenant_id="lab-tenant")
            self.assertTrue(bridge.decide(read, 1_800_000_001_000_000_000 + index * 10_000_000_000)["allow"])
            pre = row("audit", previous=rows[-1]["Hash"], replay=replay,
                      binding=binding, outcome="pre_dispatch:reserved_rechecked",
                      ident=f"{index * 2 + 1:032x}", now=index * 2 + 1)
            rows.append(pre)
            rows.append(row("audit", previous=pre["Hash"], replay=replay,
                            binding=binding, outcome="permit:target_known",
                            ident=f"{index * 2 + 2:032x}", now=index * 2 + 2))
            self.write(rows)
            probe = dict(marker, replay_id=f"{index + 10:032x}",
                         binding_digest=f"{index + 10:064x}")
            result = bridge.decide(probe, 1_800_000_002_000_000_000 + index * 10_000_000_000)
            self.assertEqual(result["allow"], index == 4)
        last = json.loads(bridge.ledger.read_text().splitlines()[-1])
        self.assertEqual(last["charge"], "65")
        self.assertEqual(last["threshold"], "65")
        other = dict(marker, actor_id="agent-2", replay_id="f" * 32)
        self.assertFalse(bridge.decide(other, 1_800_000_100_000_000_000)["allow"])

    def test_g15_signed_state_cannot_be_rebound_to_new_binding(self):
        self.write(audit_rows()[:1])
        bridge = Bridge(Path(self.temp.name).resolve() / "rebind.jsonl", earning_audit=self.audit)
        read = {k: v for k, v in self.decision.items() if k != "allow"}
        read.update(operation_digest="e" * 64, tenant_id="lab-tenant")
        now = 1_800_000_000_000_000_000
        token = bridge.issue(read, now)
        self.assertTrue(bridge.evaluate(read, token, now)["allow"])
        changed = dict(read, binding_digest="f" * 64)
        self.assertFalse(bridge.evaluate(changed, token, now)["allow"])


if __name__ == "__main__":
    unittest.main()
