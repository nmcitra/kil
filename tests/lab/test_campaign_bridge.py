from decimal import Decimal
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import json
import threading
import tempfile
import unittest

from lab.campaign_bridge import Bridge, parse_request


def request():
    return {'binding_digest': 'a'*64, 'operation_digest': 'b'*64,
            'replay_id': 'c'*32, 'actor_id': 'agent-1',
            'tenant_id': 'lab-tenant', 'operation_id': 'lab.set_marker'}


class BridgeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name).resolve()
        self.bridge = Bridge(self.directory/'decisions.jsonl')
        self.now = 1_800_000_000_000_000_000

    def test_signed_low_divergence_allows_and_is_recorded(self):
        result = self.bridge.decide(request(), self.now)
        self.assertTrue(result['allow'])
        self.assertEqual(result['binding_digest'], request()['binding_digest'])
        self.assertLessEqual(result['expires_unix_ns']-self.now, 5_000_000_000)
        self.assertIn(result['decision_digest'], self.bridge.ledger.read_text())

    def test_high_divergence_denies(self):
        self.bridge = Bridge(self.directory/'other.jsonl', divergence=Decimal('0.9'))
        self.assertFalse(self.bridge.decide(request(), self.now)['allow'])

    def test_rate_feedback_reduces_fast_unique_attempts_but_not_same_replay(self):
        bridge=Bridge(self.directory/'rate.jsonl', divergence_mode='attempt-rate')
        first=request()
        self.assertTrue(bridge.decide(first,self.now)['allow'])
        # Evaluate and Recheck of the same action have one local observation.
        self.assertTrue(bridge.decide(first,self.now+1_000_000_000)['allow'])
        fast=request()|{'replay_id':'d'*32,'actor_id':'agent-2'}
        denied=bridge.decide(fast,self.now+30_000_000_000)
        self.assertFalse(denied['allow'])
        self.assertIn('insufficient_charge',denied['reasons'])
        # This observation counts denied attempts. Waiting a full minute from
        # the fast attempt clears the modeled rate signal.
        paced=request()|{'replay_id':'e'*32}
        self.assertTrue(bridge.decide(paced,self.now+90_000_000_000)['allow'])
        self.assertEqual([__import__('json').loads(x)['divergence'] for x in bridge.ledger.read_text().splitlines()],
                         ['0.249','0.249','0.9','0.249'])

    def test_same_replay_with_changed_binding_or_actor_is_closed(self):
        bridge=Bridge(self.directory/'bound.jsonl',divergence_mode='attempt-rate')
        self.assertTrue(bridge.decide(request(),self.now)['allow'])
        for change in ({'binding_digest':'d'*64},{'actor_id':'agent-2'},
                       {'operation_digest':'e'*64}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                bridge.decide(request()|change,self.now+1_000_000_000)
        self.assertEqual(len(bridge.ledger.read_text().splitlines()),1)

    def test_same_replay_cannot_switch_between_status_and_marker(self):
        first=Bridge(self.directory/'cross-marker.jsonl',divergence_mode='attempt-rate')
        self.assertTrue(first.decide(request(),self.now)['allow'])
        with self.assertRaises(ValueError):
            first.decide(request()|{'operation_id':'lab.read_status'},self.now+1_000_000_000)
        second=Bridge(self.directory/'cross-status.jsonl',divergence_mode='attempt-rate')
        self.assertTrue(second.decide(request()|{'operation_id':'lab.read_status'},self.now)['allow'])
        with self.assertRaises(ValueError):
            second.decide(request(),self.now+1_000_000_000)
        self.assertEqual(len(first.ledger.read_text().splitlines()),1)
        self.assertEqual(len(second.ledger.read_text().splitlines()),1)

    def test_live_clock_is_sampled_inside_serialized_decision(self):
        count=[0]
        def tick():
            count[0]+=1
            return self.now+(count[0]-1)*5_000_000_000
        bridge=Bridge(self.directory/'concurrent.jsonl',divergence_mode='attempt-rate',clock_ns=tick)
        start=threading.Barrier(2)
        def ask(rid):
            start.wait()
            return bridge.decide(request()|{'replay_id':rid})
        with ThreadPoolExecutor(max_workers=2) as pool:
            values=list(pool.map(ask,('d'*32,'e'*32)))
        self.assertEqual(sorted(v['allow'] for v in values),[False,True])
        records=[json.loads(x) for x in bridge.ledger.read_text().splitlines()]
        self.assertEqual([x['divergence'] for x in records],['0.249','0.9'])
        self.assertEqual([x['recorded_at_unix_ns'] for x in records],
                         [self.now,self.now+5_000_000_000])

    def test_signed_token_cannot_be_rebound(self):
        token = self.bridge.issue(request(), self.now)
        changed = request() | {'binding_digest': 'd'*64}
        self.assertFalse(self.bridge.evaluate(changed, token, self.now)['allow'])

    def test_tampered_or_expired_signed_state_denies(self):
        token = self.bridge.issue(request(), self.now)
        self.assertFalse(self.bridge.evaluate(request(), token[:-4]+'AAAA', self.now)['allow'])
        self.assertFalse(self.bridge.evaluate(request(), token, self.now+4_000_000_000)['allow'])

    def test_unknown_actor_and_operation_fail_before_issuance(self):
        for field, value in [('actor_id','intruder'),('operation_id','shell.exec')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.bridge.decide(request() | {field: value}, self.now)

    def test_recording_failure_does_not_return_a_permit(self):
        self.bridge.ledger.unlink()
        self.bridge.ledger.mkdir()
        with self.assertRaises(OSError):
            self.bridge.decide(request(), self.now)
        self.bridge.ledger.rmdir()
        self.bridge.ledger.write_text('')
        with self.assertRaises(OSError):
            self.bridge.decide(request()|{'replay_id':'d'*32},self.now+60_000_000_000)

    def test_strict_json_rejects_duplicates_and_extra_fields(self):
        for payload in [b'{"actor_id":"a","actor_id":"b"}',b'{}',b'[]']:
            with self.assertRaises(ValueError):
                parse_request(payload)


if __name__ == '__main__':
    unittest.main()
