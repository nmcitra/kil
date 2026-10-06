"""Experimental protected synthetic-authority bridge using actual KIL verification.

This lab adapter is not canonical KTP earned-authority issuance or conformance.
Signing keys are generated in memory; no private key/token is emitted or recorded.
"""
from argparse import ArgumentParser
from dataclasses import replace
from decimal import Decimal
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import ssl
import stat
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from kil.domain import ActionRequest, DecisionOutcome, LocalEvidence, ReductionProfile
from kil.live_authz import AuthorizationAdapter, LiveFixture, LiveTrack
from kil.q_state import QStateClaims, QStateVerificationError, issue_q_state, key_id, verify_q_state
from lab.g15_earning import read_earned_receipts

FIELDS = frozenset(('binding_digest','operation_digest','replay_id','actor_id','tenant_id','operation_id'))
HEX64 = re.compile(r'[a-f0-9]{64}\Z')
HEX32 = re.compile(r'[a-f0-9]{32}\Z')
MAX_BODY = 4096


def _object(pairs):
    result = {}
    for k,v in pairs:
        if k in result:
            raise ValueError('duplicate_field')
        result[k] = v
    return result


def parse_request(raw):
    if type(raw) is not bytes or len(raw) > MAX_BODY:
        raise ValueError('body_limit')
    value = json.loads(raw, object_pairs_hook=_object)
    if type(value) is not dict or set(value) != FIELDS:
        raise ValueError('closed_schema')
    if not all(type(v) is str for v in value.values()):
        raise ValueError('field_type')
    if not all(HEX64.fullmatch(value[k]) for k in ('binding_digest','operation_digest')):
        raise ValueError('digest')
    if not HEX32.fullmatch(value['replay_id']):
        raise ValueError('replay_id')
    return value


class Bridge:
    def __init__(self, ledger, *, divergence=Decimal('0.249'), divergence_mode='constant',
                 clock_ns=time.time_ns, earning_audit=None):
        if not divergence.is_finite() or not Decimal('0') <= divergence <= Decimal('1'):
            raise ValueError('divergence')
        if divergence_mode not in ('constant','attempt-rate'):
            raise ValueError('divergence_mode')
        if not callable(clock_ns):
            raise ValueError('clock_ns')
        self.ledger = Path(ledger)
        if not self.ledger.is_absolute() or self.ledger.parent.resolve() != self.ledger.parent:
            raise ValueError('ledger_path')
        self.earning_audit = Path(earning_audit) if earning_audit is not None else None
        if self.earning_audit is not None and not self.earning_audit.is_absolute():
            raise ValueError('earning_audit_path')
        fd = os.open(self.ledger, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        os.fsync(fd)
        os.close(fd)
        parent = os.open(self.ledger.parent, os.O_RDONLY|os.O_DIRECTORY)
        os.fsync(parent)
        os.close(parent)
        self.key = Ed25519PrivateKey.generate()
        self.keys = {key_id(self.key.public_key()):self.key.public_key()}
        self.adapter = AuthorizationAdapter(LiveTrack.SIGNED_PLUS_LOCAL_REDUCE, keys=self.keys)
        self.divergence = divergence
        self.divergence_mode = divergence_mode
        self.clock_ns = clock_ns
        self.last_unique_marker_ns = None
        self.divergence_by_replay = {}
        self.held = False
        self.lock = threading.Lock()
        self.rows = 0
        self.decision_rows = []

    def validate(self, value):
        value = parse_request(json.dumps(value).encode())
        if value['actor_id'] not in ('agent-1','agent-2') or value['tenant_id'] != 'lab-tenant':
            raise ValueError('unknown_actor')
        if value['operation_id'] not in ('lab.set_marker','lab.read_status'):
            raise ValueError('unknown_operation')
        return value

    def _standing(self, value):
        if self.earning_audit is None:
            return None
        receipts = read_earned_receipts(self.earning_audit, self.decision_rows).get(value['actor_id'], ())
        proof = json.dumps([(r.replay_id, r.binding_digest, r.audit_hash) for r in receipts],
                           separators=(',', ':')).encode()
        count = len(receipts)
        return count, min(Decimal('100'), Decimal('40') + Decimal('5') * count), 'sha256:' + sha256(proof).hexdigest()

    @staticmethod
    def _bound_proof(value, standing):
        if standing is None:
            return 'sha256:' + value['binding_digest']
        material = b'g15-earned-and-request-v1\0' + standing[2].encode('ascii') + b'\0' + value['binding_digest'].encode('ascii')
        return 'sha256:' + sha256(material).hexdigest()

    def issue(self, value, now_ns, standing=None):
        value = self.validate(value)
        if self.earning_audit is not None and standing is None:
            standing = self._standing(value)
        now = now_ns//1_000_000_000
        charge = standing[1] if standing is not None else Decimal('80')
        threshold = (Decimal('0') if value['operation_id'] == 'lab.read_status' else Decimal('65')) if standing is not None else Decimal('40')
        history_count = standing[0] if standing is not None else 5
        minimum_history = (0 if value['operation_id'] == 'lab.read_status' else 5) if standing is not None else 2
        claims = QStateClaims(
            schema_version='kil.q-state.v0',state_id='campaign:'+value['replay_id'],
            issuer='https://synthetic-authority.kil.invalid',subject=value['actor_id'],
            audience='kil-v3-local',authority_class=value['operation_id'],
            action_class=value['operation_id'],issued_at_s=now,not_before_s=now,
            expires_at_s=now+4,evidence_horizon_s=now,
            trust_proof_id=('g15-modeled:' if standing is not None else 'modeled:')+value['replay_id'],
            trust_proof_digest=self._bound_proof(value, standing),
            envelope_result_id='modeled-envelope',
            envelope_result_digest='sha256:'+value['operation_digest'],
            deployment_profile='campaign-lab-g15-v1' if standing is not None else 'campaign-lab-modeled-v1',
            charge=charge,threshold=threshold,history_count=history_count,minimum_history=minimum_history,
            veto_clear=True,envelope_allows=True,decay_rate=Decimal('0'),
            maximum_charge=Decimal('100'),model_version='kil-decay-v1',
            parameter_version='campaign-g15-audit-v1' if standing is not None else 'campaign-modeled-v1')
        return issue_q_state(claims,self.key)

    def evaluate(self, value, token, now_ns, divergence=None, standing=None):
        value = self.validate(value)
        if self.earning_audit is not None and standing is None:
            standing = self._standing(value)
        request = ActionRequest(value['replay_id'],value['actor_id'],value['operation_id'],now_ns//1_000_000_000)
        fixture = LiveFixture(request,value['operation_id'],True,True,token,
            LocalEvidence(self.divergence if divergence is None else divergence,Decimal('0'),True),
            ReductionProfile(Decimal('0.25'),Decimal('25'),3))
        verified = None
        try:
            verified = verify_q_state(token,self.keys,now_s=request.timestamp_s,
                expected_subject=request.identity,expected_audience='kil-v3-local',
                expected_authority_class=request.authority_class,
                expected_action_class=value['operation_id'],revoked_state_ids=frozenset())
            claims = verified.claims
            expected_proof = self._bound_proof(value, standing)
            if (claims.trust_proof_digest != expected_proof or
                claims.envelope_result_digest != 'sha256:'+value['operation_digest'] or
                claims.state_id != 'campaign:'+value['replay_id']):
                fixture = replace(fixture,q_state_jws=None)
        except QStateVerificationError:
            pass
        decision = self.adapter.evaluate(fixture)
        expires = verified.claims.expires_at_s*1_000_000_000 if verified else now_ns
        reasons = list(decision.adapter_reasons)
        if decision.engine_record:
            reasons += [r.value for r in decision.engine_record.reasons]
        return dict(allow=decision.outcome is DecisionOutcome.PERMIT,
            decision_digest=decision.decision_digest,reasons=reasons,
            issued_at_unix_ns=now_ns,expires_unix_ns=expires,
            **{k:value[k] for k in ('binding_digest','operation_digest','replay_id')})

    def _local_divergence(self, value, now_ns):
        rid=value['replay_id']
        binding=(value['actor_id'],value['tenant_id'],value['operation_id'],
                 value['binding_digest'],value['operation_digest'])
        if rid in self.divergence_by_replay:
            existing,divergence=self.divergence_by_replay[rid]
            if existing!=binding:
                raise ValueError('replay_binding_mismatch')
            return divergence
        if len(self.divergence_by_replay)>=10000:
            raise OSError('observation_limit')
        value_at_rate=self.divergence
        if self.divergence_mode=='attempt-rate' and value['operation_id']=='lab.set_marker':
            last=self.last_unique_marker_ns
            value_at_rate=(Decimal('0.9') if last is not None and
                (now_ns<last or now_ns-last<60_000_000_000) else self.divergence)
            self.last_unique_marker_ns=now_ns
        self.divergence_by_replay[rid]=(binding,value_at_rate)
        return value_at_rate

    def decide(self, value, now_ns=None):
        value = self.validate(value)
        with self.lock:
            if self.held:
                raise OSError('bridge_recorder_held')
            if now_ns is None:
                now_ns=self.clock_ns()
            standing = self._standing(value)
            try:
                divergence=self._local_divergence(value,now_ns)
                result = self.evaluate(value,self.issue(value,now_ns,standing),now_ns,divergence,standing)
                charge = standing[1] if standing is not None else Decimal('80')
                threshold = (Decimal('0') if value['operation_id'] == 'lab.read_status' else Decimal('65')) if standing is not None else Decimal('40')
                raw = json.dumps(dict(result,operation_id=value['operation_id'],actor_id=value['actor_id'],
                    divergence=str(divergence),evidence_lane='synthetic-modeled',
                    charge=str(charge),threshold=str(threshold),
                    history_count=standing[0] if standing is not None else 5,
                    earned_evidence_digest=standing[2] if standing is not None else None,
                    recorded_at_unix_ns=now_ns),sort_keys=True,separators=(',',':')).encode()+b'\n'
                fd = os.open(self.ledger,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
                try:
                    row = os.fstat(fd)
                    if not stat.S_ISREG(row.st_mode) or row.st_nlink != 1 or row.st_size > 16*1024*1024 or self.rows >= 10000:
                        raise OSError('ledger_limit_or_identity')
                    view = memoryview(raw)
                    while view:
                        written = os.write(fd,view)
                        if written <= 0:
                            raise OSError('short_write')
                        view = view[written:]
                    os.fsync(fd)
                    self.rows += 1
                    self.decision_rows.append(dict(result,operation_id=value['operation_id'],
                                                   actor_id=value['actor_id']))
                finally:
                    os.close(fd)
            except OSError:
                self.held=True
                raise
        return result


class Server(ThreadingHTTPServer):
    daemon_threads = True
    def get_request(self):
        conn,addr = super().get_request()
        conn.settimeout(3)
        try:
            return self.context.wrap_socket(conn,server_side=True),addr
        except BaseException:
            conn.close()
            raise


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self,*args):
        pass

    def send(self,status,value):
        payload = json.dumps(value,separators=(',',':')).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(payload)))
        if isinstance(value,dict) and type(value.get('decision_digest')) is str and HEX64.fullmatch(value['decision_digest']):
            self.send_header('X-KIL-Decision-Digest',value['decision_digest'])
        self.send_header('Cache-Control','no-store')
        self.send_header('Connection','close')
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        if not self.server.slots.acquire(blocking=False):
            self.send(503,{'error':'unavailable'})
            return
        try:
            peer = sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
            if peer not in self.server.clients:
                self.send(403,{'error':'denied'})
                return
            if len(self.headers.items()) > 32 or sum(len(k)+len(v) for k,v in self.headers.items()) > 8192:
                raise ValueError('headers')
            if self.headers.get_all('Transfer-Encoding') or self.headers.get_all('Content-Encoding'):
                raise ValueError('encoding')
            lengths = self.headers.get_all('Content-Length',[])
            if self.path == '/decision' and self.command == 'POST':
                if len(lengths) != 1 or not lengths[0].isdigit() or int(lengths[0]) > MAX_BODY:
                    raise ValueError('length')
                raw = self.rfile.read(int(lengths[0]))
                if len(raw) != int(lengths[0]):
                    raise ValueError('truncated')
                value = parse_request(raw)
            elif (self.command,self.path) in (('POST','/lab/marker'),('GET','/lab/status')):
                if lengths and lengths != ['0']:
                    raise ValueError('body')
                value = {}
                for field in FIELDS:
                    name='x-kag-'+field.replace('_','-')
                    vals=self.headers.get_all(name,[])
                    if len(vals)!=1:
                        raise ValueError('binding_header')
                    value[field]=vals[0]
                expected='lab.set_marker' if self.path=='/lab/marker' else 'lab.read_status'
                if value['operation_id']!=expected:
                    self.send(403,{'error':'route_operation_mismatch'})
                    return
            else:
                self.send(404,{'error':'route'})
                return
            result=self.server.bridge.decide(value)
            self.send(200 if self.path=='/decision' or result['allow'] else 403,result)
        except (ValueError,OSError,TimeoutError):
            self.send(503,{'error':'unavailable'})
        finally:
            self.server.slots.release()


def main():
    p=ArgumentParser(description=__doc__)
    p.add_argument('--listen-port',type=int,default=8443)
    for name in ('server-cert','server-key','client-ca','ledger'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--allowed-client-cert',type=Path,action='append',required=True)
    p.add_argument('--divergence',type=Decimal,default=Decimal('0.249'))
    p.add_argument('--divergence-mode',choices=('constant','attempt-rate'),default='constant')
    p.add_argument('--earning-audit',type=Path)
    args=p.parse_args()
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(args.server_cert,args.server_key)
    context.load_verify_locations(args.client_ca)
    context.verify_mode=ssl.CERT_REQUIRED
    server=Server(('0.0.0.0',args.listen_port),Handler)
    server.context=context
    server.slots=threading.BoundedSemaphore(8)
    server.clients=frozenset(sha256(x509.load_pem_x509_certificate(p.read_bytes()).public_bytes(Encoding.DER)).hexdigest() for p in args.allowed_client_cert)
    server.bridge=Bridge(args.ledger,divergence=args.divergence,divergence_mode=args.divergence_mode,
                         earning_audit=args.earning_audit)
    server.serve_forever()


if __name__=='__main__':
    main()
