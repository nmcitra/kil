from hashlib import sha256
import json
import socket
import ssl
from pathlib import Path
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from lab.campaign_bridge import Bridge, Handler, Server
from lab.make_lab_identity import create


class ProtectedBridgeTLSTest(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name).resolve()
        create(self.root/'identities')
        self.ids = self.root/'identities'
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(self.ids/'bridge.pem',self.ids/'bridge-key.pem')
        ctx.load_verify_locations(self.ids/'ca.pem')
        ctx.verify_mode = ssl.CERT_REQUIRED
        self.server = Server(('127.0.0.1',0),Handler)
        self.server.context = ctx
        self.server.slots = threading.BoundedSemaphore(8)
        cert = x509.load_pem_x509_certificate((self.ids/'gateway-client.pem').read_bytes())
        self.server.clients = frozenset({sha256(cert.public_bytes(Encoding.DER)).hexdigest()})
        self.server.bridge = Bridge(self.root/'ledger.jsonl')
        thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def call(self,role,payload,path='/decision',headers=b''):
        ctx = ssl.create_default_context(cafile=str(self.ids/'ca.pem'))
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(self.ids/(role+'.pem'),self.ids/(role+'-key.pem'))
        with socket.create_connection(('127.0.0.1',self.server.server_port),timeout=3) as raw:
            with ctx.wrap_socket(raw,server_hostname='bridge') as tls:
                tls.sendall(b'POST '+path.encode()+b' HTTP/1.1\r\nHost: bridge\r\nContent-Length: '+
                    str(len(payload)).encode()+b'\r\nConnection: close\r\n'+headers+b'\r\n'+payload)
                return tls.recv(4096).split(b'\r\n',1)[0]

    def test_gateway_client_permitted_and_agent_client_forbidden(self):
        payload = json.dumps({'binding_digest':'a'*64,'operation_digest':'b'*64,
            'replay_id':'c'*32,'actor_id':'agent-1','tenant_id':'lab-tenant',
            'operation_id':'lab.set_marker'}).encode()
        self.assertIn(b'200',self.call('gateway-client',payload))
        self.assertIn(b'403',self.call('agent-1',payload))
        self.assertEqual(len(self.server.bridge.ledger.read_text().splitlines()),1)

    def test_envoy_path_cannot_claim_the_other_operation(self):
        fields={'binding_digest':'a'*64,'operation_digest':'b'*64,
                'replay_id':'c'*32,'actor_id':'agent-1','tenant_id':'lab-tenant',
                'operation_id':'lab.read_status'}
        headers=b''.join(('X-KAG-'+k.replace('_','-')+': '+v+'\r\n').encode()
                         for k,v in fields.items())
        self.assertIn(b'403',self.call('gateway-client',b'',path='/lab/marker',headers=headers))
        self.assertEqual(self.server.bridge.ledger.read_text(),'')


if __name__=='__main__':
    unittest.main()
