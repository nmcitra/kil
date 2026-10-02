"""Fixture integrity prerequisites, never implementation conformance."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


class ConformancePreflightTests(unittest.TestCase):
    def test_fixture_boundary(self):
        module_path = Path(__file__).parents[1] / 'tools/conformance_preflight.py'
        self.assertTrue(module_path.is_file(), 'fixture preflight is not implemented')
        spec = importlib.util.spec_from_file_location('preflight', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        document = {'profile': 'software-substrate-execution', 'vectors': [
            {'id': 'S01', 'request': {'resource': 'software:///test-object'},
             'expect': {'decision': 'allow'}}]}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'fixture.json'
            def check(value, valid=True):
                raw = json.dumps(value).encode()
                path.write_bytes(raw)
                digest = hashlib.sha256(raw).hexdigest()
                if valid:
                    self.assertEqual(module.load_fixture(path, digest), value)
                else:
                    with self.assertRaises(ValueError):
                        module.load_fixture(path, digest)
            check(document)
            with self.assertRaises(ValueError):
                module.load_fixture(path, '0' * 64)
            with self.assertRaises(FileNotFoundError):
                module.load_fixture(Path(temporary) / 'missing', '0' * 64)
            for mutate in (
                lambda d: d.update(profile='wrong'),
                lambda d: d.update(vectors=[]),
                lambda d: d['vectors'].append(d['vectors'][0]),
                lambda d: d['vectors'][0].update(id=''),
                lambda d: d['vectors'][0].pop('request'),
                lambda d: d['vectors'][0].update(expect={'invented': True}),
                lambda d: d['vectors'][0].update(expect={}),
                lambda d: d['vectors'][0].update(request=[]),
            ):
                bad = json.loads(json.dumps(document))
                mutate(bad)
                check(bad, False)
            raw = b'{"profile":"software-substrate-execution","profile":"other"}'
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                module.load_fixture(path, hashlib.sha256(raw).hexdigest())
            for overflow in ('1e999', '-1e999'):
                raw = json.dumps(document).replace('"allow"', overflow).encode()
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    module.load_fixture(path, hashlib.sha256(raw).hexdigest())
            path.write_bytes(b'[]')
            with self.assertRaises(ValueError):
                module.load_fixture(path, hashlib.sha256(b'[]').hexdigest())
            raw = json.dumps(document).replace('"allow"', 'NaN').encode()
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                module.load_fixture(path, hashlib.sha256(raw).hexdigest())
