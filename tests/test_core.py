import json
import socket
import unittest
from unittest.mock import patch
import core

class FakeSocket:
    def __init__(self, reply): self.reply, self.sent = reply, bytearray()
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def settimeout(self, value): pass
    def sendall(self, data): self.sent.extend(data)
    def recv(self, size): result, self.reply = self.reply, b''; return result

class FakeResponse:
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, *args):
        return json.dumps({'vulnerabilities': [{'cve': {'id':'CVE-2025-0001', 'descriptions':[{'lang':'en','value':'example'}], 'references':[{'url':'https://example.org'}]}}]}).encode()

class CoreTests(unittest.TestCase):
    def test_sha(self):
        self.assertEqual(core.sha256(b'abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    def test_clean_is_not_promoted_to_safe(self):
        fake = FakeSocket(b'stream: OK\0')
        with patch('core.socket.create_connection', return_value=fake):
            self.assertEqual(core.clam_scan(b'hello')[0], 'Analyse incomplète')
        self.assertTrue(fake.sent.startswith(b'zINSTREAM\0'))
        self.assertTrue(fake.sent.endswith(b'\0\0\0\0'))
    def test_threat(self):
        with patch('core.socket.create_connection', return_value=FakeSocket(b'stream: Eicar-Test-Signature FOUND\0')):
            self.assertEqual(core.clam_scan(b'test'), ('Menace détectée', 'Eicar-Test-Signature'))
    def test_failure_not_clean(self):
        with patch('core.socket.create_connection', return_value=FakeSocket(b'stream: ERROR\0')):
            self.assertEqual(core.clam_scan(b'x')[0], 'Échec de l’analyse')
    def test_unavailable(self):
        with patch('core.socket.create_connection', side_effect=socket.timeout):
            with self.assertRaises(TimeoutError): core.clam_scan(b'x')
    def test_cve(self):
        with patch('core.urllib.request.urlopen', return_value=FakeResponse()):
            row = core.nvd_search('CVE-2025-0001')[0]
        self.assertEqual(row['id'], 'CVE-2025-0001')
        self.assertEqual(row['references'], ['https://example.org'])
    def test_empty_query(self):
        with self.assertRaises(ValueError): core.nvd_search(' ')

if __name__ == '__main__': unittest.main()
