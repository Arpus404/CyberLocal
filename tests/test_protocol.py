import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent'))
from protocol import parse_message, MAX_LINE

class ProtocolTests(unittest.TestCase):
    def test_hello(self):
        self.assertEqual(parse_message(b'{"type":"hello","protocol":1,"chip":"ESP32"}\n','hello')['chip'], 'ESP32')
    def test_wrong_device(self):
        with self.assertRaises(ValueError): parse_message(b'{"type":"hello","protocol":1,"chip":"ESP32-S3"}\n','hello')
    def test_scan(self):
        result = parse_message(b'{"type":"scan","ok":true,"kind":"wifi","items":[{"ssid":"maison","rssi_dbm":-45}]}\n','scan')
        self.assertEqual(result['items'][0]['rssi_dbm'], -45)
    def test_malformed(self):
        for raw in (b'{oops}\n', b'{}', b'x' * (MAX_LINE + 1) + b'\n'):
            with self.subTest(raw=raw[:10]), self.assertRaises(ValueError): parse_message(raw,'scan')
    def test_failure_is_not_empty_scan(self):
        with self.assertRaises(ValueError): parse_message(b'{"type":"scan","kind":"ble","ok":false}\n','scan')
    def test_too_many(self):
        import json
        raw=(json.dumps({'type':'scan','kind':'ble','ok':True,'items':[{}]*51})+'\n').encode()
        with self.assertRaises(ValueError): parse_message(raw,'scan')

if __name__ == '__main__': unittest.main()
