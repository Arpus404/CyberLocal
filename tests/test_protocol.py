import json
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))

from protocol import MAX_LINE, parse_message


class ProtocolTests(unittest.TestCase):
    def test_hello(self):
        message = b'{"type":"hello","protocol":1,"chip":"ESP32"}\n'
        self.assertEqual(parse_message(message, "hello")["chip"], "ESP32")

    def test_wrong_device(self):
        message = b'{"type":"hello","protocol":1,"chip":"ESP32-S3"}\n'
        with self.assertRaises(ValueError):
            parse_message(message, "hello")

    def test_scan(self):
        message = (
            b'{"type":"scan","ok":true,"kind":"wifi",'
            b'"items":[{"ssid":"maison","rssi_dbm":-45}]}\n'
        )
        result = parse_message(message, "scan")
        self.assertEqual(result["items"][0]["rssi_dbm"], -45)

    def test_malformed(self):
        messages = (
            b"{oops}\n",
            b"{}",
            b"x" * (MAX_LINE + 1) + b"\n",
        )
        for message in messages:
            with self.subTest(message=message[:10]):
                with self.assertRaises(ValueError):
                    parse_message(message, "scan")

    def test_failure_is_not_empty_scan(self):
        message = b'{"type":"scan","kind":"ble","ok":false}\n'
        with self.assertRaises(ValueError):
            parse_message(message, "scan")

    def test_too_many(self):
        message = (
            json.dumps(
                {
                    "type": "scan",
                    "kind": "ble",
                    "ok": True,
                    "items": [{}] * 51,
                }
            )
            + "\n"
        ).encode()

        with self.assertRaises(ValueError):
            parse_message(message, "scan")


if __name__ == "__main__":
    unittest.main()
