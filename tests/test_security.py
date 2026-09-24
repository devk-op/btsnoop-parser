"""Tests for the Classic BT link-key extraction module."""
from __future__ import annotations

import datetime
import unittest

from btsnoop_parser.security import extract_link_keys

_UTC = datetime.timezone.utc
_TS = datetime.datetime(2024, 1, 1, 12, 0, 0, tzinfo=_UTC)

_ADDR_BYTES = bytes.fromhex("665544332211")  # on-the-wire order -> AA:BB... reversed display? see below
_ADDR_DISPLAY = "11:22:33:44:55:66"
_KEY_BYTES = bytes(range(0x30, 0x40))  # 16 arbitrary bytes


def _record(packet_type: int, payload: bytes) -> dict:
    return {"packet_type": packet_type, "payload": payload, "timestamp": _TS}


def _link_key_notification_payload(addr: bytes, key: bytes, key_type: int) -> bytes:
    # [EventCode(0x18), Len, BD_ADDR(6), LinkKey(16), KeyType(1)]
    params = addr + key + bytes([key_type])
    return bytes([0x18, len(params)]) + params


def _link_key_request_reply_payload(addr: bytes, key: bytes) -> bytes:
    # [OpcodeLSB, OpcodeMSB, Len, BD_ADDR(6), LinkKey(16)]
    opcode = 0x040B
    params = addr + key
    return bytes([opcode & 0xFF, (opcode >> 8) & 0xFF, len(params)]) + params


class TestLinkKeyNotification(unittest.TestCase):
    def test_extracts_addr_key_and_type(self):
        payload = _link_key_notification_payload(_ADDR_BYTES, _KEY_BYTES, key_type=0x05)
        keys = extract_link_keys([_record(0x04, payload)])

        self.assertEqual(len(keys), 1)
        k = keys[0]
        self.assertEqual(k["addr"], _ADDR_DISPLAY)
        self.assertEqual(k["link_key"], _KEY_BYTES.hex().upper())
        self.assertEqual(k["source"], "Link Key Notification")
        self.assertEqual(k["key_type"], 0x05)
        self.assertIn("Authenticated", k["key_type_name"])

    def test_unknown_key_type_falls_back_to_hex(self):
        payload = _link_key_notification_payload(_ADDR_BYTES, _KEY_BYTES, key_type=0xFE)
        keys = extract_link_keys([_record(0x04, payload)])
        self.assertIn("0xFE", keys[0]["key_type_name"])

    def test_ignores_other_events(self):
        payload = bytes([0x05, 0x04, 0x00, 0x01, 0x00, 0x13])  # Disconnection Complete
        self.assertEqual(extract_link_keys([_record(0x04, payload)]), [])

    def test_ignores_short_payload(self):
        payload = bytes([0x18, 0x02, 0x00, 0x00])  # too short to contain a real key
        self.assertEqual(extract_link_keys([_record(0x04, payload)]), [])


class TestLinkKeyRequestReply(unittest.TestCase):
    def test_extracts_addr_and_key(self):
        payload = _link_key_request_reply_payload(_ADDR_BYTES, _KEY_BYTES)
        keys = extract_link_keys([_record(0x01, payload)])

        self.assertEqual(len(keys), 1)
        k = keys[0]
        self.assertEqual(k["addr"], _ADDR_DISPLAY)
        self.assertEqual(k["link_key"], _KEY_BYTES.hex().upper())
        self.assertEqual(k["source"], "Link Key Request Reply")
        self.assertIsNone(k["key_type"])
        self.assertIsNone(k["key_type_name"])

    def test_ignores_other_commands(self):
        payload = bytes([0x03, 0x0C, 0x00])  # Reset command, no params
        self.assertEqual(extract_link_keys([_record(0x01, payload)]), [])

    def test_ignores_link_key_request_negative_reply(self):
        # Opcode 0x040C (negative reply) carries no key — must not be mistaken for 0x040B.
        opcode = 0x040C
        payload = bytes([opcode & 0xFF, (opcode >> 8) & 0xFF, 0x06]) + _ADDR_BYTES
        self.assertEqual(extract_link_keys([_record(0x01, payload)]), [])

    def test_ignores_pin_code_request_reply(self):
        # Opcode 0x040D is PIN Code Request Reply: BD_ADDR(6) + PIN_Length(1) + PIN(16).
        # Long enough to look like a link key command, but it's a PIN — must not be reported.
        opcode = 0x040D
        params = _ADDR_BYTES + bytes([4]) + b"1234" + bytes(12)
        payload = bytes([opcode & 0xFF, (opcode >> 8) & 0xFF, len(params)]) + params
        self.assertEqual(extract_link_keys([_record(0x01, payload)]), [])


class TestMixedRecords(unittest.TestCase):
    def test_finds_keys_across_multiple_records(self):
        records = [
            _record(0x04, _link_key_notification_payload(_ADDR_BYTES, _KEY_BYTES, key_type=0x00)),
            _record(0x02, b"\x01\x02\x03"),  # unrelated ACL data
            _record(0x01, _link_key_request_reply_payload(_ADDR_BYTES, _KEY_BYTES)),
        ]
        keys = extract_link_keys(records)
        self.assertEqual(len(keys), 2)
        self.assertEqual({k["source"] for k in keys}, {"Link Key Notification", "Link Key Request Reply"})


if __name__ == "__main__":
    unittest.main()
