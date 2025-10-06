from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from typing import Iterable

from btsnoop_parser import decode_hci_packet, parse_btsnoop_file
from btsnoop_parser.core import BTSNOOP_EPOCH_DELTA_US


def build_sample_bytes(events: Iterable[bytes]) -> bytes:
    header = b"btsnoop\0" + struct.pack(">II", 1, 1001)
    records = []
    base_ts = BTSNOOP_EPOCH_DELTA_US + 1_000_000
    for index, packet in enumerate(events):
        incl_len = len(packet)
        timestamp = base_ts + index * 2000
        record_hdr = struct.pack(">IIIIQ", incl_len, incl_len, 0, 0, timestamp)
        records.append(record_hdr + packet)
    return header + b"".join(records)


class ParserTests(unittest.TestCase):
    def setUp(self) -> None:
        command_packet = bytes([0x01, 0x03, 0x0C, 0x00])  # HCI Reset command
        self._tmpdir = tempfile.TemporaryDirectory()
        self.sample_path = Path(self._tmpdir.name) / "sample.btsnoop"
        self.sample_path.write_bytes(build_sample_bytes([command_packet]))

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_can_parse_sample_file(self) -> None:
        records = parse_btsnoop_file(self.sample_path)
        self.assertIsInstance(records, list)
        self.assertTrue(records)
        self.assertEqual(records[0]["packet_type"], 0x01)
        self.assertEqual(records[0]["direction"], "TX")

    def test_record_has_expected_fields(self) -> None:
        record = parse_btsnoop_file(self.sample_path)[0]
        self.assertEqual(record["packet_data"], record["payload"])
        self.assertTrue(str(record["packet_type_name"]).startswith("Command"))
        self.assertAlmostEqual(record["delta"], 0.0)
        self.assertEqual(record["index"], 1)

    def test_can_decode_command_with_int_packet_type(self) -> None:
        record = parse_btsnoop_file(self.sample_path)[0]
        decoded = decode_hci_packet(record["packet_type"], record["payload"])
        self.assertEqual(decoded["type"], "COMMAND")
        self.assertEqual(decoded["name"], "Reset")
        self.assertEqual(decoded["opcode"], 0x0C03)


if __name__ == "__main__":
    unittest.main()
