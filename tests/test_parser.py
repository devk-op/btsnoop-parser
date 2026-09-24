from __future__ import annotations

import datetime
import os
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Iterable

from btsnoop_parser import decode_hci_packet, iter_records, parse_btsnoop_file
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



class AndroidTimestampOffsetTests(unittest.TestCase):
    """Android can write timestamps 378 days ahead; correction is anchored, not tied to 'now'."""

    TRUE_TIME = datetime.datetime(2025, 9, 13, 8, 22, tzinfo=datetime.timezone.utc)
    OFFSET = datetime.timedelta(days=378)

    def _capture(self, first: datetime.datetime, count: int = 3) -> bytes:
        epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
        base_us = BTSNOOP_EPOCH_DELTA_US + int((first - epoch).total_seconds() * 1_000_000)
        header = b"btsnoop\0" + struct.pack(">II", 1, 1002)
        body = b"".join(
            struct.pack(">IIIIQ", 4, 4, 0, 0, base_us + i * 1_000_000) + bytes([0x01, 0x03, 0x0C, 0x00])
            for i in range(count)
        )
        return header + body

    def test_buggy_offset_corrected_against_reference(self):
        data = self._capture(self.TRUE_TIME + self.OFFSET)
        reference = self.TRUE_TIME + datetime.timedelta(days=20)
        records = list(iter_records(data, reference_time=reference))
        self.assertEqual(records[0]["timestamp"], self.TRUE_TIME)
        self.assertEqual(records[2]["delta"], 2.0)

    def test_correction_does_not_depend_on_when_you_run_it(self):
        # A year after the fact, the buggy date is in the past relative to 'now';
        # anchoring to the reference (e.g. file mtime) must still correct it.
        data = self._capture(self.TRUE_TIME + self.OFFSET)
        reference = self.TRUE_TIME + datetime.timedelta(days=20)
        for _ in range(2):
            self.assertEqual(next(iter_records(data, reference_time=reference))["timestamp"], self.TRUE_TIME)

    def test_normal_timestamps_untouched(self):
        data = self._capture(self.TRUE_TIME)
        reference = self.TRUE_TIME + datetime.timedelta(days=20)
        self.assertEqual(next(iter_records(data, reference_time=reference))["timestamp"], self.TRUE_TIME)

    def test_path_uses_file_mtime_as_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "buggy.btsnoop"
            path.write_bytes(self._capture(self.TRUE_TIME + self.OFFSET))
            mtime = (self.TRUE_TIME + datetime.timedelta(days=20)).timestamp()
            os.utime(path, (mtime, mtime))
            self.assertEqual(parse_btsnoop_file(path)[0]["timestamp"], self.TRUE_TIME)


if __name__ == "__main__":
    unittest.main()
