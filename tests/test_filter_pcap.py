"""Tests for filter_records() and write_pcap()."""
from __future__ import annotations

import io
import struct
import tempfile
import unittest
from pathlib import Path

from btsnoop_parser import filter_records, parse_btsnoop_file, write_pcap
from btsnoop_parser.core import BTSNOOP_EPOCH_DELTA_US


def _build_capture(*packet_types_and_dirs: tuple[int, int]) -> bytes:
    """Build a minimal BTSnoop file.

    Each tuple is (h4_packet_type, flags) where flags=0 → TX, flags=1 → RX.
    """
    header = b"btsnoop\0" + struct.pack(">II", 1, 1001)
    records = []
    base_ts = BTSNOOP_EPOCH_DELTA_US + 1_000_000
    for i, (ptype, flags) in enumerate(packet_types_and_dirs):
        packet = bytes([ptype, 0x00, 0x00])
        incl_len = len(packet)
        ts = base_ts + i * 1_000_000
        rec = struct.pack(">IIIIQ", incl_len, incl_len, flags, 0, ts) + packet
        records.append(rec)
    return header + b"".join(records)


def _load(data: bytes):
    from btsnoop_parser import iter_records
    return list(iter_records(data))


class TestFilterRecords(unittest.TestCase):
    def setUp(self):
        # 0x01=Command TX, 0x04=Event RX, 0x02=ACL TX, 0x04=Event TX
        self.records = _load(_build_capture(
            (0x01, 0),   # Command TX
            (0x04, 1),   # Event RX
            (0x02, 0),   # ACL TX
            (0x04, 0),   # Event TX
        ))

    def test_filter_by_type_event(self):
        result = filter_records(self.records, ["type:event"])
        self.assertEqual(len(result), 2)
        self.assertTrue(all(r["packet_type"] == 0x04 for r in result))

    def test_filter_by_type_alias_evt(self):
        result = filter_records(self.records, ["type:evt"])
        self.assertEqual(len(result), 2)

    def test_filter_by_type_hex(self):
        result = filter_records(self.records, ["type:0x01"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["packet_type"], 0x01)

    def test_filter_by_type_comma_or(self):
        result = filter_records(self.records, ["type:command,acl"])
        self.assertEqual(len(result), 2)
        types = {r["packet_type"] for r in result}
        self.assertEqual(types, {0x01, 0x02})

    def test_filter_by_dir_rx(self):
        result = filter_records(self.records, ["dir:rx"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["direction"], "RX")

    def test_filter_by_dir_tx(self):
        result = filter_records(self.records, ["dir:tx"])
        self.assertEqual(len(result), 3)

    def test_filter_combined_and(self):
        result = filter_records(self.records, ["type:event", "dir:tx"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["packet_type"], 0x04)
        self.assertEqual(result[0]["direction"], "TX")

    def test_no_filters_returns_all(self):
        result = filter_records(self.records, [])
        self.assertEqual(len(result), 4)

    def test_invalid_key_raises(self):
        with self.assertRaises(ValueError):
            filter_records(self.records, ["addr:AA:BB"])

    def test_invalid_type_raises(self):
        with self.assertRaises(ValueError):
            filter_records(self.records, ["type:garbage"])

    def test_invalid_dir_raises(self):
        with self.assertRaises(ValueError):
            filter_records(self.records, ["dir:sideways"])

    def test_missing_colon_raises(self):
        with self.assertRaises(ValueError):
            filter_records(self.records, ["typeevent"])


class TestWritePcap(unittest.TestCase):
    def setUp(self):
        self.records = _load(_build_capture(
            (0x01, 0),  # Command TX
            (0x04, 1),  # Event RX
        ))

    def _read_pcap(self, buf: bytes):
        """Parse global header and return (link_type, packets)."""
        magic, maj, min_, zone, sig, snap, linktype = struct.unpack_from("<IHHiIII", buf, 0)
        self.assertEqual(magic, 0xA1B2C3D4)
        self.assertEqual(maj, 2)
        packets = []
        offset = 24
        while offset + 16 <= len(buf):
            ts_sec, ts_usec, incl, orig = struct.unpack_from("<IIII", buf, offset)
            offset += 16
            data = buf[offset:offset + incl]
            offset += incl
            packets.append((ts_sec, ts_usec, data))
        return linktype, packets

    def test_write_to_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.pcap"
            n = write_pcap(self.records, path)
            self.assertEqual(n, 2)
            data = path.read_bytes()
        linktype, pkts = self._read_pcap(data)
        self.assertEqual(linktype, 201)
        self.assertEqual(len(pkts), 2)

    def test_write_to_file_object(self):
        buf = io.BytesIO()
        n = write_pcap(self.records, buf)
        self.assertEqual(n, 2)
        _, pkts = self._read_pcap(buf.getvalue())
        self.assertEqual(len(pkts), 2)

    def test_pseudo_header_direction(self):
        buf = io.BytesIO()
        write_pcap(self.records, buf)
        _, pkts = self._read_pcap(buf.getvalue())
        # First record is TX → pseudo-header = 0x00000000
        phdr_tx = struct.unpack_from("<I", pkts[0][2], 0)[0]
        self.assertEqual(phdr_tx, 0x00000000)
        # Second record is RX → pseudo-header = 0x00000001
        phdr_rx = struct.unpack_from("<I", pkts[1][2], 0)[0]
        self.assertEqual(phdr_rx, 0x00000001)

    def test_h4_type_byte_present(self):
        buf = io.BytesIO()
        write_pcap(self.records, buf)
        _, pkts = self._read_pcap(buf.getvalue())
        # Byte 4 (after 4-byte pseudo-header) is the H4 type byte
        self.assertEqual(pkts[0][2][4], 0x01)  # Command
        self.assertEqual(pkts[1][2][4], 0x04)  # Event

    def test_empty_records(self):
        buf = io.BytesIO()
        n = write_pcap([], buf)
        self.assertEqual(n, 0)
        # Should still have a valid global header
        self.assertEqual(len(buf.getvalue()), 24)


if __name__ == "__main__":
    unittest.main()
