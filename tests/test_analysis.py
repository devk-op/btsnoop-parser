"""Tests for the CaptureStats analysis module."""
from __future__ import annotations

import datetime
import struct
import unittest

from btsnoop_parser.analysis import CaptureStats


_UTC = datetime.timezone.utc
_BASE_TS = datetime.datetime(2024, 1, 1, 12, 0, 0, tzinfo=_UTC)


def _record(payload: bytes, ts: datetime.datetime = _BASE_TS) -> dict:
    """Build a minimal HCI EVENT record."""
    return {
        "packet_type": 0x04,
        "packet_type_name": "EVENT",
        "payload": payload,
        "timestamp": ts,
        "original_length": len(payload),
    }


def _disconnect_payload(handle: int, reason: int, status: int = 0x00) -> bytes:
    # [Event(0x05), Len, Status, HandleLSB, HandleMSB, Reason]
    return bytes([0x05, 0x04, status, handle & 0xFF, (handle >> 8) & 0xFF, reason])


def _le_conn_complete_payload(status: int, handle: int = 0x001, addr: bytes = b"\x11\x22\x33\x44\x55\x66") -> bytes:
    # [Event(0x3E), Len, Subevent(0x01), Status, HandleLSB, HandleMSB, Role, AddrType, Addr(6)]
    return bytes([0x3E, 0x0D, 0x01, status, handle & 0xFF, (handle >> 8) & 0xFF, 0x00, 0x00]) + addr


def _classic_conn_complete_payload(status: int, handle: int = 0x001, addr: bytes = b"\x11\x22\x33\x44\x55\x66") -> bytes:
    # [Event(0x03), Len, Status, HandleLSB, HandleMSB, Addr(6), LinkType, EncMode]
    return bytes([0x03, 0x0B, status, handle & 0xFF, (handle >> 8) & 0xFF]) + addr + bytes([0x01, 0x00])


def _cmd_complete_payload(opcode: int, status: int) -> bytes:
    # [Event(0x0E), Len, NumCmds, OpcodeLSB, OpcodeMSB, Status]
    return bytes([0x0E, 0x04, 0x01, opcode & 0xFF, (opcode >> 8) & 0xFF, status])


class TestDisconnection(unittest.TestCase):
    def _stats(self, reason: int) -> CaptureStats:
        s = CaptureStats()
        s.analyze_record(_record(_disconnect_payload(0x001, reason)))
        return s

    def test_normal_remote_disconnect_no_issue(self):
        s = self._stats(0x13)  # Remote User Terminated
        self.assertEqual(len(s.issues), 0)
        self.assertFalse(s.lifecycle_events[0]["is_error"])

    def test_normal_local_disconnect_no_issue(self):
        s = self._stats(0x16)  # Local Host Terminated
        self.assertEqual(len(s.issues), 0)

    def test_power_off_disconnect_not_abnormal(self):
        """0x15 (Remote Power Off) should not be flagged as abnormal."""
        s = self._stats(0x15)
        self.assertEqual(len(s.issues), 0)
        self.assertFalse(s.lifecycle_events[0]["is_error"])

    def test_low_resources_disconnect_not_abnormal(self):
        """0x14 (Remote Low Resources) should not be flagged as abnormal."""
        s = self._stats(0x14)
        self.assertEqual(len(s.issues), 0)

    def test_unexpected_disconnect_raises_issue(self):
        s = self._stats(0x08)  # Connection Timeout
        self.assertEqual(len(s.issues), 1)
        self.assertEqual(s.issues[0]["title"], "Abnormal Disconnect")
        self.assertTrue(s.lifecycle_events[0]["is_error"])


class TestLEConnectionFailed(unittest.TestCase):
    def test_failed_le_connection_appears_in_lifecycle(self):
        """A failed LE connection should appear in lifecycle_events, not just issues."""
        s = CaptureStats()
        s.analyze_record(_record(_le_conn_complete_payload(status=0x02)))  # 0x02 = No Connection
        self.assertEqual(len(s.lifecycle_events), 1)
        self.assertEqual(s.lifecycle_events[0]["event"], "Connect Failed (LE)")
        self.assertTrue(s.lifecycle_events[0]["is_error"])
        self.assertEqual(len(s.issues), 1)

    def test_successful_le_connection_no_issue(self):
        s = CaptureStats()
        s.analyze_record(_record(_le_conn_complete_payload(status=0x00)))
        self.assertEqual(len(s.issues), 0)
        self.assertEqual(s.lifecycle_events[0]["event"], "Connected (LE)")


class TestClassicConnectionFailed(unittest.TestCase):
    def test_failed_classic_connection_appears_in_lifecycle(self):
        s = CaptureStats()
        s.analyze_record(_record(_classic_conn_complete_payload(status=0x04)))  # Page Timeout
        self.assertEqual(len(s.lifecycle_events), 1)
        self.assertEqual(s.lifecycle_events[0]["event"], "Connect Failed (Classic)")
        self.assertTrue(s.lifecycle_events[0]["is_error"])
        self.assertEqual(len(s.issues), 1)

    def test_successful_classic_connection_no_issue(self):
        s = CaptureStats()
        s.analyze_record(_record(_classic_conn_complete_payload(status=0x00)))
        self.assertEqual(len(s.issues), 0)
        self.assertEqual(s.lifecycle_events[0]["event"], "Connected (Classic)")


class TestCommandFailure(unittest.TestCase):
    def test_command_failure_uses_opcode_name(self):
        """Command errors should show the opcode name, not raw hex."""
        s = CaptureStats()
        # 0x0C03 = Reset
        s.analyze_record(_record(_cmd_complete_payload(opcode=0x0C03, status=0x01)))
        self.assertEqual(len(s.issues), 1)
        self.assertIn("Reset", s.issues[0]["detail"])
        self.assertNotIn("0x0C03", s.issues[0]["detail"])

    def test_unknown_opcode_falls_back_to_hex(self):
        s = CaptureStats()
        s.analyze_record(_record(_cmd_complete_payload(opcode=0xFFFF, status=0x01)))
        self.assertIn("0xFFFF", s.issues[0]["detail"])

    def test_successful_command_no_issue(self):
        s = CaptureStats()
        s.analyze_record(_record(_cmd_complete_payload(opcode=0x0C03, status=0x00)))
        self.assertEqual(len(s.issues), 0)


class TestDurationFormat(unittest.TestCase):
    def _stats_with_duration(self, seconds: float) -> CaptureStats:
        s = CaptureStats()
        s.start_time = _BASE_TS
        s.end_time = _BASE_TS + datetime.timedelta(seconds=seconds)
        return s

    def test_seconds_only(self):
        s = self._stats_with_duration(5.456)
        # Trigger format by calling print_summary via capturing output
        import io, unittest.mock
        with unittest.mock.patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            s.print_summary()
        self.assertIn("5.456s", mock_out.getvalue())

    def test_minutes_and_seconds(self):
        s = self._stats_with_duration(125.0)
        import io, unittest.mock
        with unittest.mock.patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            s.print_summary()
        self.assertIn("2m", mock_out.getvalue())

    def test_hours_minutes_seconds(self):
        s = self._stats_with_duration(3661.0)
        import io, unittest.mock
        with unittest.mock.patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            s.print_summary()
        self.assertIn("1h", mock_out.getvalue())


if __name__ == "__main__":
    unittest.main()
