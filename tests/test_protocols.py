"""Tests for protocol decoding above HCI (L2CAP, RFCOMM, HFP)."""
from __future__ import annotations

import datetime
import struct
import unittest

from btsnoop_parser.hfp import HfpSession, looks_like_at, split_lines
from btsnoop_parser.l2cap import L2capDecoder
from btsnoop_parser.protocols import ProtocolTrace
from btsnoop_parser.rfcomm import parse_frame

_TS = datetime.datetime(2024, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
_HANDLE = 0x00B
_ADDR = bytes.fromhex("665544332211")  # 11:22:33:44:55:66 in wire order


class _Capture:
    """Builds records the way iter_records() yields them."""

    def __init__(self) -> None:
        self.records: list[dict] = []

    def _add(self, packet_type: int, direction: str, payload: bytes) -> None:
        self.records.append({
            "index": len(self.records) + 1,
            "timestamp": _TS + datetime.timedelta(milliseconds=len(self.records)),
            "direction": direction,
            "packet_type": packet_type,
            "payload": payload,
        })

    def event(self, payload: bytes) -> None:
        self._add(0x04, "RX", payload)

    def acl(self, direction: str, data: bytes, first: bool = True, handle: int = _HANDLE) -> None:
        flags = 0x2 if first else 0x1
        self._add(0x02, direction, struct.pack("<HH", handle | (flags << 12), len(data)) + data)

    def l2cap(self, direction: str, cid: int, payload: bytes, split: int = 0) -> None:
        frame = struct.pack("<HH", len(payload), cid) + payload
        if split:
            self.acl(direction, frame[:split])
            self.acl(direction, frame[split:], first=False)
        else:
            self.acl(direction, frame)

    def signal(self, direction: str, code: int, ident: int, body: bytes) -> None:
        self.l2cap(direction, 0x0001, struct.pack("<BBH", code, ident, len(body)) + body)

    def open_channel(self, psm: int, scid: int, dcid: int, ident: int = 1, result: int = 0) -> None:
        """The remote device (RX) opens a channel to the host."""
        self.signal("RX", 0x02, ident, struct.pack("<HH", psm, scid))
        self.signal("TX", 0x03, ident, struct.pack("<HHHH", dcid, scid, result, 0))

    def rfcomm(self, direction: str, cid: int, dlci: int, control: int, payload: bytes = b"", split: int = 0) -> None:
        frame = bytes([(dlci << 2) | 0x03, control, (len(payload) << 1) | 0x01]) + payload + b"\x00"
        self.l2cap(direction, cid, frame, split=split)

    def connected(self) -> None:
        # [Connection Complete, Len, Status, Handle(2), Addr(6), LinkType, Encryption]
        self.event(bytes([0x03, 0x0B, 0x00]) + struct.pack("<H", _HANDLE) + _ADDR + bytes([0x01, 0x00]))


def _trace(capture: _Capture) -> ProtocolTrace:
    trace = ProtocolTrace()
    for record in capture.records:
        trace.analyze_record(record)
    return trace


class TestL2cap(unittest.TestCase):
    def _frames(self, capture: _Capture) -> list:
        decoder = L2capDecoder()
        return [f for f in map(decoder.feed, capture.records) if f is not None]

    def test_fixed_channels_are_named(self):
        capture = _Capture()
        capture.l2cap("TX", 0x0004, b"\x02\x17\x00")
        capture.l2cap("RX", 0x0006, b"\x0b\x01")
        self.assertEqual([f.protocol for f in self._frames(capture)], ["ATT", "SMP"])

    def test_fragments_are_reassembled(self):
        capture = _Capture()
        capture.l2cap("RX", 0x0004, bytes(range(40)), split=10)
        frames = self._frames(capture)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].payload, bytes(range(40)))
        self.assertEqual(frames[0].index, 1)

    def test_continuation_without_start_is_ignored(self):
        capture = _Capture()
        capture.acl("RX", b"\x01\x02\x03\x04\x05", first=False)
        self.assertEqual(self._frames(capture), [])

    def test_dynamic_channel_is_labelled_in_both_directions(self):
        capture = _Capture()
        capture.open_channel(psm=0x0019, scid=0x0041, dcid=0x0052)
        capture.l2cap("TX", 0x0041, b"\x00")  # to the requester's CID
        capture.l2cap("RX", 0x0052, b"\x00")  # to the responder's CID
        frames = self._frames(capture)
        self.assertEqual(frames[1].notes, [("AVDTP channel opened", False)])
        self.assertEqual([f.protocol for f in frames[2:]], ["AVDTP", "AVDTP"])

    def test_refused_channel_is_reported_and_not_tracked(self):
        capture = _Capture()
        capture.open_channel(psm=0x0003, scid=0x0041, dcid=0x0000, result=0x0003)
        capture.l2cap("TX", 0x0041, b"\x00")
        frames = self._frames(capture)
        self.assertEqual(frames[1].notes, [("RFCOMM channel refused: security block", True)])
        self.assertEqual(frames[2].protocol, "L2CAP")

    def test_pending_response_keeps_request_open(self):
        capture = _Capture()
        capture.signal("RX", 0x02, 1, struct.pack("<HH", 0x0001, 0x0041))
        capture.signal("TX", 0x03, 1, struct.pack("<HHHH", 0x0052, 0x0041, 0x0001, 0))
        capture.signal("TX", 0x03, 1, struct.pack("<HHHH", 0x0052, 0x0041, 0x0000, 0))
        frames = self._frames(capture)
        self.assertEqual(frames[1].notes, [])
        self.assertEqual(frames[2].notes, [("SDP channel opened", False)])

    def test_disconnect_request_closes_channel(self):
        capture = _Capture()
        capture.open_channel(psm=0x0001, scid=0x0041, dcid=0x0052)
        capture.signal("RX", 0x06, 2, struct.pack("<HH", 0x0052, 0x0041))
        capture.l2cap("RX", 0x0052, b"\x00")
        frames = self._frames(capture)
        self.assertEqual(frames[2].notes, [("SDP channel closed", False)])
        self.assertEqual(frames[3].protocol, "L2CAP")

    def test_le_credit_based_channel(self):
        capture = _Capture()
        capture.signal("RX", 0x14, 5, struct.pack("<HHHHH", 0x0027, 0x0040, 64, 64, 1))
        capture.signal("TX", 0x15, 5, struct.pack("<HHHHH", 0x0048, 64, 64, 1, 0))
        capture.l2cap("RX", 0x0048, b"\x00")
        self.assertEqual(self._frames(capture)[2].protocol, "EATT")

    def test_unknown_dynamic_channel(self):
        capture = _Capture()
        capture.l2cap("RX", 0x0077, b"\x00")
        self.assertEqual(self._frames(capture)[0].protocol, "L2CAP")


class TestRfcomm(unittest.TestCase):
    def test_data_frame(self):
        frame = parse_frame(bytes([(6 << 2) | 0x03, 0xEF, (2 << 1) | 0x01]) + b"OK" + b"\x9a")
        self.assertEqual((frame.dlci, frame.channel, frame.frame_type, frame.payload), (6, 3, "UIH", b"OK"))

    def test_credit_byte_is_skipped(self):
        frame = parse_frame(bytes([(6 << 2) | 0x03, 0xFF, (2 << 1) | 0x01, 0x21]) + b"OK" + b"\x9a")
        self.assertEqual(frame.payload, b"OK")

    def test_two_byte_length(self):
        body = b"A" * 200
        frame = parse_frame(bytes([(6 << 2) | 0x03, 0xEF, (200 & 0x7F) << 1, 200 >> 7]) + body + b"\x00")
        self.assertEqual(frame.payload, body)

    def test_control_frames(self):
        for control, name in ((0x3F, "SABM"), (0x73, "UA"), (0x1F, "DM"), (0x53, "DISC")):
            self.assertEqual(parse_frame(bytes([0x1B, control, 0x01, 0x00])).frame_type, name)

    def test_malformed_frames(self):
        self.assertIsNone(parse_frame(b"\x1b\xef"))
        self.assertIsNone(parse_frame(bytes([0x1B, 0x99, 0x01, 0x00])))
        self.assertIsNone(parse_frame(bytes([0x1B, 0xEF, (9 << 1) | 0x01]) + b"AT"))


class TestHfp(unittest.TestCase):
    def test_feature_exchange(self):
        session = HfpSession()
        self.assertIn("codec negotiation", session.describe("AT+BRSF=128")[0])
        self.assertIn("in-band ringtone", session.describe("+BRSF: 8")[0])

    def test_codecs(self):
        session = HfpSession()
        self.assertEqual(session.describe("AT+BAC=1,2")[0], "Hands-free supports codecs: CVSD, mSBC")
        self.assertEqual(session.describe("+BCS: 2")[0], "Phone selects codec mSBC")

    def test_indicator_updates_use_names_from_cind(self):
        session = HfpSession()
        session.describe('+CIND: ("service",(0,1)),("call",(0,1)),("callsetup",(0-3)),("battchg",(0-5))')
        self.assertEqual(session.describe("+CIEV: 3,1")[0], "Status update: incoming call")
        self.assertEqual(session.describe("+CIEV: 2,1")[0], "Status update: call active")
        self.assertEqual(session.describe("+CIEV: 4,3")[0], "Status update: phone battery 3/5")

    def test_indicator_update_without_cind(self):
        self.assertEqual(HfpSession().describe("+CIEV: 3,1")[0], "Status update: indicator 3 = 1")

    def test_call_control(self):
        session = HfpSession()
        self.assertEqual(session.describe("ATA")[0], "Answers the incoming call")
        self.assertEqual(session.describe("AT+CHUP")[0], "Hangs up / rejects the call")
        self.assertEqual(session.describe("ATD5551234;")[0], "Dials 5551234")
        self.assertEqual(session.describe("RING")[0], "Incoming call is ringing")
        self.assertEqual(session.describe('+CLIP: "5551234",129')[0], "Caller ID: 5551234")

    def test_volume(self):
        self.assertEqual(HfpSession().describe("AT+VGS=12")[0], "Hands-free speaker volume is 12/15")

    def test_errors_are_flagged(self):
        session = HfpSession()
        self.assertTrue(session.describe("ERROR")[1])
        self.assertTrue(session.describe("+CME ERROR: 30")[1])
        self.assertFalse(session.describe("OK")[1])

    def test_unknown_command(self):
        self.assertEqual(HfpSession().describe("AT+ZZZ=1")[0], "Command")

    def test_split_lines_keeps_unfinished_text(self):
        self.assertEqual(split_lines("\r\n+CIEV: 1,1\r\n\r\nOK\r\n"), (["+CIEV: 1,1", "OK"], ""))
        self.assertEqual(split_lines("AT+BRSF=1\rAT+BA"), (["AT+BRSF=1"], "AT+BA"))

    def test_looks_like_at(self):
        self.assertTrue(looks_like_at("AT+BRSF=959\r"))
        self.assertTrue(looks_like_at("\r\n+CIEV: 1,1\r\n"))
        self.assertTrue(looks_like_at("\r\nOK\r\n"))
        self.assertFalse(looks_like_at("hello"))


class TestProtocolTrace(unittest.TestCase):
    def _hfp_capture(self) -> _Capture:
        capture = _Capture()
        capture.connected()
        capture.open_channel(psm=0x0003, scid=0x0041, dcid=0x0052)
        capture.rfcomm("RX", 0x0052, dlci=6, control=0x3F)  # SABM
        return capture

    def test_hfp_session_end_to_end(self):
        capture = self._hfp_capture()
        capture.rfcomm("RX", 0x0052, 6, 0xEF, b"AT+BRSF=128\r")
        capture.rfcomm("TX", 0x0041, 6, 0xEF, b"\r\n+BRSF: 8\r\n\r\nOK\r\n")
        trace = _trace(capture)

        self.assertEqual([e.protocol for e in trace.events], ["L2CAP", "RFCOMM", "HFP", "HFP", "HFP"])
        self.assertEqual(trace.events[1].summary, "Opening serial port 3")
        self.assertEqual([e.summary for e in trace.events[2:]], ["AT+BRSF=128", "+BRSF: 8", "OK"])
        self.assertTrue(all(e.device == "11:22:33:44:55:66" for e in trace.events))
        self.assertEqual(trace.frame_counts[("11:22:33:44:55:66", "RFCOMM")], 3)
        self.assertEqual(trace.serial_ports[("11:22:33:44:55:66", 3)], [2, 30, True])

    def test_command_split_across_frames_and_packets(self):
        capture = self._hfp_capture()
        capture.rfcomm("RX", 0x0052, 6, 0xEF, b"AT+VG", split=6)
        capture.rfcomm("RX", 0x0052, 6, 0xEF, b"S=9\r")
        hfp = [e for e in _trace(capture).events if e.protocol == "HFP"]
        self.assertEqual([(e.summary, e.detail) for e in hfp], [("AT+VGS=9", "Hands-free speaker volume is 9/15")])

    def test_binary_serial_data_is_counted_not_decoded(self):
        capture = self._hfp_capture()
        capture.rfcomm("RX", 0x0052, 6, 0xEF, b"\x7e\x00\xa5\x03")
        trace = _trace(capture)
        self.assertFalse([e for e in trace.events if e.protocol == "HFP"])
        self.assertEqual(trace.serial_ports[("11:22:33:44:55:66", 3)], [1, 4, False])

    def test_voice_link_lifecycle(self):
        capture = self._hfp_capture()
        sco = 0x00C
        # [Sync Connection Complete, Len, Status, Handle(2), Addr(6), LinkType, Interval, Window, RxLen(2), TxLen(2), AirMode]
        capture.event(bytes([0x2C, 0x11, 0x00]) + struct.pack("<H", sco) + _ADDR
                      + bytes([0x02, 0x0C, 0x04, 0x3C, 0x00, 0x3C, 0x00, 0x03]))
        capture.event(bytes([0x05, 0x04, 0x00]) + struct.pack("<H", sco) + bytes([0x13]))
        voice = [e for e in _trace(capture).events if e.protocol == "Voice"]
        self.assertEqual(voice[0].summary, "Voice link opened (eSCO, mSBC/transparent)")
        self.assertTrue(voice[1].summary.startswith("Voice link closed"))
        self.assertEqual(voice[0].device, "11:22:33:44:55:66")

    def test_failed_voice_link_is_an_error(self):
        capture = self._hfp_capture()
        capture.event(bytes([0x2C, 0x11, 0x1A]) + struct.pack("<H", 0) + _ADDR + bytes(8))
        voice = [e for e in _trace(capture).events if e.protocol == "Voice"]
        self.assertTrue(voice[0].is_error)

    def test_disconnect_forgets_channels(self):
        capture = self._hfp_capture()
        capture.event(bytes([0x05, 0x04, 0x00]) + struct.pack("<H", _HANDLE) + bytes([0x13]))
        capture.rfcomm("RX", 0x0052, 6, 0xEF, b"AT+CHUP\r")
        self.assertFalse([e for e in _trace(capture).events if e.protocol == "HFP"])


if __name__ == "__main__":
    unittest.main()
