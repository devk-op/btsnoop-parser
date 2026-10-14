"""Tests for protocol decoding above HCI (L2CAP, RFCOMM, HFP)."""
from __future__ import annotations

import datetime
import struct
import unittest

from btsnoop_parser import avdtp
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
        self.clock = _TS

    def _add(self, packet_type: int, direction: str, payload: bytes, keep: int = 0) -> None:
        self.clock += datetime.timedelta(milliseconds=1)
        self.records.append({
            "index": len(self.records) + 1,
            "timestamp": self.clock,
            "direction": direction,
            "packet_type": packet_type,
            "payload": payload[:keep] if keep else payload,
            "original_length": len(payload) + 1,
            "captured_length": (min(keep, len(payload)) if keep else len(payload)) + 1,
        })

    def wait(self, seconds: float) -> None:
        self.clock += datetime.timedelta(seconds=seconds)

    def event(self, payload: bytes) -> None:
        self._add(0x04, "RX", payload)

    def acl(self, direction: str, data: bytes, first: bool = True, handle: int = _HANDLE, keep: int = 0) -> None:
        flags = 0x2 if first else 0x1
        self._add(0x02, direction, struct.pack("<HH", handle | (flags << 12), len(data)) + data, keep=keep)

    def l2cap(self, direction: str, cid: int, payload: bytes, split: int = 0, keep: int = 0) -> None:
        """Send an L2CAP frame; `keep` stores only the first bytes, like Android's filtered snoop mode."""
        frame = struct.pack("<HH", len(payload), cid) + payload
        if split:
            self.acl(direction, frame[:split])
            self.acl(direction, frame[split:], first=False)
        else:
            self.acl(direction, frame, keep=keep)

    def avdtp(self, direction: str, cid: int, label: int, message_type: int, signal: int, body: bytes = b"") -> None:
        self.l2cap(direction, cid, bytes([(label << 4) | message_type, signal]) + body)

    def media(self, cid: int, seq: int, keep: int = 0) -> None:
        rtp = bytes([0x80, 0x60]) + struct.pack(">HII", seq, seq * 128, 1)
        self.l2cap("TX", cid, rtp + bytes(600), keep=keep)

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

        self.assertEqual([e.protocol for e in trace.events], ["HCI", "L2CAP", "RFCOMM", "HFP", "HFP", "HFP"])
        self.assertEqual(trace.events[2].summary, "Opening serial port 3")
        self.assertEqual([e.summary for e in trace.events[3:]], ["AT+BRSF=128", "+BRSF: 8", "OK"])
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


_SBC_CONFIG = bytes([0x07, 0x06, 0x00, 0x00, 0x21, 0x15, 0x02, 0x35])  # SBC 44.1 kHz joint stereo, bitpool 2-53
_SIG, _MEDIA = 0x0041, 0x0042  # host's CIDs; the remote's are 0x0051 and 0x0052


class TestAvdtp(unittest.TestCase):
    def _describe(self, payload: bytes) -> tuple[str, bool]:
        return avdtp.describe(avdtp.parse_signal(payload))

    def test_parse_header(self):
        sig = avdtp.parse_signal(bytes([0x50, 0x09, 0x10]))
        self.assertEqual((sig.label, sig.message_type, sig.signal, sig.name), (5, 0, 0x09, "Suspend"))
        self.assertIsNone(avdtp.parse_signal(bytes([0x58, 0x01])))  # continuation packet

    def test_discover_answer_lists_endpoints(self):
        text, _ = self._describe(bytes([0x02, 0x01, 0x04, 0x08, 0x0A, 0x08]))
        self.assertEqual(text, "Endpoints: 1 (audio sink), 2 (audio sink, in use)")

    def test_capabilities_name_codecs_and_features(self):
        ldac = bytes([0x07, 0x0A, 0x00, 0xFF]) + struct.pack("<IH", 0x012D, 0x00AA) + bytes(2)
        text, _ = self._describe(bytes([0x02, 0x0C]) + _SBC_CONFIG + ldac + bytes([0x08, 0x00]))
        self.assertEqual(text, "Supports SBC 44.1 kHz joint stereo, bitpool 2-53, LDAC; delay reporting")

    def test_set_configuration(self):
        text, _ = self._describe(bytes([0x30, 0x03, 0x04, 0x04, 0x01, 0x00]) + _SBC_CONFIG)
        self.assertEqual(text, "Configures the stream: SBC 44.1 kHz joint stereo, bitpool 2-53")

    def test_aac_sample_rate(self):
        aac = bytes([0x00, 0x02, 0x80, 0x01, 0x8C, 0x84, 0x00, 0x00])  # 44.1 kHz / 48 kHz
        self.assertEqual(avdtp.describe_codec(aac), "AAC 44.1 kHz/48 kHz")

    def test_reject_gives_reason(self):
        self.assertEqual(self._describe(bytes([0x33, 0x03, 0x07, 0xC2])), ("Set Configuration rejected: codec type not supported", True))
        self.assertEqual(self._describe(bytes([0x33, 0x07, 0x04, 0x31])), ("Start rejected: wrong state for this command", True))
        self.assertEqual(self._describe(bytes([0x31, 0x06])), ("Open not understood by the other device", True))

    def test_delay_report(self):
        self.assertEqual(self._describe(bytes([0x40, 0x0D, 0x04, 0x05, 0xDC]))[0], "Reports an audio delay of 150.0 ms")

    def test_start_and_suspend(self):
        self.assertEqual(self._describe(bytes([0x50, 0x07, 0x04]))[0], "Asks to start streaming audio")
        self.assertEqual(self._describe(bytes([0x52, 0x09]))[0], "Audio stream paused")

    def test_media_packet_detection(self):
        self.assertTrue(avdtp.is_media_packet(bytes([0x80, 0x60]), 600))
        self.assertFalse(avdtp.is_media_packet(bytes([0x80, 0x60]), 20))
        self.assertFalse(avdtp.is_media_packet(bytes([0x22, 0x11]), 600))


class TestA2dpTrace(unittest.TestCase):
    def _connected(self) -> _Capture:
        capture = _Capture()
        capture.connected()
        return capture

    def _session(self) -> _Capture:
        capture = self._connected()
        capture.open_channel(psm=0x0019, scid=_SIG, dcid=0x0051, ident=1)
        capture.avdtp("RX", 0x0051, 3, 0, 0x03, bytes([0x04, 0x04]) + _SBC_CONFIG)
        capture.avdtp("TX", _SIG, 3, 2, 0x03)
        capture.open_channel(psm=0x0019, scid=_MEDIA, dcid=0x0052, ident=2)
        capture.avdtp("RX", 0x0051, 4, 0, 0x07, bytes([0x04]))
        capture.avdtp("TX", _SIG, 4, 2, 0x07)
        return capture

    def _a2dp(self, trace: ProtocolTrace) -> list[tuple[str, str]]:
        trace.finish()
        return [(e.summary, e.detail) for e in trace.events if e.protocol == "A2DP"]

    def test_full_session(self):
        capture = self._session()
        for seq in range(3):
            capture.media(_MEDIA, seq)
        capture.wait(1.0)
        capture.avdtp("RX", 0x0051, 5, 0, 0x09, bytes([0x04]))
        capture.avdtp("TX", _SIG, 5, 2, 0x09)
        trace = _trace(capture)

        events = self._a2dp(trace)
        self.assertEqual([s for s, _ in events], ["Set Configuration", "Set Configuration accept", "Start",
                                                 "Start accept", "Suspend", "Suspend accept", "Stream summary"])
        self.assertEqual(events[0][1], "Configures the stream: SBC 44.1 kHz joint stereo, bitpool 2-53")
        self.assertTrue(events[-1][1].startswith("0.0 s of SBC 44.1 kHz joint stereo, bitpool 2-53 audio: 3 packets"))
        self.assertEqual(trace.frame_counts[("11:22:33:44:55:66", "A2DP Media")], 3)
        self.assertEqual(trace.frame_counts[("11:22:33:44:55:66", "AVDTP")], 6)

    def test_stall_is_flagged(self):
        capture = self._session()
        capture.media(_MEDIA, 1)
        capture.wait(3.0)
        capture.media(_MEDIA, 2)
        stall = [d for s, d in self._a2dp(_trace(capture)) if s == "Audio stalled"]
        self.assertEqual(len(stall), 1)
        self.assertTrue(stall[0].startswith("No audio sent for 3.0 s"))

    def test_disconnect_ends_stream(self):
        capture = self._session()
        capture.media(_MEDIA, 1)
        capture.event(bytes([0x05, 0x04, 0x00]) + struct.pack("<H", _HANDLE) + bytes([0x13]))
        trace = _trace(capture)
        trace.finish()
        tail = [(e.protocol, e.summary) for e in trace.events][-2:]
        self.assertEqual(tail, [("A2DP", "Stream summary"), ("HCI", "Disconnected")])

    def test_stream_running_at_end_of_capture(self):
        capture = self._session()
        capture.media(_MEDIA, 1)
        summary = self._a2dp(_trace(capture))[-1]
        self.assertTrue(summary[1].endswith("(still streaming when the capture ended)"))


class TestChannelsOpenedBeforeCapture(unittest.TestCase):
    """Filtered btsnooz captures often begin after the channels were set up."""

    def test_media_found_from_rtp_header(self):
        capture = _Capture()
        capture.media(0x0061, 1, keep=15)
        capture.media(0x0061, 2, keep=15)
        trace = _trace(capture)
        trace.finish()
        events = [(e.summary, e.detail) for e in trace.events]
        self.assertEqual(events[0], ("Audio streaming", "Already streaming when the capture began"))
        self.assertIn("2 packets", events[-1][1])
        self.assertEqual(trace.truncated_frames, 2)

    def test_signaling_found_from_command_and_answer(self):
        capture = _Capture()
        capture.avdtp("TX", 0x005C, 5, 0, 0x09, bytes([0x10]))
        capture.avdtp("RX", 0x004A, 5, 2, 0x09)
        capture.avdtp("RX", 0x004A, 11, 0, 0x08, bytes([0x14]))
        trace = _trace(capture)
        self.assertEqual([e.summary for e in trace.events], ["Suspend", "Suspend accept", "Close"])
        self.assertEqual(trace.frame_counts[("handle 0x00B", "AVDTP")], 3)
        self.assertNotIn(("handle 0x00B", "L2CAP"), trace.frame_counts)

    def test_unanswered_lookalike_is_not_avdtp(self):
        capture = _Capture()
        capture.l2cap("TX", 0x0066, bytes([0x00, 0x01]))  # could be an AVDTP Discover, but nothing answers
        capture.l2cap("TX", 0x0066, bytes([0x02, 0x01, 0x81, 0x00]))
        trace = _trace(capture)
        self.assertEqual(trace.events, [])
        self.assertEqual(trace.frame_counts[("handle 0x00B", "L2CAP")], 2)

    def test_closing_an_identified_channel(self):
        capture = _Capture()
        capture.media(0x0061, 1)
        capture.signal("RX", 0x06, 9, struct.pack("<HH", 0x0069, 0x0061))
        trace = _trace(capture)
        self.assertIn("A2DP audio channel closed", [e.summary for e in trace.events])

    def test_truncated_frame_keeps_declared_length(self):
        capture = _Capture()
        capture.l2cap("RX", 0x0004, bytes(100), keep=12)
        frame = L2capDecoder().feed(capture.records[0])
        self.assertEqual((frame.length, len(frame.payload), frame.truncated), (100, 4, True))


if __name__ == "__main__":
    unittest.main()
