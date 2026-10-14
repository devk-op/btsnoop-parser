"""Protocol-level view of a capture: what the devices said above HCI.

:class:`ProtocolTrace` feeds every record through the L2CAP decoder, counts
traffic per protocol, and builds a timeline of the decoded exchanges (channel
setup, RFCOMM ports, HFP commands, A2DP streaming, AVRCP remote control,
voice links).

Captures often start after a connection's channels were opened, so a channel
whose setup was not seen is identified from its contents where that is
reliable: A2DP audio by its RTP header, AVDTP signaling by a command and its
matching answer.
"""
from __future__ import annotations

import collections
import datetime
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from . import avdtp, avrcp
from .constants import HCI_ERROR_CODES
from .hfp import HfpSession, decode_text, looks_like_at, split_lines
from .l2cap import L2capDecoder, L2capFrame
from .rfcomm import parse_frame

_AIR_MODES = {0x00: "u-law", 0x01: "A-law", 0x02: "CVSD", 0x03: "mSBC/transparent"}


@dataclass
class ProtocolEvent:
    """One line of the protocol timeline."""

    index: int
    timestamp: datetime.datetime
    direction: str
    handle: int
    device: str
    protocol: str
    summary: str
    detail: str = ""
    is_error: bool = False
    # Bookkeeping traffic (status polls, acknowledgements) that print_trace leaves out.
    routine: bool = False


@dataclass
class _Stream:
    """A2DP audio sent on one connection since the stream last started."""

    packets: int = 0
    size: int = 0
    first: Optional[L2capFrame] = None
    last: Optional[L2capFrame] = None
    gaps: list[float] = field(default_factory=list)


# A source keeps sending packets while a stream is started, so a longer silence is a stall.
_STALL_SECONDS = 2.0
# How long an unconfirmed AVDTP command waits for its answer.
_ANSWER_WINDOW = datetime.timedelta(seconds=3)


def _addr(data: bytes) -> str:
    return ":".join(f"{b:02X}" for b in data[::-1])


class ProtocolTrace:
    """Decodes the protocols carried in a capture's ACL data."""

    def __init__(self) -> None:
        self.events: list[ProtocolEvent] = []
        self.frame_counts: collections.Counter[tuple[str, str]] = collections.Counter()
        self._l2cap = L2capDecoder()
        # (device, serial port) -> [data frames, bytes, carries HFP]
        self.serial_ports: dict[tuple[str, int], list[Any]] = {}
        self._devices: dict[int, str] = {}
        self._voice_handles: set[int] = set()
        # (handle, dlci) -> HFP state; (handle, dlci, direction) -> unfinished AT text
        self._hfp: dict[tuple[int, int], HfpSession] = {}
        self._at_buffers: dict[tuple[int, int, str], str] = {}
        self.data_frames = 0
        self.truncated_frames = 0
        # (handle, direction, cid) -> protocol, for channels identified from their contents
        self._labels: dict[tuple[int, str, int], str] = {}
        self._candidates: list[tuple[L2capFrame, avdtp.AvdtpSignal]] = []
        self._streams: dict[int, _Stream] = {}
        self._codecs: dict[int, str] = {}
        self._pending_codecs: dict[tuple[int, int], str] = {}
        self._streamed_before_capture: set[int] = set()
        self._started: set[int] = set()
        self._finished = False

    def device(self, handle: int) -> str:
        return self._devices.get(handle, f"handle 0x{handle:03X}")

    def analyze_record(self, record: Mapping[str, Any]) -> None:
        """Ingest a single record."""
        if record["packet_type"] == 0x04:
            self._event(record)
        elif record["packet_type"] == 0x02:
            frame = self._l2cap.feed(record)
            if frame is not None:
                self._frame(frame)

    def _add(self, source: Any, handle: int, protocol: str, summary: str, detail: str = "",
             is_error: bool = False, direction: Optional[str] = None, routine: bool = False) -> None:
        if isinstance(source, L2capFrame):
            index, timestamp, direction = source.index, source.timestamp, direction or source.direction
        else:
            index, timestamp, direction = source["index"], source["timestamp"], direction or source["direction"]
        self.events.append(ProtocolEvent(index, timestamp, direction, handle, self.device(handle),
                                         protocol, summary, detail, is_error, routine))

    def _event(self, record: Mapping[str, Any]) -> None:
        payload = record["payload"]
        if len(payload) < 2:
            return
        code = payload[0]

        if code == 0x03 and len(payload) >= 12 and payload[2] == 0x00 and payload[11] == 0x01:  # ACL Connection Complete
            handle = payload[3] | (payload[4] << 8)
            self._devices[handle] = _addr(payload[5:11])
            self._add(record, handle, "HCI", "Connected", detail="Classic (BR/EDR) link")

        elif code == 0x3E and len(payload) >= 14 and payload[2] in (0x01, 0x0A, 0x29) and payload[3] == 0x00:
            handle = payload[4] | (payload[5] << 8)
            self._devices[handle] = _addr(payload[8:14])
            self._add(record, handle, "HCI", "Connected", detail="LE link")

        elif code == 0x2C and len(payload) >= 19:  # Synchronous Connection Complete
            status, handle = payload[2], payload[3] | (payload[4] << 8)
            link = "eSCO" if payload[11] == 0x02 else "SCO"
            if status == 0x00:
                self._devices[handle] = _addr(payload[5:11])
                self._voice_handles.add(handle)
                codec = _AIR_MODES.get(payload[18], f"air mode 0x{payload[18]:02X}")
                self._add(record, handle, "Voice", f"Voice link opened ({link}, {codec})")
            else:
                reason = HCI_ERROR_CODES.get(status, f"0x{status:02X}")
                self._devices.setdefault(handle, _addr(payload[5:11]))
                self._add(record, handle, "Voice", f"Voice link failed: {reason}", is_error=True)

        elif code == 0x05 and len(payload) >= 6 and payload[2] == 0x00:  # Disconnection Complete
            handle = payload[3] | (payload[4] << 8)
            reason = HCI_ERROR_CODES.get(payload[5], f"0x{payload[5]:02X}")
            if handle in self._voice_handles:
                self._voice_handles.discard(handle)
                self._add(record, handle, "Voice", f"Voice link closed ({reason})")
            else:
                self._stop_stream(record, handle, "")
                self._add(record, handle, "HCI", "Disconnected", detail=reason)
            self._stop_stream(record, handle, "")
            self._l2cap.forget_handle(handle)
            self._candidates = [c for c in self._candidates if c[0].handle != handle]
            for store in (self._hfp, self._at_buffers, self._labels):
                for key in [k for k in store if k[0] == handle]:
                    del store[key]
            self._devices.pop(handle, None)

    def _frame(self, frame: L2capFrame) -> None:
        self.data_frames += 1
        self.truncated_frames += frame.truncated
        protocol = self._identify(frame)
        self.frame_counts[(self.device(frame.handle), protocol)] += 1
        for text, is_error in frame.notes:
            self._add(frame, frame.handle, "L2CAP", text, is_error=is_error)
        if protocol == "L2CAP Signaling":
            self._closed_identified_channels(frame)
        elif protocol == "RFCOMM":
            self._rfcomm(frame)
        elif protocol == "AVDTP":
            self._avdtp(frame)
        elif protocol == "A2DP Media":
            self._media(frame)
        elif protocol == "AVCTP":
            self._avrcp(frame)

    def _closed_identified_channels(self, frame: L2capFrame) -> None:
        """Report the closing of channels that were identified from their contents."""
        data, offset = frame.payload, 0
        while offset + 8 <= len(data):
            code, length = data[offset], data[offset + 2] | (data[offset + 3] << 8)
            if code == 0x06:  # Disconnection Request: data sent the same way used the destination CID
                dcid = data[offset + 4] | (data[offset + 5] << 8)
                scid = data[offset + 6] | (data[offset + 7] << 8)
                label = self._labels.pop((frame.handle, frame.direction, dcid), None)
                other = "RX" if frame.direction == "TX" else "TX"
                label = self._labels.pop((frame.handle, other, scid), None) or label
                if label:
                    name = {"AVDTP": "A2DP signaling", "A2DP Media": "A2DP audio", "AVCTP": "AVRCP"}[label]
                    self._add(frame, frame.handle, "L2CAP", f"{name} channel closed")
            offset += 4 + length

    def _identify(self, frame: L2capFrame) -> str:
        """Name the protocol a frame belongs to, inspecting channels whose setup was not captured."""
        if frame.protocol == "AVDTP":
            return "A2DP Media" if frame.channel_index else "AVDTP"
        if frame.protocol != "L2CAP":
            return frame.protocol
        key = (frame.handle, frame.direction, frame.cid)
        if key in self._labels:
            return self._labels[key]

        if avdtp.is_media_packet(frame.payload, frame.length):
            self._labels[key] = "A2DP Media"
            return "A2DP Media"
        if frame.payload[1:3] in (b"\x11\x0e", b"\x11\x0c", b"\x11\x0f") and frame.payload[0] & 0x0C == 0:
            self._labels[key] = "AVCTP"  # remote control (AVRCP) messages
            return "AVCTP"

        sig = avdtp.parse_signal(frame.payload)
        if sig is None:
            return "L2CAP"
        if avdtp.plausible_command(sig, frame.length):
            self._candidates = [c for c in self._candidates if frame.timestamp - c[0].timestamp < _ANSWER_WINDOW]
            self._candidates.append((frame, sig))
            return "L2CAP"
        for i, (command, command_sig) in enumerate(self._candidates):
            if (command.handle == frame.handle and command.direction != frame.direction
                    and (command_sig.label, command_sig.signal) == (sig.label, sig.signal)
                    and frame.timestamp - command.timestamp < _ANSWER_WINDOW):
                del self._candidates[i]
                self._labels[key] = "AVDTP"
                self._labels[(command.handle, command.direction, command.cid)] = "AVDTP"
                device = self.device(command.handle)
                self.frame_counts[(device, "L2CAP")] -= 1
                self.frame_counts[(device, "AVDTP")] += 1
                if self.frame_counts[(device, "L2CAP")] <= 0:
                    del self.frame_counts[(device, "L2CAP")]
                self._avdtp(command)
                return "AVDTP"
        return "L2CAP"

    def _avdtp(self, frame: L2capFrame) -> None:
        sig = avdtp.parse_signal(frame.payload)
        if sig is None:
            return  # continuation of a long message
        handle = frame.handle
        summary = sig.name if sig.is_command else f"{sig.name} {avdtp.MESSAGE_TYPES[sig.message_type]}"
        detail, is_error = avdtp.describe(sig)
        self._add(frame, handle, "A2DP", summary, detail=detail, is_error=is_error)

        accepted = sig.message_type == 2
        if sig.is_command and sig.signal in (0x03, 0x05):
            codecs, _ = avdtp._capabilities(sig.body[2:] if sig.signal == 0x03 else sig.body[1:])
            if codecs:
                self._pending_codecs[(handle, sig.label)] = codecs[0]
        elif accepted and sig.signal in (0x03, 0x05) and (handle, sig.label) in self._pending_codecs:
            self._codecs[handle] = self._pending_codecs.pop((handle, sig.label))
        elif accepted and sig.signal == 0x04:
            codecs, _ = avdtp._capabilities(sig.body)
            if codecs:
                self._codecs[handle] = codecs[0]
        elif accepted and sig.signal == 0x07:
            self._started.add(handle)
            self._streams[handle] = _Stream()
        elif accepted and sig.signal in (0x08, 0x09, 0x0A):
            self._stop_stream(frame, handle, "")
            self._started.discard(handle)

    def _avrcp(self, frame: L2capFrame) -> None:
        msg = avrcp.parse(frame.payload, frame.length)
        if msg is None:
            return
        # Snoop logs are recorded on the phone, so what it sent (TX) is the phone's side.
        summary, detail, is_error = avrcp.describe(msg, from_phone=frame.direction == "TX")
        self._add(frame, frame.handle, "AVRCP", summary, detail=detail, is_error=is_error,
                  routine=avrcp.is_routine(msg))

    def _media(self, frame: L2capFrame) -> None:
        handle = frame.handle
        stream = self._streams.get(handle)
        if stream is None:
            stream = self._streams[handle] = _Stream()
            if handle not in self._started and handle not in self._streamed_before_capture:
                self._streamed_before_capture.add(handle)
                self._add(frame, handle, "A2DP", "Audio streaming",
                          detail="Already streaming when the capture began")
        if stream.last is not None:
            silence = (frame.timestamp - stream.last.timestamp).total_seconds()
            if silence > _STALL_SECONDS:
                self._add(frame, handle, "A2DP", "Audio stalled", is_error=True,
                          detail=f"No audio sent for {silence:.1f} s while the stream was started")
        stream.first = stream.first or frame
        stream.last = frame
        stream.packets += 1
        stream.size += frame.length

    def _stop_stream(self, source: Any, handle: int, note: str) -> None:
        stream = self._streams.pop(handle, None)
        if stream is None or stream.first is None:
            return
        seconds = (stream.last.timestamp - stream.first.timestamp).total_seconds()
        rate = f", about {stream.size * 8 / seconds / 1000:.0f} kbit/s" if seconds > 0 else ""
        codec = f" {self._codecs[handle]}" if handle in self._codecs else ""
        detail = f"{seconds:.1f} s of{codec} audio: {stream.packets:,} packets, {stream.size / 1024:.0f} KB{rate}{note}"
        self._add(source, handle, "A2DP", "Stream summary", detail=detail, direction=stream.first.direction)

    def finish(self) -> None:
        """Close out streams still running at the end of the capture and order the timeline."""
        if self._finished:
            return
        self._finished = True
        for handle, stream in list(self._streams.items()):
            if stream.last is not None:
                self._stop_stream(stream.last, handle, " (still streaming when the capture ended)")
        self.events.sort(key=lambda e: e.index)

    def _rfcomm(self, frame: L2capFrame) -> None:
        rfcomm = parse_frame(frame.payload)
        if rfcomm is None or rfcomm.dlci == 0:
            return  # DLCI 0 is multiplexer housekeeping
        port = f"port {rfcomm.channel}"
        if rfcomm.frame_type == "SABM":
            self._add(frame, frame.handle, "RFCOMM", f"Opening serial {port}")
        elif rfcomm.frame_type == "DISC":
            self._add(frame, frame.handle, "RFCOMM", f"Closing serial {port}")
        elif rfcomm.frame_type == "DM":
            self._add(frame, frame.handle, "RFCOMM", f"Serial {port} refused or already closed", is_error=True)
        elif rfcomm.frame_type == "UIH" and rfcomm.payload:
            usage = self.serial_ports.setdefault((self.device(frame.handle), rfcomm.channel), [0, 0, False])
            usage[0] += 1
            usage[1] += len(rfcomm.payload)
            if self._serial_data(frame, rfcomm.dlci, rfcomm.payload):
                usage[2] = True

    def _serial_data(self, frame: L2capFrame, dlci: int, payload: bytes) -> bool:
        """Decode AT traffic on a serial port; return False if the data is something else."""
        text = decode_text(payload)
        key = (frame.handle, dlci)
        buffer_key = (frame.handle, dlci, frame.direction)
        pending = self._at_buffers.get(buffer_key, "")
        if text is None or not (key in self._hfp or pending or looks_like_at(text)):
            return False  # some other profile is using this serial port
        session = self._hfp.setdefault(key, HfpSession())
        lines, self._at_buffers[buffer_key] = split_lines(pending + text)
        for line in lines:
            summary, is_error = session.describe(line)
            self._add(frame, frame.handle, "HFP", line.strip(), detail=summary, is_error=is_error)
        return True


def print_trace(trace: ProtocolTrace, color: bool = True) -> None:
    """Print the protocol overview and timeline to stdout."""
    if color:
        BOLD, RED, CYAN, DIM, RESET = "\033[1m", "\033[91m", "\033[96m", "\033[2m", "\033[0m"
    else:
        BOLD = RED = CYAN = DIM = RESET = ""

    trace.finish()
    print(f"\n{BOLD} Protocol Traffic ───{RESET}")
    if trace.truncated_frames:
        print(f"  {DIM}Filtered capture: {trace.truncated_frames:,} of {trace.data_frames:,} data frames were stored "
              f"cut short, so some details are missing.{RESET}")
    if not trace.frame_counts:
        print("  No L2CAP data found (the capture may hold HCI commands and events only).")
    by_device: dict[str, list[tuple[str, int]]] = collections.defaultdict(list)
    for (device, protocol), count in trace.frame_counts.most_common():
        by_device[device].append((protocol, count))
    for device, protocols in by_device.items():
        print(f"  {CYAN}{device}{RESET}")
        for protocol, count in protocols:
            print(f"    {protocol:<18} {count:>7,} frames")

    if trace.serial_ports:
        print(f"\n{BOLD} Serial Ports (RFCOMM) ───{RESET}")
        for (device, port), (frames, size, is_hfp) in sorted(trace.serial_ports.items()):
            use = "HFP commands" if is_hfp else "app/vendor data (not decoded)"
            print(f"  {CYAN}{device}{RESET}  port {port:<3} {frames:>6,} data frames  {size / 1024:>8.1f} KB  {use}")

    print(f"\n{BOLD} Protocol Timeline ───{RESET}")
    events = [e for e in trace.events if not e.routine]
    hidden = len(trace.events) - len(events)
    if hidden:
        print(f"  {DIM}{hidden:,} routine messages hidden (status polls, notification sign-ups, acknowledgements).{RESET}")
    if not events:
        print("  No decoded protocol activity.")
        return
    width = max(len(e.summary) for e in events if e.detail) if any(e.detail for e in events) else 0
    width = min(width, 32)
    for event in events:
        t_str = event.timestamp.astimezone().strftime("%H:%M:%S.%f")[:-3]
        arrow = "->" if event.direction == "TX" else "<-"
        c = RED if event.is_error else ""
        text = f"{event.summary:<{width}}  {DIM}{event.detail}{RESET}" if event.detail else event.summary
        print(f"  {t_str} {arrow} {CYAN}{event.device}{RESET}  {event.protocol:<7} {c}{text}{RESET}")
