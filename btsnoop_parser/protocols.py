"""Protocol-level view of a capture: what the devices said above HCI.

:class:`ProtocolTrace` feeds every record through the L2CAP decoder, counts
traffic per protocol, and builds a timeline of the decoded exchanges (channel
setup, RFCOMM ports, HFP commands, voice links).
"""
from __future__ import annotations

import collections
import datetime
from dataclasses import dataclass
from typing import Any, Mapping, Optional

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

    def _add(self, source: Any, handle: int, protocol: str, summary: str,
             detail: str = "", is_error: bool = False, direction: Optional[str] = None) -> None:
        if isinstance(source, L2capFrame):
            index, timestamp, direction = source.index, source.timestamp, direction or source.direction
        else:
            index, timestamp, direction = source["index"], source["timestamp"], direction or source["direction"]
        self.events.append(ProtocolEvent(index, timestamp, direction, handle, self.device(handle),
                                         protocol, summary, detail, is_error))

    def _event(self, record: Mapping[str, Any]) -> None:
        payload = record["payload"]
        if len(payload) < 2:
            return
        code = payload[0]

        if code == 0x03 and len(payload) >= 11 and payload[2] == 0x00:  # Connection Complete
            self._devices[payload[3] | (payload[4] << 8)] = _addr(payload[5:11])

        elif code == 0x3E and len(payload) >= 14 and payload[2] in (0x01, 0x0A, 0x29) and payload[3] == 0x00:
            self._devices[payload[4] | (payload[5] << 8)] = _addr(payload[8:14])

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
            if handle in self._voice_handles:
                self._voice_handles.discard(handle)
                reason = HCI_ERROR_CODES.get(payload[5], f"0x{payload[5]:02X}")
                self._add(record, handle, "Voice", f"Voice link closed ({reason})")
            self._l2cap.forget_handle(handle)
            for store in (self._hfp, self._at_buffers):
                for key in [k for k in store if k[0] == handle]:
                    del store[key]
            self._devices.pop(handle, None)

    def _frame(self, frame: L2capFrame) -> None:
        self.frame_counts[(self.device(frame.handle), frame.protocol)] += 1
        for text, is_error in frame.notes:
            self._add(frame, frame.handle, "L2CAP", text, is_error=is_error)
        if frame.protocol == "RFCOMM":
            self._rfcomm(frame)

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

    print(f"\n{BOLD} Protocol Traffic ───{RESET}")
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
    if not trace.events:
        print("  No decoded protocol activity.")
        return
    width = max(len(e.summary) for e in trace.events if e.detail) if any(e.detail for e in trace.events) else 0
    width = min(width, 32)
    for event in trace.events:
        t_str = event.timestamp.astimezone().strftime("%H:%M:%S.%f")[:-3]
        arrow = "->" if event.direction == "TX" else "<-"
        c = RED if event.is_error else ""
        text = f"{event.summary:<{width}}  {DIM}{event.detail}{RESET}" if event.detail else event.summary
        print(f"  {t_str} {arrow} {CYAN}{event.device}{RESET}  {event.protocol:<7} {c}{text}{RESET}")
