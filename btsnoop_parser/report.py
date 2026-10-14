"""A complete session report: the phone, each device, each connection, and what they did.

:class:`ReportBuilder` reads every record once and gathers everything a
capture can tell about a session, not only failures: who the devices are,
how and when each connection was made and ended, link settings and quality,
the profiles in use (via :class:`~btsnoop_parser.protocols.ProtocolTrace`)
and the issues found (via :class:`~btsnoop_parser.analysis.CaptureStats`).
The result is a :class:`SessionReport`, printed by :func:`print_report` or
exported with :meth:`SessionReport.to_dict`.

Security material (link keys, pairing values, Wi-Fi passwords) is never
included; pairing is reported as an outcome only.
"""
from __future__ import annotations

import dataclasses
import datetime
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from .analysis import CaptureStats, format_duration
from .constants import HCI_ERROR_CODES
from .protocols import DeviceProfiles, ProtocolTrace, _profile_lines

BLUETOOTH_VERSIONS = {0: "1.0b", 1: "1.1", 2: "1.2", 3: "2.0", 4: "2.1", 5: "3.0", 6: "4.0", 7: "4.1", 8: "4.2",
                      9: "5.0", 10: "5.1", 11: "5.2", 12: "5.3", 13: "5.4", 14: "6.0", 15: "6.1"}

COMPANIES = {
    0x0002: "Intel", 0x0006: "Microsoft", 0x0009: "Infineon", 0x000A: "Qualcomm (CSR)", 0x000D: "Texas Instruments",
    0x000F: "Broadcom", 0x001D: "Qualcomm", 0x0046: "MediaTek", 0x0048: "Marvell", 0x004C: "Apple",
    0x0057: "Harman", 0x0059: "Nordic Semiconductor", 0x005D: "Realtek", 0x0075: "Samsung", 0x0094: "Airoha",
    0x009E: "Bose", 0x00E0: "Google", 0x012D: "Sony", 0x0131: "Cypress", 0x02FF: "Silicon Labs",
}

_MAJOR_CLASSES = {1: "computer", 2: "phone", 3: "network device", 4: "audio/video device", 5: "peripheral",
                  6: "imaging device", 7: "wearable", 8: "toy", 9: "health device"}
_AUDIO_CLASSES = {1: "wearable headset", 2: "hands-free kit", 4: "microphone", 5: "loudspeaker", 6: "headphones",
                  7: "portable audio", 8: "car audio", 9: "set-top box", 10: "hi-fi audio", 12: "video camera",
                  14: "video monitor", 15: "display with speakers", 16: "video conferencing", 18: "gaming device"}
_WEARABLE_CLASSES = {1: "wristwatch", 2: "pager", 3: "jacket", 4: "helmet", 5: "glasses"}
_PERIPHERAL_CLASSES = {1: "keyboard", 2: "mouse or pointer", 3: "keyboard with pointer"}

_PHYS = {1: "1M", 2: "2M", 3: "Coded"}
_SMP_FAILURES = {
    0x01: "passkey entry failed", 0x02: "out-of-band data not available", 0x03: "authentication requirements not met",
    0x04: "confirm value failed", 0x05: "pairing not supported", 0x06: "encryption key size too short",
    0x07: "command not supported", 0x08: "unspecified reason", 0x09: "repeated attempts",
    0x0A: "invalid parameters", 0x0B: "DHKey check failed", 0x0C: "numeric comparison failed",
    0x0D: "pairing already in progress", 0x0E: "cross-transport key derivation not allowed", 0x0F: "key rejected",
}
# Disconnection reasons that say which side ended the connection.
_ENDED_BY_PHONE = {0x16}
_ENDED_BY_DEVICE = {0x13, 0x14, 0x15}
_LINK_LOST = {0x08, 0x22, 0x3E}


def _addr(data: bytes) -> str:
    return ":".join(f"{b:02X}" for b in data[::-1])


def _u16(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8)


def _signed(byte: int) -> int:
    return byte - 256 if byte > 127 else byte


def class_of_device(value: int) -> str:
    """Plain-English device type from a Class of Device value."""
    major, minor = (value >> 8) & 0x1F, (value >> 2) & 0x3F
    if major == 4 and minor in _AUDIO_CLASSES:
        return _AUDIO_CLASSES[minor]
    if major == 7 and minor in _WEARABLE_CLASSES:
        return _WEARABLE_CLASSES[minor]
    if major == 5 and (minor >> 4) in _PERIPHERAL_CLASSES:
        return _PERIPHERAL_CLASSES[minor >> 4]
    return _MAJOR_CLASSES.get(major, "unclassified device")


def _ad_name(data: bytes) -> Optional[str]:
    """The device name in advertising or extended inquiry data, if present."""
    offset = 0
    while offset + 1 < len(data):
        length = data[offset]
        if length == 0:
            break
        if data[offset + 1] in (0x08, 0x09):
            return data[offset + 2:offset + 1 + length].decode("utf-8", "replace").strip("\x00") or None
        offset += 1 + length
    return None


@dataclass
class PhoneInfo:
    address: Optional[str] = None
    name: Optional[str] = None
    bluetooth_version: Optional[str] = None
    chip_maker: Optional[str] = None


@dataclass
class DeviceInfo:
    address: str
    name: Optional[str] = None
    kind: Optional[str] = None
    bluetooth_version: Optional[str] = None
    chip_maker: Optional[str] = None
    transports: list[str] = field(default_factory=list)
    signal_dbm: list[int] = field(default_factory=list)  # from inquiry, advertising and RSSI reads


@dataclass
class ConnectionInfo:
    device: str
    transport: str
    handle: int
    start: datetime.datetime
    end: Optional[datetime.datetime] = None
    initiated_by: Optional[str] = None
    connect_seconds: Optional[float] = None
    end_reason: Optional[str] = None
    ended_by: Optional[str] = None
    encrypted: Optional[bool] = None
    security: list[str] = field(default_factory=list)  # pairing and authentication outcomes, in order
    role: Optional[str] = None
    role_switches: int = 0
    sniff_seconds: float = 0.0
    supervision_timeout_ms: Optional[float] = None
    le_interval_ms: Optional[float] = None
    le_latency: Optional[int] = None
    le_timeout_ms: Optional[int] = None
    le_phy: Optional[str] = None
    le_max_packet: Optional[int] = None
    parameter_updates: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    # Internal: when the link last entered sniff mode.
    _sniff_since: Optional[datetime.datetime] = dataclasses.field(default=None, repr=False)

    @property
    def seconds(self) -> Optional[float]:
        return (self.end - self.start).total_seconds() if self.end else None


@dataclass
class SessionReport:
    start: Optional[datetime.datetime]
    end: Optional[datetime.datetime]
    packets: int
    filtered: bool
    phone: PhoneInfo
    devices: list[DeviceInfo]
    connections: list[ConnectionInfo]
    profiles: dict[str, DeviceProfiles]
    issues: list[dict[str, Any]]
    nearby_devices: int
    events: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """Plain data for JSON: datetimes become ISO strings and counters become dicts."""
        def convert(value: Any) -> Any:
            if isinstance(value, datetime.datetime):
                return value.isoformat()
            if dataclasses.is_dataclass(value):
                return {f.name: convert(getattr(value, f.name)) for f in dataclasses.fields(value)
                        if not f.name.startswith("_")}
            if isinstance(value, dict):
                return {str(k): convert(v) for k, v in value.items()}
            if isinstance(value, (list, tuple, set)):
                return [convert(v) for v in value]
            return value

        result = {name: convert(getattr(self, name)) for name in
                  ("start", "end", "packets", "filtered", "phone", "devices", "connections", "issues",
                   "nearby_devices", "events")}
        result["profiles"] = {device: convert(p) for device, p in self.profiles.items() if p.active()}
        for connection, source in zip(result["connections"], self.connections):
            connection["seconds"] = source.seconds
        return result


class ReportBuilder:
    """Reads a capture once and assembles a :class:`SessionReport`."""

    def __init__(self, show_personal: bool = False) -> None:
        self.stats = CaptureStats()
        self.trace = ProtocolTrace(show_personal=show_personal)
        self.phone = PhoneInfo()
        self._devices: dict[str, DeviceInfo] = {}
        self._connections: list[ConnectionInfo] = []
        self._open: dict[int, ConnectionInfo] = {}
        self._outgoing: dict[str, datetime.datetime] = {}  # address -> when the phone asked to connect
        self._incoming: set[str] = set()  # addresses that asked the phone to connect
        self._le_connecting: Optional[datetime.datetime] = None
        self._advertisers: set[str] = set()
        self._pending_names: dict[str, str] = {}  # advertised names, kept until the device connects
        self._last: Optional[datetime.datetime] = None

    def device(self, address: str) -> DeviceInfo:
        return self._devices.setdefault(address, DeviceInfo(address=address))

    def analyze_record(self, record: Mapping[str, Any]) -> None:
        self.stats.analyze_record(record)
        self.trace.analyze_record(record)
        self._last = record["timestamp"]
        payload, kind = record["payload"], record["packet_type"]
        if kind == 0x01 and len(payload) >= 3:
            self._command(record, payload[0] | (payload[1] << 8), payload[3:])
        elif kind == 0x04 and len(payload) >= 2:
            self._event(record, payload[0], payload[2:])
        elif kind == 0x02 and len(payload) >= 4:
            handle = _u16(payload, 0) & 0x0FFF
            connection = self._open.get(handle)
            if connection is not None:
                size = _u16(payload, 2)
                if record["direction"] == "TX":
                    connection.bytes_sent += size
                else:
                    connection.bytes_received += size
                self._smp(connection, payload[4:])

    def _command(self, record: Mapping[str, Any], opcode: int, params: bytes) -> None:
        when = record["timestamp"]
        if opcode == 0x0405 and len(params) >= 6:  # Create Connection
            self._outgoing[_addr(params[:6])] = when
        elif opcode in (0x200D, 0x2043):  # LE (Extended) Create Connection
            self._le_connecting = when
        elif opcode == 0x0C13 and params:  # Write Local Name
            self.phone.name = params.split(b"\x00", 1)[0].decode("utf-8", "replace") or self.phone.name

    def _event(self, record: Mapping[str, Any], code: int, p: bytes) -> None:
        when = record["timestamp"]
        if code == 0x0E and len(p) >= 4:
            self._command_complete(_u16(p, 1), p[3:])
        elif code == 0x04 and len(p) >= 9:  # Connection Request: address, class of device
            address = _addr(p[:6])
            self._incoming.add(address)
            self.device(address).kind = class_of_device(int.from_bytes(p[6:9], "little"))
        elif code == 0x03 and len(p) >= 10 and p[9] == 0x01:  # ACL Connection Complete
            self._connected(when, _u16(p, 1) & 0x0FFF, _addr(p[3:9]), "Classic", p[0])
        elif code == 0x05 and len(p) >= 4 and p[0] == 0:
            self._disconnected(when, _u16(p, 1) & 0x0FFF, p[3])
        elif code in (0x08, 0x59) and len(p) >= 4 and p[0] == 0:
            connection = self._open.get(_u16(p, 1) & 0x0FFF)
            if connection is not None:
                connection.encrypted = bool(p[3])
        elif code == 0x14 and len(p) >= 4 and p[0] == 0:
            self._mode_change(when, _u16(p, 1) & 0x0FFF, p[3])
        elif code == 0x12 and len(p) >= 8 and p[0] == 0:  # Role Change
            for connection in self._open.values():
                if connection.device == _addr(p[1:7]):
                    connection.role_switches += 1
                    connection.role = "central" if p[7] == 0 else "peripheral"
        elif code == 0x0C and len(p) >= 8 and p[0] == 0:  # Read Remote Version Information Complete
            connection = self._open.get(_u16(p, 1) & 0x0FFF)
            if connection is not None:
                info = self.device(connection.device)
                info.bluetooth_version = BLUETOOTH_VERSIONS.get(p[3], f"version {p[3]}")
                company = _u16(p, 4)
                info.chip_maker = COMPANIES.get(company, f"company 0x{company:04X}")
        elif code == 0x36 and len(p) >= 7:  # Simple Pairing Complete
            for connection in self._open.values():
                if connection.device == _addr(p[1:7]):
                    connection.security.append("paired (new pairing)" if p[0] == 0 else
                                               f"pairing refused: {HCI_ERROR_CODES.get(p[0], hex(p[0]))}")
        elif code == 0x06 and len(p) >= 3 and p[0] != 0:  # Authentication Complete, failed
            connection = self._open.get(_u16(p, 1) & 0x0FFF)
            if connection is not None:
                connection.security.append("the device no longer had the pairing key" if p[0] == 0x06 else
                                           f"authentication failed: {HCI_ERROR_CODES.get(p[0], hex(p[0]))}")
        elif code == 0x38 and len(p) >= 4:
            connection = self._open.get(_u16(p, 0) & 0x0FFF)
            if connection is not None:
                connection.supervision_timeout_ms = _u16(p, 2) * 0.625
        elif code in (0x2F, 0x22) and len(p) >= 15:  # Extended Inquiry Result / Inquiry Result with RSSI
            info = self.device(_addr(p[1:7]))
            info.kind = info.kind or class_of_device(int.from_bytes(p[9:12], "little"))
            info.signal_dbm.append(_signed(p[14]))
            if code == 0x2F:
                info.name = info.name or _ad_name(p[15:])
        elif code == 0x3E and p:
            self._le_event(when, p)

    def _command_complete(self, opcode: int, ret: bytes) -> None:
        if not ret or ret[0] != 0:
            return
        if opcode == 0x1009 and len(ret) >= 7:
            self.phone.address = _addr(ret[1:7])
        elif opcode == 0x1001 and len(ret) >= 7:
            self.phone.bluetooth_version = BLUETOOTH_VERSIONS.get(ret[1], f"version {ret[1]}")
            company = _u16(ret, 5)
            self.phone.chip_maker = COMPANIES.get(company, f"company 0x{company:04X}")
        elif opcode == 0x0C14 and len(ret) > 1:
            self.phone.name = ret[1:].split(b"\x00", 1)[0].decode("utf-8", "replace") or self.phone.name
        elif opcode == 0x1405 and len(ret) >= 4:  # Read RSSI
            connection = self._open.get(_u16(ret, 1) & 0x0FFF)
            if connection is not None:
                self.device(connection.device).signal_dbm.append(_signed(ret[3]))

    def _le_event(self, when: datetime.datetime, p: bytes) -> None:
        sub = p[0]
        if sub in (0x01, 0x0A, 0x29) and len(p) >= 12:
            handle, address = _u16(p, 2) & 0x0FFF, _addr(p[6:12])
            connection = self._connected(when, handle, address, "LE", p[1], le_role=p[4])
            base = 12 if sub == 0x01 else 24
            if connection is not None and len(p) >= base + 6:
                self._le_parameters(connection, p, base)
        elif sub == 0x03 and len(p) >= 10 and p[1] == 0:
            connection = self._open.get(_u16(p, 2) & 0x0FFF)
            if connection is not None:
                connection.parameter_updates += 1
                self._le_parameters(connection, p, 4)
        elif sub == 0x0C and len(p) >= 6 and p[1] == 0:
            connection = self._open.get(_u16(p, 2) & 0x0FFF)
            if connection is not None:
                tx, rx = _PHYS.get(p[4], "?"), _PHYS.get(p[5], "?")
                connection.le_phy = tx if tx == rx else f"{tx} out, {rx} in"
        elif sub == 0x07 and len(p) >= 11:
            connection = self._open.get(_u16(p, 1) & 0x0FFF)
            if connection is not None:
                connection.le_max_packet = max(_u16(p, 3), _u16(p, 7))
        elif sub == 0x0D and len(p) >= 26:  # Extended Advertising Report (first report)
            self._advertised(_addr(p[5:11]), _signed(p[15]), p[26:26 + p[25]])
        elif sub == 0x02 and len(p) >= 11:  # Advertising Report (first report)
            data = p[11:11 + p[10]]
            rssi = _signed(p[11 + p[10]]) if len(p) > 11 + p[10] else None
            self._advertised(_addr(p[4:10]), rssi, data)

    def _advertised(self, address: str, rssi: Optional[int], data: bytes) -> None:
        self._advertisers.add(address)
        name = _ad_name(data)
        # Keep details only for devices the phone connects to; others just count as nearby.
        if address in self._devices:
            info = self._devices[address]
            info.name = info.name or name
            if rssi is not None and rssi != 127:
                info.signal_dbm.append(rssi)
        elif name:
            self._pending_names[address] = name

    @staticmethod
    def _le_parameters(connection: ConnectionInfo, p: bytes, offset: int) -> None:
        connection.le_interval_ms = _u16(p, offset) * 1.25
        connection.le_latency = _u16(p, offset + 2)
        connection.le_timeout_ms = _u16(p, offset + 4) * 10

    def _connected(self, when: datetime.datetime, handle: int, address: str, transport: str, status: int,
                   le_role: Optional[int] = None) -> Optional[ConnectionInfo]:
        if status != 0:
            return None
        info = self.device(address)
        if transport not in info.transports:
            info.transports.append(transport)
        info.name = info.name or self._pending_names.pop(address, None)
        connection = ConnectionInfo(device=address, transport=transport, handle=handle, start=when)
        if transport == "Classic":
            if address in self._outgoing:
                connection.initiated_by = "phone"
                connection.connect_seconds = (when - self._outgoing.pop(address)).total_seconds()
            elif address in self._incoming:
                connection.initiated_by = "device"
                self._incoming.discard(address)
        else:
            connection.role = "central" if le_role == 0 else "peripheral"
            connection.initiated_by = "phone" if le_role == 0 else "device"
            if le_role == 0 and self._le_connecting is not None:
                connection.connect_seconds = (when - self._le_connecting).total_seconds()
                self._le_connecting = None
        self._open[handle] = connection
        self._connections.append(connection)
        return connection

    def _disconnected(self, when: datetime.datetime, handle: int, reason: int) -> None:
        connection = self._open.pop(handle, None)
        if connection is None:
            return
        self._mode_change(when, handle, 0, connection)
        connection.end = when
        connection.end_reason = HCI_ERROR_CODES.get(reason, f"0x{reason:02X}")
        if reason in _ENDED_BY_PHONE:
            connection.ended_by = "phone"
        elif reason in _ENDED_BY_DEVICE:
            connection.ended_by = "device"
        elif reason in _LINK_LOST:
            connection.ended_by = "link lost"

    def _mode_change(self, when: datetime.datetime, handle: int, mode: int,
                     connection: Optional[ConnectionInfo] = None) -> None:
        connection = connection or self._open.get(handle)
        if connection is None:
            return
        if connection._sniff_since is not None:
            connection.sniff_seconds += (when - connection._sniff_since).total_seconds()
            connection._sniff_since = None
        if mode == 0x02:
            connection._sniff_since = when

    def _smp(self, connection: ConnectionInfo, frame: bytes) -> None:
        """Pairing outcome on LE links (SMP, CID 0x0006). Only the result is read, never key material."""
        if connection.transport != "LE" or len(frame) < 5 or _u16(frame, 2) != 0x0006:
            return
        code = frame[4]
        if code == 0x01 and "pairing started" not in connection.security:
            connection.security.append("pairing started")
        elif code == 0x05 and len(frame) >= 6:
            connection.security.append(f"pairing failed: {_SMP_FAILURES.get(frame[5], f'reason 0x{frame[5]:02X}')}")
        elif code in (0x04, 0x0D) and connection.security[-1:] == ["pairing started"]:
            connection.security[-1] = "paired (new pairing)"

    def build(self) -> SessionReport:
        self.trace.finish()
        for connection in self._open.values():  # still connected when the capture ended
            self._mode_change(self._last, connection.handle, 0, connection)
        for address, info in self._devices.items():
            profile = self.trace.profiles.get(address)
            if profile is not None:
                info.name = info.name or profile.device_info.get("Device Name")
                info.kind = info.kind or _kind_from_profile(profile)
                if (profile.android_auto_start or profile.android_auto_wifi) and "Android Auto" not in info.kind:
                    info.kind += " with Android Auto"
        devices = [d for d in self._devices.values() if d.transports]
        known = {d.address for d in devices}
        for key, profile in self.trace.profiles.items():
            if profile.active() and key not in known:  # connected before the capture began
                devices.append(DeviceInfo(address=key, name=profile.device_info.get("Device Name"),
                                          kind=_kind_from_profile(profile),
                                          transports=["connected before the capture began"]))
        events = [{"time": e.timestamp, "device": e.device, "protocol": e.protocol, "summary": e.summary,
                   "detail": e.detail, "error": e.is_error} for e in self.trace.events if not e.routine]
        return SessionReport(
            start=self.stats.start_time, end=self.stats.end_time, packets=self.stats.total_packets,
            filtered=self.trace.truncated_frames > 0, phone=self.phone, devices=devices,
            connections=self._connections, profiles=self.trace.profiles, issues=self.stats.issues,
            nearby_devices=len(self._advertisers - {d.address for d in devices}), events=events,
        )


def _kind_from_profile(p: DeviceProfiles) -> Optional[str]:
    appearance = p.device_info.get("Appearance")
    if appearance and appearance != "unknown":
        return appearance
    if p.android_auto_start or p.android_auto_wifi:
        return "car with Android Auto"
    if p.le_audio or p.le_audio_codec:
        return "LE Audio headset"
    if "Heart Rate" in p.gatt_services:
        return "fitness or health device"
    if "Human Interface Device" in p.gatt_services:
        return "keyboard, mouse or remote"
    if p.hfp_first and (p.streams or p.codec):
        return "audio device with calls (headset or car kit)"
    if p.streams or p.codec:
        return "audio device"
    return None


def build_report(records, show_personal: bool = False) -> SessionReport:
    builder = ReportBuilder(show_personal=show_personal)
    for record in records:
        builder.analyze_record(record)
    return builder.build()


def _clock(ts: Optional[datetime.datetime]) -> str:
    return ts.astimezone().strftime("%H:%M:%S") if ts else "?"


def _connection_line(c: ConnectionInfo) -> list[str]:
    span = format_duration(c.start, c.end) if c.end else "still connected at the end"
    first = f"{_clock(c.start)} - {_clock(c.end) if c.end else '...'}  {c.transport}, {span}"
    details = []
    if c.initiated_by:
        took = f", took {c.connect_seconds:.1f} s" if c.connect_seconds and c.connect_seconds >= 0.05 else ""
        details.append(f"started by the {c.initiated_by}{took}")
    if c.end_reason:
        who = {"phone": "the phone", "device": "the device"}.get(c.ended_by or "", "")
        details.append(f"ended by {who} ({c.end_reason})" if who else f"ended: {c.end_reason}")
    details.extend(c.security)
    if c.encrypted is not None:
        details.append("encrypted" if c.encrypted else "not encrypted")
    link = []
    if c.le_interval_ms is not None:
        link.append(f"interval {c.le_interval_ms:g} ms, latency {c.le_latency}, timeout {c.le_timeout_ms} ms")
    if c.le_phy:
        link.append(f"{c.le_phy} radio")
    if c.le_max_packet:
        link.append(f"packets up to {c.le_max_packet} bytes")
    if c.parameter_updates:
        link.append(f"{c.parameter_updates} parameter update(s)")
    seconds = c.seconds or ((c.end or c.start) - c.start).total_seconds()
    if c.sniff_seconds and seconds:
        link.append(f"power saving {c.sniff_seconds / seconds:.0%} of the time")
    if c.role_switches:
        link.append(f"{c.role_switches} role switch(es)")
    if c.supervision_timeout_ms:
        link.append(f"drops after {c.supervision_timeout_ms / 1000:g} s of silence")
    if c.bytes_sent + c.bytes_received >= 1024:
        link.append(f"sent {c.bytes_sent / 1024:.0f} KB, received {c.bytes_received / 1024:.0f} KB")
    lines = [first]
    if details:
        lines.append("; ".join(details))
    if link:
        lines.append("; ".join(link))
    return lines


def print_report(report: SessionReport, color: bool = True) -> None:
    """Print the full session report."""
    if color:
        BOLD, YELLOW, RED, CYAN, DIM, RESET = "\033[1m", "\033[93m", "\033[91m", "\033[96m", "\033[2m", "\033[0m"
    else:
        BOLD = YELLOW = RED = CYAN = DIM = RESET = ""

    print(f"\n{BOLD}Bluetooth Session Report{RESET}")
    print(f"  Capture      {_clock(report.start)} - {_clock(report.end)} "
          f"({format_duration(report.start, report.end)}), {report.packets:,} packets"
          + (f" {DIM}(filtered: some details were cut){RESET}" if report.filtered else ""))
    phone = report.phone
    parts = [p for p in (phone.name and f'"{phone.name}"', phone.address,
                         phone.bluetooth_version and f"Bluetooth {phone.bluetooth_version}",
                         phone.chip_maker and f"{phone.chip_maker} chip") if p]
    if parts:
        print(f"  Phone        {', '.join(parts)}")
    if report.nearby_devices:
        print(f"  Nearby       {report.nearby_devices} other device(s) seen advertising")

    print(f"\n{BOLD}Devices ({len(report.devices)}){RESET}")
    if not report.devices:
        print("  No connections in this capture.")
    for device in report.devices:
        name = f' "{device.name}"' if device.name else ""
        print(f"  {CYAN}{device.address}{RESET}{name}")
        facts = [device.kind or "unknown type", " + ".join(device.transports)]
        if device.bluetooth_version:
            facts.append(f"Bluetooth {device.bluetooth_version}")
        if device.chip_maker:
            facts.append(f"{device.chip_maker} chip")
        if device.signal_dbm:
            low, high = min(device.signal_dbm), max(device.signal_dbm)
            facts.append(f"signal {low} dBm" if low == high else f"signal {low} to {high} dBm")
        print(f"    {'About':<17} {', '.join(facts)}")
        for connection in [c for c in report.connections if c.device == device.address]:
            for i, line in enumerate(_connection_line(connection)):
                print(f"    {'Connection' if i == 0 else '':<17} {line}")
        profile = report.profiles.get(device.address)
        if profile is not None and profile.active():
            for label, text, warning in _profile_lines(profile):
                colour = YELLOW if warning else ""
                print(f"    {label:<17} {colour}{'! ' if warning else ''}{text}{RESET if warning else ''}")

    problems = [i for i in report.issues if i["level"] != "INFO"]
    notes = [i for i in report.issues if i["level"] == "INFO"]
    print(f"\n{BOLD}Problems{RESET}")
    if not problems:
        print("  None found at the connection level.")
    for issue in problems:
        colour = RED if issue["level"] in ("ERROR", "CRITICAL") else YELLOW
        print(f"  {colour}[{issue['level']}] {_clock(issue['timestamp'])} {issue['title']}: {issue['detail']}{RESET}")
    if notes:
        print(f"  {DIM}{len(notes)} routine failure(s) not counted as problems (see --stats){RESET}")


def activity_lines(report: SessionReport) -> list[str]:
    """A condensed, plain-text "Device Activity" section for the --ai model.

    Problems are prefixed with WARNING; times of individual streams and song
    titles are left out to keep the model's input short.
    """
    lines = ["Device Activity:"]
    seen = {"music": False, "calls": False, "controls": False, "Android Auto": False}
    for device in report.devices:
        name = f' "{device.name}"' if device.name else ""
        lines.append(f"  {device.address}{name} ({device.kind or 'unknown type'})")
        connections = [c for c in report.connections if c.device == device.address]
        if connections:
            last = connections[-1]
            ending = (f"; last ended by the {last.ended_by} ({last.end_reason})" if last.ended_by
                      else f"; last ended: {last.end_reason}" if last.end_reason else "; still connected at the end")
            lines.append(f"    Connections: {len(connections)}{ending}")
        security = list(dict.fromkeys(note for c in connections for note in c.security))
        for note in security:
            problem = not note.startswith(("paired", "pairing started"))
            lines.append(f"    {'WARNING: ' if problem else 'Security: '}{note}")
        profile = report.profiles.get(device.address)
        if profile is None or not profile.active():
            continue
        label = ""
        sync_parts: dict[str, list[str]] = {}
        for text_label, text, warning in _profile_lines(profile):
            if text_label:
                label = text_label
            if label == "Songs":
                continue
            if label in profile.syncs and not warning:
                # One line per sync service, keeping only what actually came back.
                if not text.endswith("requested") and "nothing transferred" not in text:
                    sync_parts.setdefault(label, []).append(text.split(", over")[0])
                continue
            if not text_label and text[:2].isdigit() and text[2:3] == ":":
                continue  # a single stream's start and end time
            prefix = "WARNING: " if warning else (f"{label}: " if text_label else "")
            lines.append(f"    {prefix}{text}")
        for service, parts in sync_parts.items():
            lines.append(f"    {service}: {'; '.join(parts)}")
        if profile.tracks:
            lines.append(f"    Songs: {len(profile.tracks)} played")
        seen["music"] |= bool(profile.streams or profile.codec or profile.le_audio)
        seen["calls"] |= bool(profile.hfp_first)
        seen["controls"] |= bool(profile.buttons or profile.volume_sets or profile.volume_reports)
        seen["Android Auto"] |= bool(profile.android_auto_start or profile.android_auto_wifi)
    if not report.devices:
        lines.append("  No device activity recorded.")
    missing = [name for name, found in seen.items() if not found]
    if missing:
        lines.append(f"  Not seen: {', '.join(missing)}")
    return lines
