"""GATT decoding: what LE devices read, write and report over ATT.

ATT messages address values by a numeric handle. Which characteristic a
handle is (Battery Level, Heart Rate Measurement, ...) is only known from the
service discovery the client runs after connecting, so :class:`GattTracker`
follows discovery and keeps a database per server. Captures that start after
discovery (common with bonded devices, which cache it) show raw handles, and
values whose format is unknown are shown as length only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

SERVICES = {
    0x1800: "Generic Access", 0x1801: "Generic Attribute", 0x1802: "Immediate Alert", 0x1803: "Link Loss",
    0x1804: "Tx Power", 0x1805: "Current Time", 0x1808: "Glucose", 0x1809: "Health Thermometer",
    0x180A: "Device Information", 0x180D: "Heart Rate", 0x180F: "Battery", 0x1810: "Blood Pressure",
    0x1811: "Alert Notification", 0x1812: "Human Interface Device", 0x1814: "Running Speed and Cadence",
    0x1816: "Cycling Speed and Cadence", 0x1818: "Cycling Power", 0x181C: "User Data", 0x181E: "Bond Management",
    0x1822: "Pulse Oximeter", 0x1826: "Fitness Machine", 0x1843: "Audio Input Control", 0x1844: "Volume Control",
    0x1845: "Volume Offset Control", 0x1846: "Coordinated Set Identification", 0x1848: "Media Control",
    0x1849: "Generic Media Control", 0x184B: "Telephone Bearer", 0x184C: "Generic Telephone Bearer",
    0x184D: "Microphone Control", 0x184E: "Audio Stream Control", 0x184F: "Broadcast Audio Scan",
    0x1850: "Published Audio Capabilities", 0x1853: "Common Audio", 0x1854: "Hearing Access",
    0x1855: "Telephony and Media Audio", 0xFE2C: "Google Fast Pair",
}

CHARACTERISTICS = {
    0x2A00: "Device Name", 0x2A01: "Appearance", 0x2A04: "Preferred Connection Parameters",
    0x2A05: "Service Changed", 0x2A19: "Battery Level", 0x2A23: "System ID", 0x2A24: "Model Number",
    0x2A25: "Serial Number", 0x2A26: "Firmware Revision", 0x2A27: "Hardware Revision",
    0x2A28: "Software Revision", 0x2A29: "Manufacturer Name", 0x2A2B: "Current Time", 0x2A37: "Heart Rate Measurement",
    0x2A38: "Body Sensor Location", 0x2A39: "Heart Rate Control Point", 0x2A4A: "HID Information",
    0x2A4B: "Report Map", 0x2A4C: "HID Control Point", 0x2A4D: "Report", 0x2A4E: "Protocol Mode",
    0x2A50: "PnP ID", 0x2AA6: "Central Address Resolution", 0x2B29: "Client Supported Features",
    0x2B2A: "Database Hash", 0x2B3A: "Server Supported Features", 0x2B51: "TMAP Role",
    0x2B7D: "Volume State", 0x2B7E: "Volume Control Point", 0x2B7F: "Volume Flags",
    0x2B84: "Set Identity Resolving Key", 0x2B85: "Set Size", 0x2B86: "Set Member Lock", 0x2B87: "Set Member Rank",
    0x2B93: "Media Player Name", 0x2B96: "Track Changed", 0x2B97: "Track Title", 0x2B98: "Track Duration",
    0x2B99: "Track Position", 0x2BA3: "Media State", 0x2BA4: "Media Control Point",
    0x2BA5: "Media Control Opcodes Supported", 0x2BB3: "Bearer Provider Name", 0x2BBD: "Call State",
    0x2BBE: "Call Control Point", 0x2BC3: "Mute", 0x2BC4: "Sink ASE", 0x2BC5: "Source ASE",
    0x2BC6: "ASE Control Point", 0x2BC9: "Sink PAC", 0x2BCA: "Sink Audio Locations", 0x2BCB: "Source PAC",
    0x2BCC: "Source Audio Locations", 0x2BCD: "Available Audio Contexts", 0x2BCE: "Supported Audio Contexts",
}

DESCRIPTORS = {
    0x2900: "Extended Properties", 0x2901: "User Description", 0x2902: "Notification Settings",
    0x2904: "Presentation Format", 0x2908: "Report Reference",
}

_DECLARATIONS = {0x2800: "Primary Service", 0x2801: "Secondary Service", 0x2802: "Include", 0x2803: "Characteristic"}

OPCODES = {
    0x01: "Error", 0x02: "MTU Request", 0x03: "MTU Response", 0x04: "Find Information",
    0x05: "Find Information Response", 0x06: "Find By Type Value", 0x07: "Find By Type Value Response",
    0x08: "Read By Type", 0x09: "Read By Type Response", 0x0A: "Read", 0x0B: "Read Response", 0x0C: "Read Blob",
    0x0D: "Read Blob Response", 0x0E: "Read Multiple", 0x0F: "Read Multiple Response", 0x10: "Read By Group Type",
    0x11: "Read By Group Type Response", 0x12: "Write", 0x13: "Write Response", 0x16: "Prepare Write",
    0x17: "Prepare Write Response", 0x18: "Execute Write", 0x19: "Execute Write Response", 0x1B: "Notification",
    0x1D: "Indication", 0x1E: "Confirmation", 0x20: "Read Multiple Variable",
    0x21: "Read Multiple Variable Response", 0x23: "Multiple Notification", 0x52: "Write Command",
    0xD2: "Signed Write Command",
}

ERRORS = {
    0x01: "invalid handle", 0x02: "read not permitted", 0x03: "write not permitted", 0x04: "invalid request",
    0x05: "insufficient authentication (devices need to pair)", 0x06: "request not supported",
    0x07: "invalid offset", 0x08: "insufficient authorization", 0x09: "prepare queue full",
    0x0A: "attribute not found", 0x0B: "attribute not long", 0x0C: "encryption key too short",
    0x0D: "invalid value length", 0x0E: "unlikely error", 0x0F: "insufficient encryption",
    0x10: "unsupported group type", 0x11: "insufficient resources", 0x12: "database out of sync",
    0x13: "value not allowed", 0xFC: "write request rejected", 0xFD: "notification settings misconfigured",
    0xFE: "procedure already in progress", 0xFF: "value out of range",
}

# Opcodes sent by a client (the rest come from the server).
_REQUESTS = {0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x16, 0x18, 0x20, 0x52, 0xD2}
_TEXT = {0x2A00, 0x2A24, 0x2A25, 0x2A26, 0x2A27, 0x2A28, 0x2A29, 0x2B93, 0x2B97, 0x2BB3}
# Characteristics whose notifications report a state worth showing when it changes.
_STATEFUL = {0x2A19, 0x2B7D, 0x2BA3, 0x2BC3, 0x2B97, 0x2BBD}

_MEDIA_STATES = {0: "inactive", 1: "playing", 2: "paused", 3: "seeking"}
_MEDIA_COMMANDS = {
    0x01: "Play", 0x02: "Pause", 0x03: "Fast Rewind", 0x04: "Fast Forward", 0x05: "Stop", 0x10: "Move Relative",
    0x20: "Previous Segment", 0x21: "Next Segment", 0x30: "Previous Track", 0x31: "Next Track",
    0x32: "First Track", 0x33: "Last Track", 0x40: "Previous Group", 0x41: "Next Group",
}
_VOLUME_COMMANDS = {0x00: "Volume Down", 0x01: "Volume Up", 0x02: "Unmute and Volume Down",
                    0x03: "Unmute and Volume Up", 0x04: "Set Volume", 0x05: "Unmute", 0x06: "Mute"}
# Appearance categories (the value's upper 10 bits).
_APPEARANCES = {
    0: "unknown", 1: "phone", 2: "computer", 3: "watch", 4: "clock", 5: "display", 6: "remote control",
    7: "eyeglasses", 8: "tag", 9: "keyring", 10: "media player", 11: "barcode scanner", 12: "thermometer",
    13: "heart rate sensor", 14: "blood pressure monitor", 15: "human interface device", 16: "glucose meter",
    17: "running or walking sensor", 18: "cycling sensor", 19: "control device", 20: "network device",
    21: "sensor", 37: "wearable audio device", 41: "hearing aid",
}
_SENSOR_LOCATIONS = {0: "other", 1: "chest", 2: "wrist", 3: "finger", 4: "hand", 5: "ear lobe", 6: "foot"}


def uuid_name(uuid: bytes) -> str:
    """Name a little-endian UUID as it appears on the wire."""
    if len(uuid) == 2:
        value = int.from_bytes(uuid, "little")
        for table in (CHARACTERISTICS, SERVICES, DESCRIPTORS, _DECLARATIONS):
            if value in table:
                return table[value]
        return f"0x{value:04X}"
    text = uuid[::-1].hex()
    if len(text) == 32:
        if text.endswith("00001000800000805f9b34fb"):  # 16-bit UUID written in 128-bit form
            return uuid_name(bytes.fromhex(text[4:8])[::-1])
        return f"vendor {text[:8]}-{text[8:12]}"
    return f"UUID {text}"


def _u16(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8)


def _short(uuid: bytes) -> Optional[int]:
    return int.from_bytes(uuid, "little") if len(uuid) == 2 else None


def decode_value(uuid: Optional[int], value: bytes) -> Optional[str]:
    """Plain-English value of a known characteristic, or None if the format is unknown."""
    if uuid is None or not value:
        return None
    if uuid in _TEXT:
        return value.decode("utf-8", "replace").rstrip("\x00")
    if uuid == 0x2A19:
        return f"{value[0]}%"
    if uuid == 0x2A01 and len(value) >= 2:
        category = _u16(value, 0) >> 6
        return _APPEARANCES.get(category, f"appearance category {category}")
    if uuid == 0x2A37 and len(value) >= 2:
        rate = _u16(value, 1) if value[0] & 0x01 and len(value) >= 3 else value[1]
        return f"{rate} bpm"
    if uuid == 0x2A38:
        return _SENSOR_LOCATIONS.get(value[0], f"location {value[0]}")
    if uuid == 0x2902 and len(value) >= 2:
        flags = _u16(value, 0)
        return {0: "updates off", 1: "notifications on", 2: "indications on"}.get(flags, f"0x{flags:04X}")
    if uuid == 0x2B7D and len(value) >= 2:
        return f"volume {round(value[0] * 100 / 255)}%" + (", muted" if value[1] else "")
    if uuid == 0x2B7E:
        command = _VOLUME_COMMANDS.get(value[0], f"command 0x{value[0]:02X}")
        if value[0] == 0x04 and len(value) >= 3:
            command += f" to {round(value[2] * 100 / 255)}%"
        return command
    if uuid == 0x2BA3:
        return _MEDIA_STATES.get(value[0], f"state {value[0]}")
    if uuid == 0x2BA4:
        return _MEDIA_COMMANDS.get(value[0], f"command 0x{value[0]:02X}")
    if uuid == 0x2BC3:
        return {0: "not muted", 1: "muted", 2: "mute disabled"}.get(value[0], f"0x{value[0]:02X}")
    if uuid in (0x2B98, 0x2B99) and len(value) >= 4:
        centiseconds = int.from_bytes(value[:4], "little", signed=True)
        if centiseconds < 0:
            return "unknown"
        seconds = centiseconds // 100
        return f"{seconds // 60}:{seconds % 60:02d}"
    return None


@dataclass
class _Database:
    """What discovery revealed about one GATT server."""

    services: list[tuple[int, int, bytes]] = field(default_factory=list)  # (start, end, uuid)
    attributes: dict[int, bytes] = field(default_factory=dict)  # handle -> uuid


@dataclass
class GattMessage:
    summary: str
    detail: str
    is_error: bool
    routine: bool
    # Facts for summaries: (characteristic uuid, decoded value) for values seen, and errors.
    value: Optional[tuple[Optional[int], str, bytes]] = None


class GattTracker:
    """Follows ATT traffic per connection and names handles from discovery."""

    def __init__(self) -> None:
        # (connection handle, direction the server sends) -> database
        self._db: dict[tuple[int, str], _Database] = {}
        # (connection handle, direction the client sends) -> (opcode, request parameters)
        self._requests: dict[tuple[int, str], tuple[int, bytes]] = {}
        self._last_values: dict[tuple[int, str, int], bytes] = {}

    def forget(self, handle: int) -> None:
        for store in (self._db, self._requests, self._last_values):
            for key in [k for k in store if k[0] == handle]:
                del store[key]

    def services(self, handle: int, server_direction: str) -> list[str]:
        db = self._db.get((handle, server_direction))
        return [uuid_name(uuid) for _, _, uuid in db.services] if db else []

    def _name(self, db: _Database, att_handle: int) -> str:
        uuid = db.attributes.get(att_handle)
        return uuid_name(uuid) if uuid else f"handle 0x{att_handle:04X}"

    def feed(self, handle: int, direction: str, payload: bytes) -> Optional[GattMessage]:
        if not payload:
            return None
        opcode = payload[0]
        name = OPCODES.get(opcode, f"ATT 0x{opcode:02X}")
        server = ("RX" if direction == "TX" else "TX") if opcode in _REQUESTS else direction
        db = self._db.setdefault((handle, server), _Database())
        if opcode in _REQUESTS and opcode not in (0x52, 0xD2):
            self._requests[(handle, direction)] = (opcode, payload[1:])
        request = self._requests.get((handle, "RX" if direction == "TX" else "TX"), (None, b""))
        body = payload[1:]

        if opcode == 0x01 and len(body) >= 4:
            code = body[3]
            reason = ERRORS.get(code, f"application error 0x{code:02X}")
            what = OPCODES.get(body[0], f"0x{body[0]:02X}")
            target = self._name(db, _u16(body, 1)) if _u16(body, 1) else ""
            routine = code == 0x0A  # the normal end of a discovery
            return GattMessage("Error", f"{what} {target}: {reason}".replace("  ", " "), not routine, routine)
        if opcode in (0x02, 0x03) and len(body) >= 2:
            return GattMessage(name, f"Maximum message size {_u16(body, 0)} bytes", False, True)
        if opcode in (0x04, 0x08, 0x10, 0x06, 0x0E, 0x20, 0x0C):
            return GattMessage(name, "Service discovery" if opcode in (0x04, 0x06, 0x08, 0x10) else name,
                               False, True)
        if opcode == 0x11 and body:  # primary services: (start, end, uuid) records
            size, found = body[0], []
            for i in range(1, len(body) - size + 1, size):
                start, end, uuid = _u16(body, i), _u16(body, i + 2), body[i + 4:i + size]
                db.services.append((start, end, uuid))
                found.append(uuid_name(uuid))
            return GattMessage("Services", "Found: " + ", ".join(found), False, False)
        if opcode == 0x07:
            return GattMessage(name, "Service discovery", False, True)
        if opcode == 0x09 and body:  # Read By Type: (handle, value) records
            size = body[0]
            wanted = request[1][4:] if request[0] == 0x08 else b""
            records = [body[i:i + size] for i in range(1, len(body) - size + 1, size)]
            if wanted in (b"\x03\x28", b"\x02\x28") or not records:
                for record in records:
                    if wanted == b"\x03\x28" and len(record) >= 7:
                        db.attributes[_u16(record, 3)] = record[5:]  # value handle -> characteristic uuid
                return GattMessage(name, "Service discovery", False, True)
            # Reading a characteristic by its type (e.g. Device Name) returns its value directly.
            db.attributes.setdefault(_u16(records[0], 0), wanted)
            return self._value_message(handle, server, db, 0x0B, _u16(records[0], 0), records[0][2:])
        if opcode == 0x05 and body:  # Find Information: (handle, uuid) pairs
            width = 2 if body[0] == 1 else 16
            for i in range(1, len(body) - width - 1, 2 + width):
                db.attributes.setdefault(_u16(body, i), body[i + 2:i + 2 + width])
            return GattMessage(name, "Service discovery", False, True)

        if opcode in (0x0A, 0x12, 0x52, 0x1B, 0x1D, 0x16) and len(body) >= 2:
            att_handle = _u16(body, 0)
            value = body[2:] if opcode != 0x16 else body[4:]
            return self._value_message(handle, server, db, opcode, att_handle, value)
        if opcode in (0x0B, 0x0D) and request[0] in (0x0A, 0x0C) and len(request[1]) >= 2:
            return self._value_message(handle, server, db, opcode, _u16(request[1], 0), body)
        if opcode in (0x13, 0x17, 0x18, 0x19, 0x1E):
            return GattMessage(name, name, False, True)
        return GattMessage(name, name, False, True)

    def _value_message(self, handle: int, server: str, db: _Database, opcode: int, att_handle: int,
                       value: bytes) -> GattMessage:
        uuid_bytes = db.attributes.get(att_handle)
        uuid = _short(uuid_bytes) if uuid_bytes else None
        target = self._name(db, att_handle)
        decoded = decode_value(uuid, value) if opcode != 0x0A else None
        shown = decoded if decoded is not None else (f"{len(value)} bytes" if value else "")
        if opcode == 0x0A:
            return GattMessage("Read", f"Reads {target}", False, True)
        if opcode in (0x0B, 0x0D):
            return GattMessage("Read Response", f"{target}: {shown}", False, decoded is None,
                               (uuid, decoded, value) if decoded is not None else None)
        if opcode in (0x12, 0x52, 0x16):
            routine = uuid == 0x2902 or decoded is None
            return GattMessage("Write", f"Writes {target}: {shown}", False, routine,
                               (uuid, decoded, value) if decoded is not None else None)
        # Notification or indication: show it when a known state changes.
        key = (handle, server, att_handle)
        changed = self._last_values.get(key) != value
        self._last_values[key] = value
        kind = "Notification" if opcode == 0x1B else "Indication"
        routine = not (uuid in _STATEFUL and changed)
        return GattMessage(kind, f"{target}: {shown}", False, routine,
                           (uuid, decoded, value) if decoded is not None else (uuid, None, value))
