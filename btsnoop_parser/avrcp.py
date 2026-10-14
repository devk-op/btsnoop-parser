"""AVRCP decoding: media buttons, volume, play status and track changes.

AVRCP messages travel over AVCTP. Each has an AV/C header saying whether it is
a command or a response, and an opcode: PASS THROUGH for button presses, or
VENDOR DEPENDENT for everything else (volume, notifications, play status,
track details), which then names a PDU.

Android's filtered snoop mode keeps only the first 6 bytes of each message,
which ends just before the PDU or button. For such messages the description
falls back to what the message size and direction usually mean, and says so.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

CTYPES = {
    0x0: "control", 0x1: "status", 0x2: "specific inquiry", 0x3: "notify", 0x4: "general inquiry",
    0x8: "not implemented", 0x9: "accepted", 0xA: "rejected", 0xB: "in transition", 0xC: "stable",
    0xD: "changed", 0xF: "interim",
}
_FAILED = {0x8, 0xA}

BUTTONS = {
    0x40: "Power", 0x41: "Volume Up", 0x42: "Volume Down", 0x43: "Mute", 0x44: "Play", 0x45: "Stop",
    0x46: "Pause", 0x47: "Record", 0x48: "Rewind", 0x49: "Fast Forward", 0x4A: "Eject", 0x4B: "Next",
    0x4C: "Previous", 0x7E: "Vendor button",
}

PDUS = {
    0x10: "Get Capabilities", 0x11: "List Player Settings", 0x13: "Get Player Settings",
    0x14: "Set Player Settings", 0x20: "Get Track Details", 0x30: "Get Play Status",
    0x31: "Register Notification", 0x40: "Continue Response", 0x41: "Abort Response",
    0x50: "Set Absolute Volume", 0x60: "Set Addressed Player", 0x74: "Play Item", 0x90: "Add To Now Playing",
}

EVENTS = {
    0x01: "play status", 0x02: "track", 0x03: "track end", 0x04: "track start", 0x05: "play position",
    0x06: "battery", 0x07: "system status", 0x08: "player settings", 0x09: "now playing list",
    0x0A: "available players", 0x0B: "active player", 0x0C: "media library", 0x0D: "volume",
}

PLAY_STATUS = {0: "stopped", 1: "playing", 2: "paused", 3: "seeking forward", 4: "seeking back", 0xFF: "error"}
_BATTERY = {0: "normal", 1: "low", 2: "critical", 3: "on external power", 4: "full"}
_ATTRIBUTES = {1: "Title", 2: "Artist", 3: "Album", 7: "Duration"}

_SIG_COMPANY = b"\x00\x19\x58"
_VENDOR_HEADER = 13  # AVCTP (3) + AV/C (3) + company (3) + PDU, packet type, parameter length (4)


@dataclass
class AvrcpMessage:
    label: int
    is_response: bool
    ctype: int
    opcode: int
    payload: bytes  # the whole AVCTP message as captured
    length: int  # its declared length, larger than len(payload) when the capture cut it

    @property
    def ctype_name(self) -> str:
        return CTYPES.get(self.ctype, f"0x{self.ctype:X}")

    @property
    def failed(self) -> bool:
        return self.is_response and self.ctype in _FAILED


def parse(payload: bytes, length: int) -> Optional[AvrcpMessage]:
    """Decode the AVCTP and AV/C headers of a single-packet AVRCP message."""
    if len(payload) < 6 or (payload[0] >> 2) & 0x03 != 0 or payload[1:3] != b"\x11\x0e":
        return None
    return AvrcpMessage(label=payload[0] >> 4, is_response=bool(payload[0] & 0x02), ctype=payload[3] & 0x0F,
                        opcode=payload[5], payload=payload, length=length)


def _volume(byte: int) -> str:
    return f"{round((byte & 0x7F) * 100 / 127)}%"


def _clock(ms: int) -> str:
    seconds = ms // 1000
    return f"{seconds // 60}:{seconds % 60:02d}"


def _event_value(event: int, data: bytes) -> str:
    if event == 0x01 and data:
        return PLAY_STATUS.get(data[0], f"0x{data[0]:02X}")
    if event == 0x02 and len(data) >= 8:
        return "nothing selected" if data[:8] == b"\xff" * 8 else "new track"
    if event == 0x05 and len(data) >= 4:
        position = int.from_bytes(data[:4], "big")
        return "unknown" if position == 0xFFFFFFFF else _clock(position)
    if event == 0x06 and data:
        return _BATTERY.get(data[0], f"0x{data[0]:02X}")
    if event == 0x0D and data:
        return _volume(data[0])
    return ""


def _track_details(params: bytes) -> str:
    if not params:
        return "Track details"
    parts, offset = [], 1
    for _ in range(params[0]):
        if offset + 8 > len(params):
            break
        attribute = int.from_bytes(params[offset:offset + 4], "big")
        size = int.from_bytes(params[offset + 6:offset + 8], "big")
        value = params[offset + 8:offset + 8 + size].decode("utf-8", "replace")
        offset += 8 + size
        if attribute == 7 and value.isdigit():
            value = _clock(int(value))
        if attribute in _ATTRIBUTES and value:
            parts.append(f"{_ATTRIBUTES[attribute]}: {value}")
    return "; ".join(parts) if parts else "Track details"


def describe(msg: AvrcpMessage, from_phone: bool) -> tuple[str, str, bool]:
    """Return (summary, plain-English detail, is_error).

    ``from_phone`` is True for messages the capturing device sent; it is only
    used to interpret messages the capture cut short.
    """
    if msg.opcode == 0x7C:
        return _pass_through(msg)
    if msg.opcode != 0x00:
        return "AV/C " + msg.ctype_name, f"AV/C opcode 0x{msg.opcode:02X}", msg.failed
    if len(msg.payload) < _VENDOR_HEADER:
        return _vendor_cut(msg, from_phone)
    if msg.payload[6:9] != _SIG_COMPANY:
        return "Vendor command", "Manufacturer-specific remote control message", msg.failed

    pdu = msg.payload[9]
    params = msg.payload[_VENDOR_HEADER:]
    name = PDUS.get(pdu, f"PDU 0x{pdu:02X}")
    if msg.failed:
        reason = f" (error 0x{params[0]:02X})" if params else ""
        return name, f"{name} {msg.ctype_name}{reason}", True
    if pdu == 0x31:
        event = params[0] if params else None
        what = EVENTS.get(event, f"event 0x{event:02X}") if event is not None else "an event"
        if not msg.is_response:
            return name, f"Asks to be told when the {what} changes", False
        value = _event_value(event, params[1:]) if event is not None else ""
        if msg.ctype == 0xF:
            return name, f"Current {what}: {value}" if value else f"Will report {what} changes", False
        return name, f"{what.capitalize()} changed" + (f": {value}" if value else ""), False
    if pdu == 0x50:
        level = _volume(params[0]) if params else "?"
        return name, (f"Sets the volume to {level}" if not msg.is_response else f"Volume is now {level}"), False
    if pdu == 0x30:
        if not msg.is_response:
            return name, "Asks for the play status", False
        if len(params) >= 9:
            length, position = int.from_bytes(params[0:4], "big"), int.from_bytes(params[4:8], "big")
            status = PLAY_STATUS.get(params[8], f"0x{params[8]:02X}")
            return name, f"{status.capitalize()}, {_clock(position)} of {_clock(length)}", False
        return name, "Play status reply", False
    if pdu == 0x20:
        return name, ("Asks for the track's title, artist and album" if not msg.is_response
                      else _track_details(params)), False
    if pdu == 0x10:
        if msg.is_response and len(params) >= 2 and params[0] == 0x03:
            events = [EVENTS.get(e, f"0x{e:02X}") for e in params[2:2 + params[1]]]
            return name, "Can report: " + ", ".join(events), False
        return name, "Asks what the other side supports" if not msg.is_response else "Capabilities", False
    return name, f"{name} {msg.ctype_name}", False


def _pass_through(msg: AvrcpMessage) -> tuple[str, str, bool]:
    if len(msg.payload) < 7:
        if msg.is_response:
            return "Button", f"Button {msg.ctype_name} (which button was not recorded)", msg.failed
        return "Button", "Button pressed or released (which button was not recorded)", False
    button = BUTTONS.get(msg.payload[6] & 0x7F, f"button 0x{msg.payload[6] & 0x7F:02X}")
    action = "released" if msg.payload[6] & 0x80 else "pressed"
    if msg.is_response:
        return button, f"{button} {action}: {msg.ctype_name}", msg.failed
    return button, f"{button} {action}", False


def _vendor_cut(msg: AvrcpMessage, from_phone: bool) -> tuple[str, str, bool]:
    """Guess a vendor-dependent message cut before its PDU from its declared size, type and sender."""
    note = "; details cut from the log"
    size = msg.length - _VENDOR_HEADER
    if msg.failed:
        return "Request failed", f"Request {msg.ctype_name}{note}", True
    if not msg.is_response:
        if msg.ctype == 0x3 and size == 5:
            return "Register Notification", f"Asks to be told about a change{note}", False
        if msg.ctype == 0x1 and size == 0:
            return "Get Play Status", f"Likely asks for the play status{note}", False
        if msg.ctype == 0x0 and size == 1:
            return "Set Absolute Volume", f"Likely sets the volume{note}", False
        return "Request", f"Request ({msg.ctype_name}){note}", False
    if msg.ctype == 0xC and size == 9:
        return "Get Play Status", f"Likely play status and position{note}", False
    if msg.ctype in (0xD, 0xF):
        # The phone reports play state, position and track; the headset reports its volume.
        guesses = {1: ("play status" if from_phone else "volume"), 4: "play position",
                   8: "track", 0: "now playing list or players"}
        guess = guesses.get(size - 1)
        if msg.ctype == 0xD:
            what = f"Likely {guess} changed" if guess else "A notified value changed"
        else:
            what = f"Likely current {guess}" if guess else "Current value of a notified item"
        return "Notification", what + note, False
    return "Response", f"Response ({msg.ctype_name}){note}", False


def is_routine(msg: AvrcpMessage) -> bool:
    """True for bookkeeping traffic: notification sign-ups, status polls, button acknowledgements."""
    if msg.failed:
        return False
    if msg.opcode == 0x7C:
        released = len(msg.payload) >= 7 and msg.payload[6] & 0x80
        return msg.is_response or bool(released)
    if msg.opcode != 0x00 or msg.ctype in (0x3, 0xF):  # notification sign-ups and their first answer
        return msg.opcode == 0x00
    if len(msg.payload) >= _VENDOR_HEADER:
        pdu, params = msg.payload[9], msg.payload[_VENDOR_HEADER:]
        return pdu in (0x10, 0x30) or (pdu == 0x31 and params[:1] == b"\x05")
    size = msg.length - _VENDOR_HEADER
    # Cut short: play status polls (empty request, 9-byte answer) and position updates (4 bytes of data).
    return (msg.ctype == 0x1 and size == 0) or (msg.ctype == 0xC and size == 9) or (msg.ctype == 0xD and size == 5)
