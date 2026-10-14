"""LE Audio decoding: stream setup (ASCS), capabilities (PACS) and call state (TBS).

LE Audio sets up each audio stream through an Audio Stream Endpoint (ASE) on
the earbuds or hearing aids. The phone writes commands to the ASE Control
Point (configure the codec, configure quality of service, enable, release),
the device answers on the same characteristic, and each ASE reports its state
(codec configured, QoS configured, enabling, streaming, ...).
"""
from __future__ import annotations

from typing import Optional

ASE_STATES = {0: "idle", 1: "codec configured", 2: "QoS configured", 3: "enabling", 4: "streaming",
              5: "disabling", 6: "releasing"}

CONTROL_OPCODES = {1: "Config Codec", 2: "Config QoS", 3: "Enable", 4: "Receiver Start Ready", 5: "Disable",
                   6: "Receiver Stop Ready", 7: "Update Metadata", 8: "Release"}

RESPONSE_CODES = {
    0x00: "success", 0x01: "unsupported command", 0x02: "invalid length", 0x03: "invalid ASE",
    0x04: "not allowed in the current state", 0x05: "wrong direction", 0x06: "unsupported audio capabilities",
    0x07: "unsupported setting", 0x08: "setting rejected", 0x09: "invalid setting", 0x0A: "unsupported metadata",
    0x0B: "metadata rejected", 0x0C: "invalid metadata", 0x0D: "insufficient resources", 0x0E: "unspecified error",
}
_REASONS = {0x01: "codec", 0x02: "codec settings", 0x03: "interval", 0x04: "framing", 0x05: "PHY",
            0x06: "frame size", 0x07: "retransmissions", 0x08: "latency", 0x09: "presentation delay",
            0x0A: "stream mapping"}

CONTEXTS = ["unspecified", "calls", "media", "game", "instructional", "voice assistant", "live", "sound effects",
            "notifications", "ringtone", "alerts", "emergency alarm"]

_COMPANIES = {0x00E0: "Google", 0x0075: "Samsung", 0x004C: "Apple", 0x000A: "Qualcomm", 0x001D: "Qualcomm",
              0x0006: "Microsoft", 0x0057: "Harman", 0x009E: "Bose", 0x012D: "Sony"}
_LC3_RATES = {0x01: "8 kHz", 0x02: "11.025 kHz", 0x03: "16 kHz", 0x04: "22.05 kHz", 0x05: "24 kHz", 0x06: "32 kHz",
              0x07: "44.1 kHz", 0x08: "48 kHz", 0x09: "88.2 kHz", 0x0A: "96 kHz"}
_LC3_SUPPORTED = ["8", "11.025", "16", "22.05", "24", "32", "44.1", "48", "88.2", "96"]
_CALL_STATES = {0: "incoming", 1: "dialing", 2: "ringing at the other end", 3: "active", 4: "on hold",
                5: "held by the other party", 6: "on hold on both ends"}
_CALL_COMMANDS = {0: "Accept call", 1: "End call", 2: "Hold call", 3: "Resume call", 4: "Start call",
                  5: "Join calls"}


def _u16(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8)


def _u24(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 3], "little")


def _ltvs(data: bytes) -> dict[int, bytes]:
    """Length-type-value records, as used for codec settings and metadata."""
    found, offset = {}, 0
    while offset < len(data) and data[offset]:
        length = data[offset]
        if offset + 1 + length > len(data):
            break
        found[data[offset + 1]] = data[offset + 2:offset + 1 + length]
        offset += 1 + length
    return found


def codec_name(codec_id: bytes) -> str:
    if len(codec_id) < 5:
        return "unknown codec"
    if codec_id[0] == 0x06:
        return "LC3"
    if codec_id[0] == 0xFF:
        company = _u16(codec_id, 1)
        return f"{_COMPANIES.get(company, f'company 0x{company:04X}')} vendor codec 0x{_u16(codec_id, 3):04X}"
    return f"codec 0x{codec_id[0]:02X}"


def contexts(mask: int) -> str:
    names = [name for i, name in enumerate(CONTEXTS) if mask & (1 << i)]
    return ", ".join(names) if names else "none"


def metadata_contexts(metadata: bytes) -> Optional[int]:
    """The streaming audio contexts named in ASE metadata (what the stream is for)."""
    value = _ltvs(metadata).get(0x02)
    return _u16(value, 0) if value and len(value) >= 2 else None


def describe_codec(codec_id: bytes, config: bytes) -> str:
    text = codec_name(codec_id)
    if codec_id[:1] != b"\x06":
        return text
    settings = _ltvs(config)
    parts = []
    if 0x01 in settings and settings[0x01]:
        parts.append(_LC3_RATES.get(settings[0x01][0], f"rate 0x{settings[0x01][0]:02X}"))
    duration = {0: 7.5, 1: 10.0}.get(settings[0x02][0]) if settings.get(0x02) else None
    if duration:
        parts.append(f"{duration:g} ms frames")
    if settings.get(0x04) and len(settings[0x04]) >= 2 and duration:
        octets = _u16(settings[0x04], 0)
        parts.append(f"{octets * 8 / duration:.0f} kbps per channel")
    return text + (" " + ", ".join(parts) if parts else "")


def _qos(data: bytes, offset: int) -> str:
    """SDU interval, framing, PHY, max SDU, retransmissions, latency, presentation delay."""
    interval = _u24(data, offset)
    max_sdu = _u16(data, offset + 5)
    latency = _u16(data, offset + 8)
    delay = _u24(data, offset + 10)
    rate = f", up to {max_sdu * 8 * 1000 / interval:.0f} kbps" if interval else ""
    return (f"{max_sdu}-byte packets every {interval / 1000:g} ms{rate}, latency {latency} ms, "
            f"playback delay {delay / 1000:g} ms")


def describe_control(value: bytes, notified: bool) -> tuple[str, bool]:
    """Describe an ASE Control Point command (written) or its result (notified)."""
    if len(value) < 2:
        return "ASE command", False
    opcode, count = value[0], value[1]
    name = CONTROL_OPCODES.get(opcode, f"opcode 0x{opcode:02X}")
    if notified:
        results, failed = [], False
        for k in range(count):
            i = 2 + 3 * k
            if i + 3 > len(value):
                break
            code, reason = value[i + 1], value[i + 2]
            if code:
                failed = True
                why = f" ({_REASONS[reason]})" if reason in _REASONS else ""
                results.append(f"stream {value[i]} {RESPONSE_CODES.get(code, f'error 0x{code:02X}')}{why}")
            else:
                results.append(f"stream {value[i]} ok")
        return f"{name}: " + "; ".join(results), failed

    parts, offset = [], 2
    for _ in range(count):
        if offset >= len(value):
            break
        ase = value[offset]
        if opcode == 1 and offset + 9 <= len(value):
            length = value[offset + 8]
            parts.append(f"stream {ase}: {describe_codec(value[offset + 3:offset + 8], value[offset + 9:offset + 9 + length])}")
            offset += 9 + length
        elif opcode == 2 and offset + 16 <= len(value):
            parts.append(f"stream {ase}: {_qos(value, offset + 3)}")
            offset += 16
        elif opcode in (3, 7) and offset + 2 <= len(value):
            length = value[offset + 1]
            mask = metadata_contexts(value[offset + 2:offset + 2 + length])
            parts.append(f"stream {ase}" + (f" for {contexts(mask)}" if mask is not None else ""))
            offset += 2 + length
        else:
            parts.append(f"stream {ase}")
            offset += 1
    return f"{name}: " + "; ".join(parts), False


def describe_ase(value: bytes) -> str:
    """Describe an ASE state notification."""
    if len(value) < 2:
        return "stream state"
    ase, state = value[0], value[1]
    text = f"stream {ase} {ASE_STATES.get(state, f'state {state}')}"
    if state == 1 and len(value) >= 25:
        text += f" ({describe_codec(value[19:24], value[25:25 + value[24]])})"
    elif state == 2 and len(value) >= 17:
        text += f" ({_qos(value, 4)})"
    elif state in (3, 4, 5) and len(value) >= 5:
        mask = metadata_contexts(value[5:5 + value[4]])
        if mask is not None:
            text += f" for {contexts(mask)}"
    return text


def describe_pac(value: bytes) -> str:
    """Describe a Sink or Source PAC: the codecs and rates a device supports."""
    if not value:
        return "no codecs"
    records, offset = [], 1
    for _ in range(value[0]):
        if offset + 6 > len(value):
            break
        codec_id, length = value[offset:offset + 5], value[offset + 5]
        caps = _ltvs(value[offset + 6:offset + 6 + length])
        offset += 6 + length
        if offset < len(value):
            offset += 1 + value[offset]  # metadata
        text = codec_name(codec_id)
        rates = caps.get(0x01)
        if codec_id[:1] == b"\x06" and rates and len(rates) >= 2:
            mask = _u16(rates, 0)
            supported = [r for i, r in enumerate(_LC3_SUPPORTED) if mask & (1 << i)]
            if supported:
                text += f" ({'/'.join(supported)} kHz)"
        records.append(text)
    return ", ".join(records) if records else "no codecs"


def describe_contexts(value: bytes) -> str:
    if len(value) < 4:
        return f"{len(value)} bytes"
    return f"listening: {contexts(_u16(value, 0))}; microphone: {contexts(_u16(value, 2))}"


def describe_locations(value: bytes) -> str:
    if len(value) < 4:
        return f"{len(value)} bytes"
    mask = int.from_bytes(value[:4], "little")
    names = {0x1: "left", 0x2: "right", 0x4: "centre"}
    found = [name for bit, name in names.items() if mask & bit]
    return " and ".join(found) if found else f"locations 0x{mask:08X}"


def call_states(value: bytes) -> list[tuple[int, str]]:
    """(call index, state) for each call in a Call State value."""
    return [(value[i], _CALL_STATES.get(value[i + 1], f"state {value[i + 1]}"))
            for i in range(0, len(value) - 2, 3)]


def describe_calls(value: bytes) -> str:
    calls = call_states(value)
    return "; ".join(f"call {index} {state}" for index, state in calls) if calls else "no calls"


def describe_call_control(value: bytes, notified: bool) -> tuple[str, bool]:
    if not value:
        return "call command", False
    name = _CALL_COMMANDS.get(value[0], f"command 0x{value[0]:02X}")
    if notified and len(value) >= 3:
        ok = value[2] == 0
        return f"{name}: {'done' if ok else f'failed (result 0x{value[2]:02X})'}", not ok
    return name, False


def looks_like_control_command(value: bytes) -> bool:
    return len(value) >= 3 and value[0] in CONTROL_OPCODES and 1 <= value[1] <= 8


def answers(command: bytes, response: bytes) -> bool:
    """True when a notification is the control point's answer to a command."""
    return (len(response) >= 5 and response[:2] == command[:2]
            and len(response) == 2 + 3 * response[1])


def looks_like_ase(value: bytes, ase_ids: set[int]) -> bool:
    return len(value) >= 2 and value[0] in ase_ids and value[1] in ASE_STATES
