"""AVDTP decoding: the signaling behind A2DP audio streaming.

A2DP uses two L2CAP channels per connection. The first AVDTP channel carries
signaling: finding the other device's audio endpoints, agreeing a codec, and
opening, starting, pausing (suspending) and closing the stream. Later AVDTP
channels carry the audio itself as RTP packets.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

SIGNALS = {
    0x01: "Discover",
    0x02: "Get Capabilities",
    0x03: "Set Configuration",
    0x04: "Get Configuration",
    0x05: "Reconfigure",
    0x06: "Open",
    0x07: "Start",
    0x08: "Close",
    0x09: "Suspend",
    0x0A: "Abort",
    0x0B: "Security Control",
    0x0C: "Get All Capabilities",
    0x0D: "Delay Report",
}

MESSAGE_TYPES = {0: "command", 1: "general reject", 2: "accept", 3: "reject"}

ERRORS = {
    0x01: "bad header format",
    0x11: "bad length",
    0x12: "bad endpoint id",
    0x13: "endpoint already in use",
    0x14: "endpoint not in use",
    0x17: "bad service category",
    0x18: "bad payload format",
    0x19: "command not supported",
    0x1A: "invalid capabilities",
    0x22: "bad recovery type",
    0x23: "bad media transport format",
    0x25: "bad recovery format",
    0x26: "bad header compression format",
    0x27: "bad content protection format",
    0x28: "bad multiplexing format",
    0x29: "unsupported configuration",
    0x31: "wrong state for this command",
    # A2DP codec errors
    0xC1: "invalid codec type",
    0xC2: "codec type not supported",
    0xC3: "invalid sampling frequency",
    0xC4: "sampling frequency not supported",
    0xC5: "invalid channel mode",
    0xC6: "channel mode not supported",
    0xD3: "invalid bitpool",
    0xD4: "bitpool not supported",
    0xE0: "invalid codec parameter",
    0xE1: "codec parameter not supported",
}

# (vendor id, codec id) -> name, for codecs sent as "vendor specific".
VENDOR_CODECS = {
    (0x0000004F, 0x0001): "aptX",
    (0x000000D7, 0x0024): "aptX HD",
    (0x0000000A, 0x0002): "aptX Low Latency",
    (0x000000D7, 0x00AD): "aptX Adaptive",
    (0x0000012D, 0x00AA): "LDAC",
    (0x00000075, 0x0102): "Samsung Scalable",
    (0x000000E0, 0x0001): "Opus",
}

_SBC_RATES = {0x80: "16 kHz", 0x40: "32 kHz", 0x20: "44.1 kHz", 0x10: "48 kHz"}
_SBC_MODES = {0x08: "mono", 0x04: "dual channel", 0x02: "stereo", 0x01: "joint stereo"}
_AAC_RATES = ["8 kHz", "11.025 kHz", "12 kHz", "16 kHz", "22.05 kHz", "24 kHz", "32 kHz", "44.1 kHz",
              "48 kHz", "64 kHz", "88.2 kHz", "96 kHz"]


@dataclass
class AvdtpSignal:
    label: int
    message_type: int
    signal: int
    body: bytes  # parameters after the signal id

    @property
    def name(self) -> str:
        return SIGNALS.get(self.signal, f"signal 0x{self.signal:02X}")

    @property
    def is_command(self) -> bool:
        return self.message_type == 0


def parse_signal(payload: bytes) -> Optional[AvdtpSignal]:
    """Decode the header of an AVDTP signaling message (None for continuation fragments)."""
    if len(payload) < 2:
        return None
    packet_type = (payload[0] >> 2) & 0x03
    if packet_type == 0:  # single packet
        signal, body = payload[1] & 0x3F, payload[2:]
    elif packet_type == 1 and len(payload) >= 3:  # first of several packets
        signal, body = payload[2] & 0x3F, payload[3:]
    else:
        return None
    return AvdtpSignal(label=payload[0] >> 4, message_type=payload[0] & 0x03, signal=signal, body=body)


# Exact or minimum parameter length of each command, used to recognise AVDTP on a
# channel whose setup happened before the capture started.
_COMMAND_LENGTHS = {0x01: (0, 0), 0x02: (1, 1), 0x03: (2, 255), 0x04: (1, 1), 0x05: (1, 255), 0x06: (1, 1),
                    0x07: (1, 32), 0x08: (1, 1), 0x09: (1, 32), 0x0A: (1, 1), 0x0B: (1, 255), 0x0C: (1, 1),
                    0x0D: (3, 3)}


def plausible_command(sig: AvdtpSignal, length: int) -> bool:
    """True when a message's declared L2CAP length fits the command it claims to be."""
    bounds = _COMMAND_LENGTHS.get(sig.signal)
    return sig.is_command and bounds is not None and bounds[0] <= length - 2 <= bounds[1]


def is_media_packet(payload: bytes, length: int) -> bool:
    """True for an RTP packet as A2DP sends audio: version 2 with a dynamic payload type."""
    return len(payload) >= 2 and payload[0] & 0xC0 == 0x80 and payload[1] & 0x7F >= 96 and length >= 40


def _seid(byte: int) -> int:
    return byte >> 2


def describe_codec(info: bytes) -> str:
    """Describe a Media Codec capability/configuration (the bytes after category and length)."""
    if len(info) < 2:
        return "unknown codec"
    codec = info[1]
    if codec == 0x00:
        if len(info) < 6:
            return "SBC"
        rates = [r for bit, r in _SBC_RATES.items() if info[2] & bit]
        modes = [m for bit, m in _SBC_MODES.items() if info[2] & bit]
        return f"SBC {'/'.join(rates)} {'/'.join(modes)}, bitpool {info[4]}-{info[5]}"
    if codec == 0x02:
        if len(info) < 5:
            return "AAC"
        bits = (info[3] << 4) | (info[4] >> 4)
        rates = [r for i, r in enumerate(_AAC_RATES) if bits & (1 << (11 - i))]
        return f"AAC {'/'.join(rates)}" if rates else "AAC"
    if codec == 0x01:
        return "MP3"
    if codec == 0xFF and len(info) >= 8:
        vendor = int.from_bytes(info[2:6], "little")
        codec_id = int.from_bytes(info[6:8], "little")
        return VENDOR_CODECS.get((vendor, codec_id), f"vendor codec 0x{vendor:08X}/0x{codec_id:04X}")
    return f"codec 0x{codec:02X}"


def _capabilities(data: bytes) -> tuple[list[str], list[str]]:
    """Split service capabilities into (codec descriptions, other features)."""
    codecs, features = [], []
    offset = 0
    while offset + 2 <= len(data):
        category, length = data[offset], data[offset + 1]
        value = data[offset + 2:offset + 2 + length]
        offset += 2 + length
        if category == 0x07:
            codecs.append(describe_codec(value))
        elif category == 0x04:
            features.append("content protection")
        elif category == 0x08:
            features.append("delay reporting")
    return codecs, features


def describe(sig: AvdtpSignal) -> tuple[str, bool]:
    """Return (plain-English description, is_error) for one signaling message."""
    body = sig.body
    if sig.message_type == 1:
        return f"{sig.name} not understood by the other device", True
    if sig.message_type == 3:
        # Configuration rejects name the failing category first; Start/Suspend name the endpoint first.
        code = body[1] if sig.signal in (0x03, 0x05, 0x07, 0x09) and len(body) >= 2 else (body[0] if body else None)
        reason = ERRORS.get(code, f"error 0x{code:02X}") if code is not None else "no reason given"
        return f"{sig.name} rejected: {reason}", True

    command = sig.is_command
    if sig.signal == 0x01:
        if command:
            return "Asks which audio endpoints the other device has", False
        endpoints = []
        for i in range(0, len(body) - 1, 2):
            role = "sink" if body[i + 1] & 0x08 else "source"
            media = "audio" if body[i + 1] >> 4 == 0 else "video"
            used = ", in use" if body[i] & 0x02 else ""
            endpoints.append(f"{_seid(body[i])} ({media} {role}{used})")
        return "Endpoints: " + (", ".join(endpoints) if endpoints else "none listed"), False
    if sig.signal in (0x02, 0x0C):
        if command:
            return f"Asks endpoint {_seid(body[0])} what it supports" if body else "Asks an endpoint what it supports", False
        codecs, features = _capabilities(body)
        text = "Supports " + (", ".join(codecs) if codecs else "an unrecorded codec")
        return text + (f"; {', '.join(features)}" if features else ""), False
    if sig.signal in (0x03, 0x05):
        if command:
            codecs, features = _capabilities(body[2:] if sig.signal == 0x03 else body[1:])
            what = codecs[0] if codecs else "codec settings not recorded"
            verb = "Configures the stream" if sig.signal == 0x03 else "Changes the stream to"
            return f"{verb}: {what}" + (f"; {', '.join(features)}" if features else ""), False
        return "Configuration accepted", False
    if sig.signal == 0x04:
        if command:
            return "Asks for the stream's current configuration", False
        codecs, _ = _capabilities(body)
        return "Current configuration: " + (codecs[0] if codecs else "not recorded"), False
    if sig.signal == 0x0D:
        if command and len(body) >= 3:
            return f"Reports an audio delay of {int.from_bytes(body[1:3], 'big') / 10:.1f} ms", False
        return ("Reports its audio delay" if command else "Delay report acknowledged"), False
    actions = {
        0x06: ("Asks to open the audio stream", "Audio stream opened"),
        0x07: ("Asks to start streaming audio", "Audio streaming started"),
        0x08: ("Asks to close the audio stream", "Audio stream closed"),
        0x09: ("Asks to pause the audio stream", "Audio stream paused"),
        0x0A: ("Aborts the audio stream", "Stream aborted"),
        0x0B: ("Content protection exchange", "Content protection exchange accepted"),
    }
    request, done = actions.get(sig.signal, (sig.name, f"{sig.name} accepted"))
    return (request if command else done), False
