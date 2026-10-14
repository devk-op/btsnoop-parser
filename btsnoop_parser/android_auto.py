"""Wireless Android Auto start-up over Bluetooth.

A car with wireless Android Auto advertises a Bluetooth service for it. The
car and phone exchange a few short messages on that RFCOMM serial port: a
version check, then the car's Wi-Fi details, then the phone's connection
result. Everything after that runs over Wi-Fi and is not in the HCI log.

Each message is a 2-byte length, a 2-byte message id, then a protobuf body.
One message carries the car's Wi-Fi network name and password; it is
recognised but its contents are never decoded.
"""
from __future__ import annotations

from typing import Optional

# Service UUID the car advertises over SDP.
SERVICE_UUID = bytes.fromhex("4de17a0052cb11e6bdf40800200c9a66")

_MESSAGES = {
    1: ("Start request", "Car asks the phone to start wireless Android Auto"),
    2: ("Wi-Fi request", "Phone asks for the car's Wi-Fi details"),
    3: ("Wi-Fi details", "Car sent its Wi-Fi network name and password (not shown)"),
    4: ("Version request", "Car asks which Android Auto version the phone supports"),
    5: ("Version reply", "Phone reports its Android Auto version"),
}


def is_message(payload: bytes) -> bool:
    """True when a serial-port payload has this protocol's framing."""
    return len(payload) >= 4 and int.from_bytes(payload[:2], "big") == len(payload) - 4 \
        and 1 <= int.from_bytes(payload[2:4], "big") <= 7


def _varint_field(body: bytes, wanted: int) -> Optional[int]:
    """Value of the first varint field numbered `wanted` in a protobuf body, as a signed 64-bit int."""
    offset = 0
    while offset < len(body):
        tag = body[offset]
        offset += 1
        field, wire = tag >> 3, tag & 0x07
        if wire == 0:
            value, shift = 0, 0
            while offset < len(body):
                byte = body[offset]
                offset += 1
                value |= (byte & 0x7F) << shift
                shift += 7
                if not byte & 0x80:
                    break
            if field == wanted:
                return value - (1 << 64) if value >= 1 << 63 else value
        elif wire == 2 and offset < len(body):
            offset += 1 + body[offset]
        else:
            return None
    return None


def describe(payload: bytes) -> tuple[str, str, bool]:
    """Return (summary, detail, is_error) for one message."""
    message = int.from_bytes(payload[2:4], "big")
    body = payload[4:]
    if message in _MESSAGES:
        return (*_MESSAGES[message], False)
    # Status replies: 0 means success.
    status = _varint_field(body, 1 if message == 6 else 3)
    if message == 6:
        if status in (0, None):
            return "Wi-Fi status", "Phone connected to the car's Wi-Fi", False
        return "Wi-Fi status", f"Phone could not connect to the car's Wi-Fi (status {status})", True
    if status in (0, None):
        return "Start reply", "Phone accepted the request to start", False
    return "Start reply", f"Phone refused to start (status {status})", True
