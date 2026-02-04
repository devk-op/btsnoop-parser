"""Utilities to decode raw HCI payloads into structured dictionaries."""

from __future__ import annotations

from typing import Any

from .constants import HCI_OPCODE_NAMES, HCI_PACKET_TYPES


def _normalise_key(name: str) -> str:
    return name.replace(" ", "_").replace("-", "_").upper()


_PACKET_TYPE_BY_CODE = dict(HCI_PACKET_TYPES)
_PACKET_TYPE_BY_NORMALISED = {
    _normalise_key(label): label for label in HCI_PACKET_TYPES.values()
}


def _packet_type_label(packet_type: Any) -> str:
    if isinstance(packet_type, int):
        return _PACKET_TYPE_BY_CODE.get(packet_type, f"UNKNOWN_{packet_type:02X}")

    normalised = _normalise_key(str(packet_type))
    return _PACKET_TYPE_BY_NORMALISED.get(normalised, normalised)


def decode_hci_packet(packet_type: Any, data: bytes) -> dict[str, Any]:
    """
    Decode raw HCI payload bytes into a friendly dictionary.

    The function gracefully handles short packets by returning an ``error`` field so
    that downstream callers can decide how to react.
    """
    payload = bytes(data or b"")
    label = _packet_type_label(packet_type)

    if label == "COMMAND":
        if len(payload) < 3:
            return {
                "type": "COMMAND",
                "error": "payload too short (<3 bytes)",
                "raw": payload.hex(),
            }
        opcode = payload[0] | (payload[1] << 8)
        param_len = payload[2]
        params = payload[3 : 3 + param_len]
        ogf = (opcode >> 10) & 0x3F
        ocf = opcode & 0x3FF
        return {
            "type": "COMMAND",
            "opcode": opcode,
            "ogf": ogf,
            "ocf": ocf,
            "name": HCI_OPCODE_NAMES.get(opcode, "Unknown"),
            "parameter_length": param_len,
            "parameters_hex": params.hex(),
        }

    if label == "EVENT":
        if len(payload) < 2:
            return {
                "type": "EVENT",
                "error": "payload too short (<2 bytes)",
                "raw": payload.hex(),
            }
        event_code = payload[0]
        param_len = payload[1]
        params = payload[2 : 2 + param_len]
        return {
            "type": "EVENT",
            "event_code": event_code,
            "parameter_length": param_len,
            "parameters_hex": params.hex(),
        }

    return {
        "type": label,
        "length": len(payload),
        "payload_hex": payload.hex(),
    }
