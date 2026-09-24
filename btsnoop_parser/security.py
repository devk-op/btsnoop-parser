"""Extract Classic Bluetooth (BR/EDR) link keys seen in HCI traffic.

A link key passes over HCI in the clear in two places: the controller hands
a freshly-paired key to the host via a Link Key Notification event, and the
host replays a previously-cached key back to the controller via a Link Key
Request Reply command on every subsequent (re)connection — so a link key
shows up here even for captures that don't contain the original pairing.

A link key is credential material: it can decrypt that device's encrypted
traffic (e.g. loaded into Wireshark's Bluetooth protocol preferences). Only
extract these from captures you're authorized to analyze.

This module covers Classic BR/EDR only. BLE uses a different mechanism (an
LTK negotiated via the LE Long Term Key Request event/command pair over a
separate opcode) that isn't decoded here.
"""
from __future__ import annotations

from typing import Any, Iterable

_LINK_KEY_NOTIFICATION_EVENT = 0x18
_LINK_KEY_REQUEST_REPLY_OPCODE = 0x040D

KEY_TYPE_NAMES = {
    0x00: "Combination key",
    0x01: "Local Unit key",
    0x02: "Remote Unit key",
    0x03: "Debug Combination key",
    0x04: "Unauthenticated Combination key (P-192)",
    0x05: "Authenticated Combination key (P-192)",
    0x06: "Changed Combination key",
    0x07: "Unauthenticated Combination key (P-256)",
    0x08: "Authenticated Combination key (P-256)",
}


def _reversed_addr(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in raw[::-1])


def extract_link_keys(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Scan parsed HCI records for Classic BT link keys.

    Returns a list of dicts, each with: `timestamp`, `addr` (device BD_ADDR),
    `link_key` (32-char uppercase hex), `source` ("Link Key Notification" or
    "Link Key Request Reply"), and `key_type`/`key_type_name` (only present
    for Link Key Notification, where the controller reports how the key was
    derived; `None` for Link Key Request Reply, which only replays a cached
    key without stating its type).
    """
    keys: list[dict[str, Any]] = []

    for record in records:
        ptype = record["packet_type"]
        payload = record["payload"]

        if ptype == 0x04 and len(payload) >= 25 and payload[0] == _LINK_KEY_NOTIFICATION_EVENT:
            addr = _reversed_addr(payload[2:8])
            link_key = payload[8:24].hex().upper()
            key_type = payload[24]
            keys.append({
                "timestamp": record["timestamp"],
                "addr": addr,
                "link_key": link_key,
                "source": "Link Key Notification",
                "key_type": key_type,
                "key_type_name": KEY_TYPE_NAMES.get(key_type, f"Unknown (0x{key_type:02X})"),
            })

        elif ptype == 0x01 and len(payload) >= 25:
            opcode = payload[0] | (payload[1] << 8)
            if opcode == _LINK_KEY_REQUEST_REPLY_OPCODE:
                addr = _reversed_addr(payload[3:9])
                link_key = payload[9:25].hex().upper()
                keys.append({
                    "timestamp": record["timestamp"],
                    "addr": addr,
                    "link_key": link_key,
                    "source": "Link Key Request Reply",
                    "key_type": None,
                    "key_type_name": None,
                })

    return keys
