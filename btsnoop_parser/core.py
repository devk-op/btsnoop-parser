#!/usr/bin/env python3
"""Core parsing utilities for Bluetooth BTSnoop HCI logs."""

from __future__ import annotations

import datetime as _dt
import logging
import os
import struct
from typing import BinaryIO, Iterator, Mapping, MutableMapping, Optional, Sequence, Union

BTSNOOP_HEADER = b"btsnoop\0"
# μs between 0001-01-01 and 1970-01-01 (btsnoop epoch → Unix epoch)
BTSNOOP_EPOCH_DELTA_US = 62135596800000000

LOG = logging.getLogger(__name__)

# H4 packet types -> human readable names
HCI_PACKET_TYPES = {
    0x01: "Command",
    0x02: "ACL Data",
    0x03: "SCO Data",
    0x04: "Event",
    0x05: "ISO Data",  # BLE isochronous (LE Audio)
}

# Common event codes
EVENT_NAMES = {
    0x01: "Inquiry Complete",
    0x02: "Inquiry Result",
    0x03: "Connection Complete",
    0x05: "Disconnection Complete",
    0x0E: "Command Complete",
    0x0F: "Command Status",
    0x3E: "LE Meta Event",
}

# LE Meta subevents
LE_SUBEVENT_NAMES = {
    0x01: "LE Connection Complete",
    0x02: "LE Advertising Report",
    0x03: "LE Connection Update Complete",
    0x0A: "LE PHY Update Complete",
    0x0E: "LE Extended Advertising Report",
    0x0F: "LE Periodic Adv Sync Established",
    0x12: "LE Channel Selection Algorithm",
    0x19: "LE CIS Established",
    0x1D: "LE BIG Info Adv Report",
}

# A tiny set of common command opcodes (Opcode = OGF<<10 | OCF)
CMD_NAMES = {
    0x0C01: "Set Event Mask",
    0x0C03: "Reset",
    0x0C14: "Read Local Name",
    0x0C1F: "Write LE Host Supported",
    0x0C3C: "Read Local Supported Codecs (V2)",
    0x1001: "Read Local Version Information",
    0x1002: "Read Local Supported Commands",
    0x1003: "Read Local Supported Features",
    0x1009: "Read BD_ADDR",
    0x2001: "LE Set Event Mask",
    0x2002: "LE Read Buffer Size",
    0x2003: "LE Read Local Supported Features",
    0x200C: "LE Read White List Size",
    0x201C: "LE Read Supported States",
    0x2067: "LE Read Local Supported Features (V2)",
}


def _ts_from_btsnoop(timestamp_us: int) -> _dt.datetime:
    """Convert btsnoop μs since 0001-01-01 to a UTC datetime."""
    unix_us = timestamp_us - BTSNOOP_EPOCH_DELTA_US
    return _dt.datetime.fromtimestamp(unix_us / 1_000_000, _dt.timezone.utc)


def _proto_name(packet_type: int) -> str:
    return HCI_PACKET_TYPES.get(packet_type, f"Unknown (0x{packet_type:02X})")


def _decode_info(packet_type: int, payload: bytes, direction: str) -> str:
    """Produce a short human-friendly info string similar to Wireshark."""
    send_recv = "Sent" if direction == "TX" else "Rcvd"

    if packet_type == 0x01:  # Command
        if len(payload) >= 3:
            opcode = payload[0] | (payload[1] << 8)
            name = CMD_NAMES.get(opcode, f"Opcode 0x{opcode:04X}")
            return f"{send_recv} Command {name}"
        return f"{send_recv} Command (short)"

    if packet_type == 0x04:  # Event
        if len(payload) >= 2:
            evt = payload[0]
            name = EVENT_NAMES.get(evt, f"Event 0x{evt:02X}")
            if evt == 0x3E and len(payload) >= 3:
                sub = payload[2]
                subname = LE_SUBEVENT_NAMES.get(sub, f"Subevent 0x{sub:02X}")
                return f"{send_recv} LE Meta: {subname}"
            return f"{send_recv} {name}"
        return f"{send_recv} Event (short)"

    if packet_type == 0x02:
        return f"{send_recv} ACL Data (len {len(payload)})"
    if packet_type == 0x03:
        return f"{send_recv} SCO Data (len {len(payload)})"
    if packet_type == 0x05:
        return f"{send_recv} ISO Data (len {len(payload)})"

    return f"{send_recv} {_proto_name(packet_type)}"


def iter_records(
    source: Union[str, os.PathLike, bytes, bytearray, memoryview, BinaryIO]
) -> Iterator[MutableMapping[str, object]]:
    """
    Yield parsed records from a BTSnoop HCI capture.

    The function accepts a filesystem path or raw bytes. For each record it yields
    a mutable mapping containing both modern and legacy keys:
      - index: 1-based record counter
      - timestamp: datetime.datetime instance (UTC)
      - delta: seconds from the first record as float
      - direction: 'TX' (host→controller) or 'RX' (controller→host)
      - packet_type: numeric HCI packet type
      - packet_type_name: human readable packet type
      - packet_type_id / packet_type_str (legacy aliases)
      - payload / packet_data: payload bytes (alias)
      - original_length, captured_length: integer lengths
      - flags, drops: raw values from the file header
    """
    if isinstance(source, (str, os.PathLike)):
        with open(source, "rb") as fh:
            yield from iter_records(fh.read())
        return
    if hasattr(source, "read"):
        yield from iter_records(source.read())
        return

    data = memoryview(source)
    if len(data) < 16:
        raise ValueError("File too short to contain BTSnoop header")
    if data[:8].tobytes() != BTSNOOP_HEADER:
        raise ValueError("Invalid BTSnoop file header")

    version, datalink = struct.unpack(">II", data[8:16])
    LOG.debug("Parsed BTSnoop header: version=%s datalink=%s", version, datalink)
    if datalink != 1001:
        LOG.warning("Unexpected datalink value %s (expected 1001 for HCI H4)", datalink)

    offset = 16
    index = 0
    first_ts: Optional[_dt.datetime] = None

    while offset + 24 <= len(data):
        orig_len, incl_len, flags, drops, timestamp = struct.unpack(
            ">IIIIQ", data[offset:offset + 24]
        )
        offset += 24
        if incl_len == 0:
            continue
        if offset + incl_len > len(data):
            LOG.warning(
                "Truncated packet encountered (wanted %s bytes, have %s). Stopping parse.",
                incl_len,
                len(data) - offset,
            )
            return

        packet = data[offset:offset + incl_len].tobytes()
        offset += incl_len
        ptype = packet[0]
        payload = packet[1:] if len(packet) > 1 else b""

        try:
            ts = _ts_from_btsnoop(timestamp)
        except Exception as exc:
            LOG.error("Skipping record with invalid timestamp %s: %s", timestamp, exc)
            continue

        index += 1
        if first_ts is None:
            first_ts = ts
        delta = (ts - first_ts).total_seconds() if first_ts else 0.0

        direction = "RX" if (flags & 0x1) else "TX"
        record: MutableMapping[str, object] = {
            "index": index,
            "timestamp": ts,
            "delta": delta,
            "direction": direction,
            "packet_type": ptype,
            "packet_type_name": _proto_name(ptype),
            "packet_type_id": ptype,  # legacy alias
            "packet_type_str": _proto_name(ptype),  # legacy alias
            "payload": payload,
            "packet_data": payload,  # legacy alias
            "original_length": orig_len,
            "captured_length": incl_len,
            "flags": flags,
            "drops": drops,
        }
        yield record


def parse_btsnoop_file(filename: Union[str, os.PathLike]) -> list[MutableMapping[str, object]]:
    """Return a list of records parsed from a BTSnoop HCI log."""
    with open(filename, "rb") as fh:
        return list(iter_records(fh.read()))


def print_table(
    records: Sequence[Mapping[str, object]],
    *,
    limit: Optional[int] = None,
    file=None,
) -> None:
    """Render a Wireshark-like summary table to stdout or the provided file object."""
    if file is None:
        import sys

        file = sys.stdout

    header = f"{'No.':<5} {'Time':<10} {'Source':<11} {'Destination':<12} {'Protocol':<10} Info"
    print(header, file=file)

    count = 0
    for record in records:
        if limit is not None and count >= limit:
            break

        count += 1
        src = "host" if record["direction"] == "TX" else "controller"
        dst = "controller" if record["direction"] == "TX" else "host"
        proto_name = str(record.get("packet_type_name") or _proto_name(record["packet_type"]))  # type: ignore[index]
        proto = ("HCI_" + proto_name.split()[0]).ljust(10)
        info = _decode_info(
            int(record["packet_type"]),  # type: ignore[arg-type]
            record["packet_data"],  # type: ignore[index]
            str(record["direction"]),
        )
        print(
            f"{record['index']:<5} {record['delta']:.6f} {src:<11} {dst:<12} {proto} {info}",
            file=file,
        )


def slice_records(records: Sequence[Mapping[str, object]], limit: Optional[int]) -> Sequence[Mapping[str, object]]:
    """Return a shortened view of records respecting the limit."""
    if limit is None or limit >= len(records):
        return records
    return records[:limit]
