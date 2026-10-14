#!/usr/bin/env python3
"""Core parsing utilities for Bluetooth BTSnoop HCI logs."""

from __future__ import annotations

import datetime as _dt
import logging
import os
import struct
from typing import BinaryIO, Iterator, Mapping, MutableMapping, Optional, Sequence, Union

from . import packet_info
from .constants import HCI_OPCODE_NAMES

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

# Event and LE subevent names live with the packet descriptions; kept here for existing imports.
EVENT_NAMES = packet_info.EVENT_NAMES
LE_SUBEVENT_NAMES = packet_info.LE_SUBEVENT_NAMES

CMD_NAMES = HCI_OPCODE_NAMES


def _ts_from_btsnoop(timestamp_us: int) -> _dt.datetime:
    """Convert btsnoop μs since 0001-01-01 to a UTC datetime."""
    unix_us = timestamp_us - BTSNOOP_EPOCH_DELTA_US
    return _dt.datetime.fromtimestamp(unix_us / 1_000_000, _dt.timezone.utc)


def _proto_name(packet_type: int) -> str:
    return HCI_PACKET_TYPES.get(packet_type, f"Unknown (0x{packet_type:02X})")


def _decode_info(packet_type: int, payload: bytes, direction: str) -> str:
    """Produce a short human-friendly info string similar to Wireshark."""
    text, _ = packet_info.describe(packet_type, payload)
    if text is not None:
        return text
    return f"{_proto_name(packet_type)} (len {len(payload)})"


_ANDROID_TS_OFFSET = _dt.timedelta(days=378)


def _needs_android_offset_fix(first_ts: _dt.datetime, reference: _dt.datetime) -> bool:
    # Some Android versions write timestamps 378 days (1 year + 13 days) ahead.
    # A capture can't postdate its reference time (file mtime or now), so a
    # first timestamp that does — and lands before it once shifted back — has the bug.
    slack = _dt.timedelta(days=1)
    return first_ts > reference + slack and first_ts - _ANDROID_TS_OFFSET <= reference + slack


def iter_records(
    source: Union[str, os.PathLike, bytes, bytearray, memoryview, BinaryIO],
    *,
    reference_time: Optional[_dt.datetime] = None,
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

    ``reference_time`` is the latest time the capture could have been taken; it
    anchors the Android +378-day timestamp correction. It defaults to the file's
    modification time for paths, and to the current time otherwise.
    """
    now = _dt.datetime.now(_dt.timezone.utc)
    if isinstance(source, (str, os.PathLike)):
        if reference_time is None:
            mtime = _dt.datetime.fromtimestamp(os.path.getmtime(source), _dt.timezone.utc)
            reference_time = min(mtime, now)
        with open(source, "rb") as fh:
            yield from iter_records(fh.read(), reference_time=reference_time)
        return
    if hasattr(source, "read"):
        yield from iter_records(source.read(), reference_time=reference_time)
        return
    if reference_time is None:
        reference_time = now

    data = memoryview(source)
    if len(data) < 16:
        raise ValueError("File too short to contain BTSnoop header")
    if data[:8].tobytes() != BTSNOOP_HEADER:
        raise ValueError("Invalid BTSnoop file header")

    version, datalink = struct.unpack(">II", data[8:16])
    LOG.debug("Parsed BTSnoop header: version=%s datalink=%s", version, datalink)
    if datalink not in (1001, 1002):
        LOG.warning("Unexpected datalink value %s (expected 1001 or 1002 for HCI H4)", datalink)

    offset = 16
    index = 0
    first_ts: Optional[_dt.datetime] = None
    ts_fix: Optional[_dt.timedelta] = None

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
            if ts_fix is None:
                fix_needed = _needs_android_offset_fix(ts, reference_time)
                ts_fix = _ANDROID_TS_OFFSET if fix_needed else _dt.timedelta(0)
            ts -= ts_fix
        except (ValueError, OverflowError, OSError) as exc:
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
    return list(iter_records(filename))


# Short names for the packet list's Protocol column.
_COLUMN_NAMES = {
    "AVCTP": "AVRCP", "AVCTP Browsing": "AVRCP-BR", "AVDTP": "A2DP", "A2DP Media": "A2DP",
    "L2CAP Signaling": "L2CAP", "HID Control": "HID", "HID Interrupt": "HID",
}


def _column(protocol: str) -> str:
    return "L2CAP" if protocol.startswith("PSM ") else _COLUMN_NAMES.get(protocol, protocol)[:10]


def _data_info(record: Mapping[str, object], trace) -> tuple[str, str, bool]:
    """(protocol, description, is_error) for a data packet, from the protocol decoding."""
    index = record["index"]
    protocol = trace.frame_labels.get(index) if trace is not None else None
    events = trace.events_by_index().get(index, []) if trace is not None else []
    size = len(record["payload"])  # type: ignore[arg-type]
    if not events:
        if protocol is None:
            return "HCI_ACL" if record["packet_type"] == 0x02 else "HCI_" + _proto_name(record["packet_type"]).split()[0], \
                f"{'Continued data' if record['packet_type'] == 0x02 else 'Data'} (len {size})", False
        return _column(protocol), f"{protocol} data (len {size})", False
    parts = []
    for event in events:
        if event.protocol in ("AVRCP", "AAuto") and event.detail:
            parts.append(event.detail)
        elif event.protocol == "HFP" and event.detail and event.detail not in ("OK", "Result"):
            parts.append(f"{event.summary}  ({event.detail})")
        elif event.detail and event.summary not in event.detail:
            parts.append(f"{event.summary}: {event.detail}")
        else:
            parts.append(event.detail or event.summary)
    return _column(events[0].protocol), "; ".join(parts), any(e.is_error for e in events)


def print_table(
    records: Sequence[Mapping[str, object]],
    *,
    limit: Optional[int] = None,
    color: bool = True,
    file=None,
    trace=None,
) -> None:
    """Render a Wireshark-like packet list to stdout or the provided file object.

    Commands and events are described with what they refer to and whether
    they failed; data packets with what they carry (e.g. "AVRCP: Next pressed").
    ``trace`` is a :class:`~btsnoop_parser.protocols.ProtocolTrace` already fed
    with the capture; one is built from ``records`` when it is not given.
    """
    import sys

    if file is None:
        file = sys.stdout
    if trace is None:
        from .protocols import ProtocolTrace

        trace = ProtocolTrace()
        for record in records:
            trace.analyze_record(record)

    if color:
        RESET, BLUE, GREEN, RED = "\033[0m", "\033[34m", "\033[32m", "\033[31m"
    else:
        RESET = BLUE = GREEN = RED = ""

    print(f"{'No.':<5} {'Time':<10} {'Source':<11} {'Destination':<12} {'Protocol':<10} Info", file=file)
    for count, record in enumerate(records):
        if limit is not None and count >= limit:
            break
        direction = str(record["direction"])
        src, dst = ("host", "controller") if direction == "TX" else ("controller", "host")
        c_dir = BLUE if direction == "TX" else GREEN
        packet_type = int(record["packet_type"])  # type: ignore[arg-type]

        info, is_error = packet_info.describe(packet_type, record["payload"])  # type: ignore[arg-type]
        if info is not None:
            proto = "HCI_CMD" if packet_type == 0x01 else "HCI_EVT"
        else:
            proto, info, is_error = _data_info(record, trace)
        c_info = RED if is_error else ""
        print(
            f"{record['index']:<5} {record['delta']:.6f} {c_dir}{src:<11} {dst:<12}{RESET} "
            f"{proto:<10} {c_info}{info}{RESET if c_info else ''}",
            file=file,
        )
    if file is sys.stdout and sys.stderr.isatty():
        print("\nTip: --stats summarises what happened; --protocols shows a timeline of what the devices said.",
              file=sys.stderr)


def slice_records(records: Sequence[Mapping[str, object]], limit: Optional[int]) -> Sequence[Mapping[str, object]]:
    """Return a shortened view of records respecting the limit."""
    if limit is None or limit >= len(records):
        return records
    return records[:limit]


# Normalised aliases accepted by filter_records for the "type" key.
_TYPE_ALIASES: dict[str, set[int]] = {
    "command": {0x01},
    "cmd":     {0x01},
    "acl":     {0x02},
    "sco":     {0x03},
    "event":   {0x04},
    "evt":     {0x04},
    "iso":     {0x05},
}


def filter_records(
    records: Sequence[Mapping[str, object]],
    filters: Sequence[str],
) -> list[Mapping[str, object]]:
    """Return records that match *all* of the supplied filter expressions.

    Each expression is a ``key:value`` string.  Supported keys:

    * ``type`` — packet type name or number, e.g. ``type:event``, ``type:acl``,
      ``type:0x04``.  Multiple values may be comma-separated:
      ``type:command,event``.
    * ``dir`` — direction: ``dir:tx`` or ``dir:rx``.

    Examples::

        filter_records(records, ["type:event"])
        filter_records(records, ["type:command,event", "dir:tx"])
    """
    if not filters:
        return list(records)

    # Pre-parse filter expressions once
    type_ids: Optional[set[int]] = None
    dir_value: Optional[str] = None

    for expr in filters:
        if ":" not in expr:
            raise ValueError(f"Invalid filter expression {expr!r} — expected 'key:value'")
        key, _, value = expr.partition(":")
        key = key.strip().lower()
        value = value.strip().lower()

        if key == "type":
            ids: set[int] = set()
            for part in value.split(","):
                part = part.strip()
                if part.startswith("0x"):
                    ids.add(int(part, 16))
                elif part.isdigit():
                    ids.add(int(part))
                elif part in _TYPE_ALIASES:
                    ids.update(_TYPE_ALIASES[part])
                else:
                    raise ValueError(
                        f"Unknown packet type {part!r}. "
                        f"Valid values: {', '.join(sorted(_TYPE_ALIASES))}, or a hex/int."
                    )
            type_ids = ids if type_ids is None else type_ids & ids

        elif key == "dir":
            if value not in ("tx", "rx"):
                raise ValueError(f"Invalid dir value {value!r} — use 'tx' or 'rx'")
            dir_value = value.upper()

        else:
            raise ValueError(f"Unknown filter key {key!r}. Supported keys: type, dir")

    result = []
    for record in records:
        if type_ids is not None and record["packet_type"] not in type_ids:
            continue
        if dir_value is not None and record["direction"] != dir_value:
            continue
        result.append(record)
    return result
