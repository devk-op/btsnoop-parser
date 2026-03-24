"""Write parsed BTSnoop records to a PCAP file readable by Wireshark / tshark."""
from __future__ import annotations

import os
import struct
from typing import IO, Mapping, Sequence, Union

# PCAP global header constants
_PCAP_MAGIC = 0xA1B2C3D4        # little-endian, microsecond resolution
_PCAP_VERSION_MAJOR = 2
_PCAP_VERSION_MINOR = 4
_PCAP_SNAPLEN = 65535

# Link type 201 = LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR
# Wireshark uses the 4-byte pseudo-header to show TX/RX direction.
_LINKTYPE_BT_HCI_H4_PHDR = 201
_PHDR_HOST_TO_CONTROLLER = 0x00000000  # TX
_PHDR_CONTROLLER_TO_HOST = 0x00000001  # RX

_GLOBAL_HEADER_FMT = "<IHHiIII"   # magic, maj, min, zone, sigfigs, snaplen, network
_PKT_HEADER_FMT    = "<IIII"      # ts_sec, ts_usec, incl_len, orig_len


def write_pcap(
    records: Sequence[Mapping[str, object]],
    dest: Union[str, os.PathLike, IO[bytes]],
) -> int:
    """Write *records* to a PCAP file at *dest*.

    Returns the number of packets written.  The output uses link type
    ``LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR`` (201) so Wireshark can colour
    packets by direction (TX blue / RX green) exactly as btsnoop-parser does.

    Parameters
    ----------
    records:
        Any iterable of record dicts as returned by :func:`iter_records` or
        :func:`parse_btsnoop_file`.
    dest:
        Filesystem path (str or :class:`pathlib.Path`) **or** an already-open
        binary file object.  When a path is given the file is created/truncated.

    Example
    -------
    ::

        from btsnoop_parser import parse_btsnoop_file
        from btsnoop_parser.pcap import write_pcap

        records = parse_btsnoop_file("btsnoop_hci.log")
        write_pcap(records, "capture.pcap")
        # open in Wireshark: wireshark capture.pcap
    """
    if isinstance(dest, (str, os.PathLike)):
        with open(dest, "wb") as fh:
            return write_pcap(records, fh)

    fh: IO[bytes] = dest  # type: ignore[assignment]

    # --- Global header ---
    fh.write(
        struct.pack(
            _GLOBAL_HEADER_FMT,
            _PCAP_MAGIC,
            _PCAP_VERSION_MAJOR,
            _PCAP_VERSION_MINOR,
            0,       # thiszone (UTC)
            0,       # sigfigs
            _PCAP_SNAPLEN,
            _LINKTYPE_BT_HCI_H4_PHDR,
        )
    )

    count = 0
    for record in records:
        ts = record["timestamp"]
        # Compute Unix timestamp in seconds + microseconds
        ts_float: float = ts.timestamp()  # type: ignore[union-attr]
        ts_sec = int(ts_float)
        ts_usec = int((ts_float - ts_sec) * 1_000_000)

        # 4-byte pseudo-header: direction
        direction = record["direction"]
        phdr = _PHDR_HOST_TO_CONTROLLER if direction == "TX" else _PHDR_CONTROLLER_TO_HOST
        pseudo = struct.pack("<I", phdr)

        # H4 frame = packet_type_byte + payload
        ptype_byte = bytes([int(record["packet_type"])])  # type: ignore[arg-type]
        payload = bytes(record["payload"])  # type: ignore[arg-type]
        frame = pseudo + ptype_byte + payload

        incl_len = len(frame)
        orig_len = 4 + 1 + int(record["original_length"])  # phdr + type + payload

        fh.write(struct.pack(_PKT_HEADER_FMT, ts_sec, ts_usec, incl_len, orig_len))
        fh.write(frame)
        count += 1

    return count
