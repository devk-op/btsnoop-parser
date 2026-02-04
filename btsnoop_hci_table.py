#!/usr/bin/env python3
# btsnoop_hci_table.py
import argparse
import datetime
import struct
import json
import csv
from typing import Iterable, Any, Optional

BTSNOOP_HEADER = b'btsnoop\0'
# μs between 0001-01-01 and 1970-01-01 (btsnoop epoch → Unix epoch)
BTSNOOP_EPOCH_DELTA_US = 62135596800000000

# H4 packet types
HCI_PACKET_TYPES = {
    0x01: "Command",
    0x02: "ACL Data",
    0x03: "SCO Data",
    0x04: "Event",
    0x05: "ISO Data",  # BLE isochronous (LE Audio)
}

# map for CLI filters
PROTO_NAME_TO_TYPE = {
    "command": 0x01, "acl": 0x02, "acl data": 0x02, "sco": 0x03,
    "event": 0x04, "iso": 0x05, "iso data": 0x05,
}

# Common event names
EVENT_NAMES = {
    0x01: "Inquiry Complete",
    0x02: "Inquiry Result",
    0x03: "Connection Complete",
    0x05: "Disconnection Complete",
    0x07: "Remote Name Request Complete",
    0x0E: "Command Complete",
    0x0F: "Command Status",
    0x3E: "LE Meta Event",
}

# LE Meta subevents (subset)
LE_SUBEVENT_NAMES = {
    0x01: "LE Connection Complete",
    0x02: "LE Advertising Report",
    0x03: "LE Connection Update Complete",
    0x0A: "LE PHY Update Complete",
    0x0E: "LE Extended Advertising Report",
    0x0F: "LE Periodic Adv Sync Established",
    0x12: "LE Channel Selection Algorithm",
    0x19: "LE CIS Established",
    0x1A: "LE CIS Request",
    0x1D: "LE BIG Info Adv Report",
}

# A tiny set of common HCI command opcodes (Opcode = OGF<<10 | OCF)
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
    0x201C: "LE Read Supported States",
    0x2067: "LE Read Local Supported Features (V2)",
}

# ───────────────────────── helpers ─────────────────────────

def ts_from_btsnoop(timestamp_us: int) -> datetime.datetime:
    unix_us = timestamp_us - BTSNOOP_EPOCH_DELTA_US
    return datetime.datetime.fromtimestamp(unix_us / 1_000_000, datetime.timezone.utc).replace(tzinfo=None)

def proto_name_from_type(ptype: int) -> str:
    return HCI_PACKET_TYPES.get(ptype, f"Unknown (0x{ptype:02X})")

def parse_handle_12bit(h2: int) -> int:
    """Extract 12-bit connection handle from the 16-bit HCI handle+flags word."""
    return h2 & 0x0FFF

def bdaddr_to_str_le(b: bytes) -> str:
    """HCI events carry BD_ADDR little-endian; present as big-endian colon string."""
    if len(b) != 6:
        return "??:??:??:??:??:??"
    return ":".join(f"{x:02X}" for x in b[::-1])

def parse_le_advertising_data(ad: bytes) -> dict[int, bytes]:
    """Parse LE Advertising data (AD structures). Returns dict type->value."""
    out: dict[int, bytes] = {}
    i = 0
    while i < len(ad):
        length = ad[i]
        i += 1
        if length == 0 or i + length > len(ad) + 1:
            break
        ad_type = ad[i]
        value = ad[i+1:i+length]
        out[ad_type] = value
        i += length
    return out

def decode_info(ptype: int, payload: bytes, direction: str) -> str:
    """Produce a short Wireshark-like Info string."""
    sent_recv = "Sent" if direction == "TX" else "Rcvd"

    if ptype == 0x01:  # Command
        if len(payload) >= 3:
            opcode = payload[0] | (payload[1] << 8)
            name = CMD_NAMES.get(opcode, f"Opcode 0x{opcode:04X}")
            return f"{sent_recv} Command {name}"
        return f"{sent_recv} Command (short)"

    if ptype == 0x04:  # Event
        if len(payload) >= 2:
            evt = payload[0]
            name = EVENT_NAMES.get(evt, f"Event 0x{evt:02X}")
            if evt == 0x3E and len(payload) >= 3:
                sub = payload[2]
                subname = LE_SUBEVENT_NAMES.get(sub, f"Subevent 0x{sub:02X}")
                return f"{sent_recv} LE Meta: {subname}"
            return f"{sent_recv} {name}"
        return f"{sent_recv} Event (short)"

    if ptype == 0x02:
        return f"{sent_recv} ACL Data (len {len(payload)})"
    if ptype == 0x03:
        return f"{sent_recv} SCO Data (len {len(payload)})"
    if ptype == 0x05:
        return f"{sent_recv} ISO Data (len {len(payload)})"
    return f"{sent_recv} {proto_name_from_type(ptype)}"

# ───────────────────────── parsing ─────────────────────────

def parse_records(filename: str) -> Iterable[dict[str, Any]]:
    """
    Generator yielding parsed records from a btsnoop HCI file.
    Adds 'handle' and 'peer_addr' where possible.
    Learns address->name and handle->address mappings.
    Also extracts 'opcode', 'event', 'le_subevent' for filtering/export.
    """
    handle_to_addr: dict[int, str] = {}   # 12-bit conn handle -> peer bdaddr
    addr_to_name: dict[str, str] = {}     # peer bdaddr -> friendly name

    with open(filename, "rb") as f:
        if f.read(8) != BTSNOOP_HEADER:
            raise ValueError("Invalid BTSnoop file header")

        version, datalink = struct.unpack(">II", f.read(8))
        if datalink != 1001:
            print(f"[WARN] Datalink={datalink} (expected 1001 for HCI H4)")

        rec_no = 0
        while True:
            hdr = f.read(24)
            if len(hdr) < 24:
                return
            orig_len, incl_len, flags, drops, ts_us = struct.unpack(">IIIIQ", hdr)
            pkt = f.read(incl_len)
            if len(pkt) < incl_len:
                print(f"[WARN] Incomplete packet read (wanted {incl_len}, got {len(pkt)}); stopping.")
                return
            if incl_len == 0:
                continue

            # Direction: bit 0 == received by host (per btsnoop spec)
            is_rx = (flags & 0x1) != 0
            direction = "RX" if is_rx else "TX"

            try:
                ts = ts_from_btsnoop(ts_us)
            except Exception as e:
                print(f"[ERROR] Bad timestamp {ts_us}: {e}")
                continue

            ptype = pkt[0]
            payload = pkt[1:] if len(pkt) > 1 else b""

            handle: Optional[int] = None
            peer_addr: Optional[str] = None  # set for this record if we can
            opcode: Optional[int] = None
            event: Optional[int] = None
            le_subevent: Optional[int] = None

            # Commands: extract opcode
            if ptype == 0x01 and len(payload) >= 3:
                opcode = payload[0] | (payload[1] << 8)

            # ACL/ISO Data: extract handle & map to peer
            if ptype == 0x02 and len(payload) >= 4:
                hword = payload[0] | (payload[1] << 8)
                handle = parse_handle_12bit(hword)
                peer_addr = handle_to_addr.get(handle)

            elif ptype == 0x05 and len(payload) >= 4:
                hword = payload[0] | (payload[1] << 8)
                handle = parse_handle_12bit(hword)
                peer_addr = handle_to_addr.get(handle)

            # Events: extract codes & learn mappings
            elif ptype == 0x04 and len(payload) >= 2:
                event = payload[0]

                # Classic Connection Complete (0x03)
                if event == 0x03 and len(payload) >= 13:
                    status = payload[1]
                    h = payload[2] | (payload[3] << 8)
                    handle = parse_handle_12bit(h)
                    bd = bdaddr_to_str_le(payload[4:10])
                    if status == 0x00:
                        handle_to_addr[handle] = bd
                        peer_addr = bd  # show on this record

                # Remote Name Request Complete (0x07)
                elif event == 0x07 and len(payload) >= 8:
                    status = payload[1]
                    bd = bdaddr_to_str_le(payload[2:8])
                    name_bytes = payload[8:]
                    name = name_bytes.split(b'\x00', 1)[0].decode(errors="ignore")
                    if status == 0x00 and name:
                        addr_to_name[bd] = name
                    peer_addr = bd

                # LE Meta Event (0x3E)
                elif event == 0x3E and len(payload) >= 3:
                    le_subevent = payload[2]
                    subpayload = payload[3:]

                    # LE Connection Complete (0x01)
                    if le_subevent == 0x01 and len(subpayload) >= 19:
                        status = subpayload[0]
                        h = subpayload[1] | (subpayload[2] << 8)
                        handle = parse_handle_12bit(h)
                        bd = bdaddr_to_str_le(subpayload[4:10])
                        if status == 0x00:
                            handle_to_addr[handle] = bd
                            peer_addr = bd

                    # LE Advertising Report (0x02)
                    elif le_subevent == 0x02 and len(subpayload) >= 1:
                        i = 0
                        num = subpayload[i]; i += 1
                        first_bd: Optional[str] = None
                        for _ in range(num):
                            if i + 9 > len(subpayload):
                                break
                            evt_type = subpayload[i]; i += 1
                            addr_type = subpayload[i]; i += 1
                            bd = bdaddr_to_str_le(subpayload[i:i+6]); i += 6
                            if first_bd is None:
                                first_bd = bd
                            if i >= len(subpayload): break
                            adlen = subpayload[i]; i += 1
                            ad = subpayload[i:i+adlen]; i += adlen
                            if i >= len(subpayload): break
                            rssi = subpayload[i]; i += 1
                            ads = parse_le_advertising_data(ad)
                            name = None
                            if 0x09 in ads:
                                name = ads[0x09].decode(errors="ignore")
                            elif 0x08 in ads:
                                name = ads[0x08].decode(errors="ignore")
                            if name:
                                addr_to_name[bd] = name
                        if first_bd:
                            peer_addr = first_bd

            rec_no += 1
            yield {
                "no": rec_no,
                "timestamp": ts,
                "flags": flags,
                "drops": drops,
                "direction": direction,  # RX=from controller to host; TX=host to controller
                "ptype": ptype,
                "ptype_name": proto_name_from_type(ptype),
                "payload": payload,
                "handle": handle,
                "peer_addr": peer_addr,
                "opcode": opcode,
                "event": event,
                "le_subevent": le_subevent,
                # expose mappings (by reference) so printer can see latest names/handles
                "addr_to_name": addr_to_name,
                "handle_to_addr": handle_to_addr,
            }

# ───────────────────────── filters & printing/export ─────────────────────────

def within_time(ts: datetime.datetime, start: Optional[datetime.datetime], end: Optional[datetime.datetime]) -> bool:
    if start and ts < start:
        return False
    if end and ts > end:
        return False
    return True

def build_proto_filter(proto_args: Optional[Iterable[str]]) -> Optional[set[int]]:
    if not proto_args:
        return None
    out: set[int] = set()
    for p in proto_args:
        key = p.strip().lower()
        if key in PROTO_NAME_TO_TYPE:
            out.add(PROTO_NAME_TO_TYPE[key])
        else:
            try:
                out.add(int(key, 0))  # allow 0x04 style
            except ValueError:
                raise SystemExit(f"Unknown protocol '{p}'. Use: command,event,acl,sco,iso")
    return out

def parse_time_arg(s: Optional[str]) -> Optional[datetime.datetime]:
    if not s:
        return None
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1]
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            pass
    raise SystemExit(f"Could not parse time '{s}'. Try e.g. 2025-10-05T21:25:30.000Z")

def label_pair(rec: dict[str, Any], mode: str) -> tuple[str, str]:
    """
    Return (source, destination) strings based on label mode:
      - logical  -> 'host' / 'controller'
      - address  -> 'host' / 'AA:BB:CC:DD:EE:FF'
      - friendly -> 'host' / 'Nice Headphones (AA:BB:...)' or bdaddr if no name
    Fallback: if we don't know a peer address, ALWAYS fall back to logical labels.
    """
    def logical():
        src = "host" if rec["direction"] == "TX" else "controller"
        dst = "controller" if rec["direction"] == "TX" else "host"
        return src, dst

    if mode == "logical":
        return logical()

    addr_to_name = rec["addr_to_name"]
    peer = rec.get("peer_addr")

    # Try to infer peer from handle if not present
    if not peer and rec.get("handle") is not None:
        peer = rec["handle_to_addr"].get(rec["handle"])

    if not peer:
        return logical()

    # For address/friendly, local side is always "host"
    src_is_host = rec["direction"] == "TX"
    local = "host"

    if mode == "address":
        remote = peer
        return (local, remote) if src_is_host else (remote, local)

    # friendly
    name = addr_to_name.get(peer)
    remote = f"{name} ({peer})" if name else peer
    return (local, remote) if src_is_host else (remote, local)

def record_matches_code_filters(rec: dict[str, Any],
                                opcode_filter: Optional[set[int]],
                                event_filter: Optional[set[int]],
                                le_sub_filter: Optional[set[int]]) -> bool:
    # If any filter list is provided, record must match that list
    if opcode_filter is not None:
        if rec["ptype"] != 0x01:
            return False
        if rec.get("opcode") not in opcode_filter:
            return False
    if event_filter is not None:
        if rec["ptype"] != 0x04:
            return False
        if rec.get("event") not in event_filter:
            return False
    if le_sub_filter is not None:
        # must be LE Meta Event with desired subevent
        if not (rec["ptype"] == 0x04 and rec.get("event") == 0x3E):
            return False
        if rec.get("le_subevent") not in le_sub_filter:
            return False
    return True

def parse_int_set(values: Optional[list[str]], name: str) -> Optional[set[int]]:
    if not values:
        return None
    out: set[int] = set()
    for v in values:
        try:
            out.add(int(v, 0))  # supports '15', '0x0F'
        except ValueError:
            raise SystemExit(f"Invalid {name} value '{v}'. Use decimal or hex like 0x0F.")
    return out

def make_export_row(rec: dict[str, Any], delta: float, src: str, dst: str, info: str) -> dict[str, Any]:
    # Friendly fields for CSV/JSON
    return {
        "no": rec["no"],
        "timestamp": rec["timestamp"].isoformat() + "Z",
        "delta_s": round(delta, 6),
        "direction": rec["direction"],
        "source": src,
        "destination": dst,
        "protocol": rec["ptype_name"],
        "info": info,
        "opcode": f"0x{rec['opcode']:04X}" if rec.get("opcode") is not None else None,
        "event": f"0x{rec['event']:02X}" if rec.get("event") is not None else None,
        "le_subevent": f"0x{rec['le_subevent']:02X}" if rec.get("le_subevent") is not None else None,
        "handle": rec.get("handle"),
        "peer_addr": rec.get("peer_addr"),
    }

def stream_and_collect(records: Iterable[Dict[str, Any]],
                       start: Optional[datetime.datetime],
                       end: Optional[datetime.datetime],
                       proto_filter: Optional[set[int]],
                       direction: Optional[str],
                       opcode_filter: Optional[set[int]],
                       event_filter: Optional[set[int]],
                       le_sub_filter: Optional[set[int]],
                       limit: Optional[int],
                       label_mode: str,
                       print_rows: bool):
    if direction:
        direction = direction.upper()
        if direction not in {"TX", "RX"}:
            raise SystemExit("--direction must be TX or RX")

    collected = []
    printed = 0
    t0: Optional[datetime.datetime] = None

    if print_rows:
        header = f"{'No.':<6} {'Time':<10} {'Source':<24} {'Destination':<24} {'Protocol':<10} Info"
        print(header)

    for r in records:
        if not within_time(r["timestamp"], start, end):
            continue
        if proto_filter and r["ptype"] not in proto_filter:
            continue
        if direction and r["direction"] != direction:
            continue
        if not record_matches_code_filters(r, opcode_filter, event_filter, le_sub_filter):
            continue

        if t0 is None:
            t0 = r["timestamp"]
        delta = (r["timestamp"] - t0).total_seconds()

        src, dst = label_pair(r, label_mode)
        proto = ("HCI_" + r["ptype_name"].split()[0]).ljust(10)
        info = decode_info(r["ptype"], r["payload"], r["direction"])

        if print_rows:
            print(f"{r['no']:<6} {delta:>9.6f} {src:<24} {dst:<24} {proto} {info}")

        collected.append(make_export_row(r, delta, src, dst, info))
        printed += 1
        if limit and printed >= limit:
            break

    if print_rows and printed == 0:
        print("(no matching records)")

    return collected

def export_csv(path: str, rows: list[dict[str, Any]]) -> None:
    if not rows:
        # Create an empty CSV with header
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["no","timestamp","delta_s","direction","source","destination",
                                                   "protocol","info","opcode","event","le_subevent",
                                                   "handle","peer_addr"])
            writer.writeheader()
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

def export_json(path: str, rows: list[dict[str, Any]]) -> None:
    with open(path, "w") as f:
        json.dump(rows, f, indent=2)

# ───────────────────────── CLI ─────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Parse btsnoop HCI logs and print/export a Wireshark-like table with filters and labeling."
    )
    ap.add_argument("file", help="Path to btsnoop_hci.log")
    ap.add_argument("--proto", "-p", nargs="*", default=None,
                    help="Filter by protocol(s): command event acl sco iso (or hex like 0x04)")
    ap.add_argument("--start", help="Start time UTC, e.g., 2025-10-05T21:25:30.000Z")
    ap.add_argument("--end", help="End time UTC, e.g., 2025-10-05T21:26:00.000Z")
    ap.add_argument("--direction", "-d", choices=["TX", "RX"],
                    help="Filter by direction (TX=host→controller, RX=controller→host)")
    ap.add_argument("--opcode", nargs="*", help="Filter by HCI opcode(s) (decimal or hex, e.g., 0x0C03)")
    ap.add_argument("--event", nargs="*", help="Filter by HCI Event code(s) (e.g., 0x0E 0x0F)")
    ap.add_argument("--le-subevent", nargs="*", help="Filter by LE Meta subevent code(s) (e.g., 0x01 0x02)")
    ap.add_argument("--limit", "-n", type=int, default=None, help="Stop after printing N rows")
    ap.add_argument("--label", choices=["logical", "address", "friendly"], default="logical",
                    help="How to label Source/Destination columns")
    ap.add_argument("--csv", help="Write matching rows to CSV file")
    ap.add_argument("--json", help="Write matching rows to JSON file")
    args = ap.parse_args()

    start = parse_time_arg(args.start)
    end = parse_time_arg(args.end)
    proto_filter = build_proto_filter(args.proto)
    opcode_filter = parse_int_set(args.opcode, "opcode")
    event_filter = parse_int_set(args.event, "event")
    le_sub_filter = parse_int_set(args.le_subevent, "le_subevent")

    recs = parse_records(args.file)
    rows = stream_and_collect(
        recs, start, end, proto_filter, args.direction,
        opcode_filter, event_filter, le_sub_filter,
        args.limit, args.label,
        print_rows=True  # print table to stdout
    )

    if args.csv:
        export_csv(args.csv, rows)
        print(f"[INFO] CSV written: {args.csv}")
    if args.json:
        export_json(args.json, rows)
        print(f"[INFO] JSON written: {args.json}")

if __name__ == "__main__":
    main()
