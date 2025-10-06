import argparse
import json
from typing import Any

from .core import parse_btsnoop_file, print_table, slice_records
from .hci_decoder import decode_hci_packet


def _serialise_record(record: dict[str, Any]) -> dict[str, Any]:
    """Return a JSON-friendly copy of a parsed record."""
    serialised = dict(record)
    ts = serialised.get("timestamp")
    if hasattr(ts, "isoformat"):
        serialised["timestamp"] = ts.isoformat()
    payload = serialised.get("payload")
    if isinstance(payload, (bytes, bytearray)):
        serialised["payload"] = payload.hex()
    serialised.pop("packet_data", None)
    serialised.pop("packet_type_str", None)
    serialised.pop("packet_type_id", None)
    return serialised


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse Android btsnoop_hci.log captures.")
    parser.add_argument("file", help="Path to a btsnoop_hci.log file")
    parser.add_argument("--limit", type=int, help="Limit the number of records shown")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of a text table (payload is hex encoded)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output (implies --json)",
    )
    parser.add_argument(
        "--decode",
        action="store_true",
        help="Print decoded packet metadata beneath the table",
    )
    args = parser.parse_args()

    records = parse_btsnoop_file(args.file)
    limited = slice_records(records, args.limit)

    if args.json or args.pretty:
        data = [_serialise_record(record) for record in limited]
        indent = 2 if args.pretty else None
        print(json.dumps(data, indent=indent))
        return

    print_table(limited, limit=args.limit)

    if args.decode:
        for record in limited:
            decoded = decode_hci_packet(record["packet_type"], record["payload"])
            print(f"{record['index']:>4} {decoded}")
