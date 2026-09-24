import argparse
import json
import sys
from typing import Any

from .core import filter_records, parse_btsnoop_file, print_table, slice_records
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


def _build_capture_stats(records):
    from .analysis import CaptureStats
    stats = CaptureStats()
    for record in records:
        stats.analyze_record(record)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse Android btsnoop_hci.log captures.")
    parser.add_argument("file", help="Path to a btsnoop_hci.log file")
    parser.add_argument("--limit", type=int, help="Limit the number of records shown")
    parser.add_argument(
        "--filter",
        dest="filters",
        metavar="EXPR",
        action="append",
        default=[],
        help=(
            "Filter expression as key:value.  May be repeated. "
            "Supported keys: type (command/acl/event/sco/iso or 0xNN), dir (tx/rx). "
            "Example: --filter type:event --filter dir:rx"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of a text table (payload is hex encoded)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the JSON output",
    )
    parser.add_argument(
        "--decode",
        action="store_true",
        help="Print decoded packet metadata beneath the table",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Analyze capture and show high-level statistics and issues",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Analyze capture issues with a local LLM (requires the 'ai' extra)",
    )
    parser.add_argument(
        "--question",
        metavar="TEXT",
        default=None,
        help="Question to ask the LLM about the capture (used with --ai)",
    )
    parser.add_argument(
        "--base-model",
        metavar="NAME",
        default=None,
        help="Hugging Face model id to use for --ai (default: Qwen/Qwen2.5-1.5B-Instruct)",
    )
    parser.add_argument(
        "--adapter-path",
        metavar="DIR",
        default=None,
        help="Path to a LoRA adapter directory to specialize the --ai model",
    )
    parser.add_argument(
        "--link-keys",
        action="store_true",
        help="Extract Classic BT link keys seen in HCI traffic (sensitive — see docs)",
    )
    parser.add_argument(
        "--pcap",
        metavar="OUTPUT.pcap",
        help="Write records to a PCAP file (Wireshark-compatible, link type 201)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    args = parser.parse_args()

    try:
        records = parse_btsnoop_file(args.file)
    except FileNotFoundError:
        parser.error(f"File not found: {args.file}")
    except PermissionError:
        parser.error(f"Permission denied: {args.file}")

    # Apply filters before any other processing
    if args.filters:
        try:
            records = filter_records(records, args.filters)
        except ValueError as exc:
            parser.error(str(exc))

    # --pcap: write and exit (can combine with --filter)
    if args.pcap:
        from .pcap import write_pcap
        n = write_pcap(records, args.pcap)
        print(f"Wrote {n} packets to {args.pcap}")
        return

    if args.stats:
        stats = _build_capture_stats(records)
        stats.print_summary(color=not args.no_color)
        return

    if args.ai:
        stats = _build_capture_stats(records)
        from .llm import (
            DEFAULT_BASE_MODEL,
            DEFAULT_QUESTION,
            ModelUnavailableError,
            ask,
        )
        base_model = args.base_model or DEFAULT_BASE_MODEL
        print(f"Loading {base_model} (this may take a moment)...", file=sys.stderr)
        try:
            answer = ask(
                stats,
                question=args.question or DEFAULT_QUESTION,
                base_model=base_model,
                adapter_path=args.adapter_path,
            )
        except ModelUnavailableError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        print(answer)
        return

    if args.link_keys:
        from .security import extract_link_keys
        print(
            "Warning: link keys are credential material — only use with captures "
            "you're authorized to analyze.",
            file=sys.stderr,
        )
        keys = extract_link_keys(records)
        if not keys:
            print("No link keys found.")
            return
        for k in keys:
            key_type = f" [{k['key_type_name']}]" if k["key_type_name"] else ""
            print(f"{k['timestamp']}  {k['addr']}  {k['link_key']}  ({k['source']}){key_type}")
        return

    limited = slice_records(records, args.limit)

    if args.json or args.pretty:
        data = [_serialise_record(record) for record in limited]
        indent = 2 if args.pretty else None
        print(json.dumps(data, indent=indent))
        return

    print_table(limited, limit=args.limit, color=not args.no_color)

    if args.decode:
        for record in limited:
            decoded = decode_hci_packet(record["packet_type"], record["payload"])
            print(f"{record['index']:>4} {decoded}")
