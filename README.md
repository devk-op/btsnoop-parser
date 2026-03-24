# btsnoop-parser

[![CI](https://github.com/devk-op/btsnoop-parser/actions/workflows/ci.yml/badge.svg)](https://github.com/devk-op/btsnoop-parser/actions?query=workflow%3A"CI%2FCD+Pipeline")
[![PyPI](https://img.shields.io/pypi/v/btsnoop-parser)](https://pypi.org/project/btsnoop-parser/)
[![Docs](https://readthedocs.org/projects/btsnoop-parser/badge/?version=latest)](https://btsnoop-parser.readthedocs.io)
[![Python](https://img.shields.io/pypi/pyversions/btsnoop-parser)](https://pypi.org/project/btsnoop-parser/)

`btsnoop-parser` is a small library and CLI for exploring Bluetooth `btsnoop_hci.log`
captures produced on Android devices.  It is a lightweight alternative to Wireshark
when you need a quick look at packet metadata or want to script over captures in Python.

```
$ btsnoop_parser capture.log --stats

 Capture Statistics ───
  Duration:      4m 32.871s
  Total Packets: 1,842
  Data Volume:   142.67 KB

Packet Types:
  ACL Data            1,204
  Event                 512
  Command               126

Detected Devices:
  AA:BB:CC:DD:EE:FF  Unknown
  11:22:33:44:55:66  Unknown

Connection History:
  2024-06-01 09:12:03.441  Connected (LE)        0x001 -> Device: AA:BB:CC:DD:EE:FF
  2024-06-01 09:14:21.009  Disconnected          0x001 -> Reason: Remote User Terminated Connection (Remote Device)
  2024-06-01 09:15:44.230  Connect Failed (LE)   0x002 -> Device: 11:22:33:44:55:66 — Page Timeout

Potential Issues (1):
  [WARN] 2024-06-01 09:15:44.230 - LE Connection Failed: Failed to connect to 11:22:33:44:55:66: Page Timeout
```

## Features

- Parses BTSnoop HCI logs into friendly Python dicts — zero dependencies.
- Wireshark-style CLI table with direction colouring.
- **`--filter`** — filter by packet type and direction before processing.
- **`--pcap`** — export to PCAP (link type 201) for Wireshark / tshark.
- **`--stats`** — connection history, device list, and issue detection.
- Decodes common HCI command/event payloads.
- Corrects the Android ±378-day timestamp bug automatically.

## Installation

```bash
pip install btsnoop-parser
```

## CLI Usage

```bash
# Wireshark-style table, first 20 packets
btsnoop_parser capture.log --limit 20

# Show only HCI events
btsnoop_parser capture.log --filter type:event

# Show only TX commands
btsnoop_parser capture.log --filter type:command --filter dir:tx

# Export filtered records to a PCAP file — open directly in Wireshark
btsnoop_parser capture.log --filter type:event --pcap events.pcap

# Convert the whole capture to PCAP
btsnoop_parser capture.log --pcap full.pcap

# Capture statistics and issue detection
btsnoop_parser capture.log --stats

# JSON output for scripting
btsnoop_parser capture.log --json | jq '[.[] | select(.direction=="RX")]'
```

Run `btsnoop_parser --help` for the full option list.

### `--filter` expressions

| Key    | Values                                          | Example                  |
|--------|-------------------------------------------------|--------------------------|
| `type` | `command`, `acl`, `event`, `sco`, `iso`, `0xNN` | `--filter type:event`    |
| `dir`  | `tx`, `rx`                                      | `--filter dir:tx`        |

Comma-separate types for OR logic: `--filter type:command,event`
Repeat the flag to AND filters: `--filter type:event --filter dir:rx`

## Python API

```python
from btsnoop_parser import (
    parse_btsnoop_file,
    iter_records,
    filter_records,
    write_pcap,
    decode_hci_packet,
)

# Load all records
records = parse_btsnoop_file("btsnoop_hci.log")

# Filter to HCI events only
events = filter_records(records, ["type:event"])

# Export to Wireshark-compatible PCAP
write_pcap(records, "capture.pcap")

# Stream large files without loading everything into memory
for record in iter_records("btsnoop_hci.log"):
    decoded = decode_hci_packet(record["packet_type"], record["payload"])
    if decoded.get("type") == "COMMAND":
        print(record["timestamp"], decoded["name"])
```

Full API reference: **[btsnoop-parser.readthedocs.io](https://btsnoop-parser.readthedocs.io)**

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check
```

## License

MIT © Kranthi

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on setting up your
environment, running tests, and submitting pull requests.
