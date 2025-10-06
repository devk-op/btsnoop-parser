# btsnoop-parser

[![CI](https://github.com/krathi/btsnoop-parser/actions/workflows/ci.yml/badge.svg)](https://github.com/krathi/btsnoop-parser/actions/workflows/ci.yml)

`btsnoop-parser` is a small library and CLI for exploring Bluetooth `btsnoop_hci.log`
captures produced on Android devices. It focuses on being a lightweight alternative
to Wireshark when you only need a quick glance at packet metadata or want to script
over captures in Python.

## Features

- Parses BTSnoop HCI logs into friendly Python dictionaries.
- Provides a Wireshark-style CLI table with optional JSON export.
- Decodes common HCI command/event payloads.
- Ships with pure-Python code and zero runtime dependencies.

## Installation

```bash
pip install btsnoop-parser
```

To work with a local checkout during development:

```bash
pip install -e .
```

## Command Line Usage

After installation the `btsnoop_parser` entry point becomes available:

```bash
# Show the first 10 packets in a capture
btsnoop_parser path/to/btsnoop_hci.log --limit 10

# Emit JSON for scripting
btsnoop_parser path/to/btsnoop_hci.log --json --limit 5

# Print decoded HCI command/event metadata
btsnoop_parser path/to/btsnoop_hci.log --decode
```

Run `btsnoop_parser --help` for the complete option list.

## Python API

```python
from btsnoop_parser import decode_hci_packet, parse_btsnoop_file

records = parse_btsnoop_file("btsnoop_hci.log")

for record in records[:5]:
    print(record["timestamp"], record["packet_type_name"], record["direction"])
    decoded = decode_hci_packet(record["packet_type"], record["payload"])
    if decoded["type"] == "COMMAND":
        print("  ↳", decoded["name"], hex(decoded["opcode"]))
```

If you only need to stream over a file without holding everything in memory,
`btsnoop_parser.iter_records(Path("capture.btsnoop"))` yields the same dictionaries
as `parse_btsnoop_file` but lazily.

## Development

```bash
# Run the lightweight unittest-based test suite
python3 -m unittest discover -s tests

# Optional linting (install optional dev dependencies first)
ruff check
```

## License

MIT © Kranthi

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on setting up your
environment, running tests, and submitting pull requests.
