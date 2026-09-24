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

```
$ btsnoop_parser capture.log --ai

Loading Qwen/Qwen2.5-1.5B-Instruct (this may take a moment)...
The Bluetooth session lasted for approximately 3 minutes and 41 seconds. It involved two connections:
1. **Initial Connection**: On June 1, 2024, at 9:12 AM, a connection was established between device AA:BB:CC:DD:EE:FF (unknown) and another unknown device.
2. **Disconnection**: At 9:14 PM, the connection was abruptly terminated by the remote device due to a remote user terminating the connection.
**Detected Issue**: There was a disconnect initiated by the remote device, which resulted from a page timeout during the connection attempt.
**Root Cause**: The most likely root cause was that the connection attempt timed out before completing successfully. This could have been due to various factors including network latency, insufficient buffer space on either end, or other communication issues preventing the connection from being fully established within the expected time frame.
```

That's unedited output from the default 1.5B model for the capture above. It finds the
real problem (the Page Timeout), but small local models also muddle details: the clean
disconnect is blamed on the timeout, "9:14 PM" should be AM, and the speculative causes
at the end are generic. Treat `--ai` as a plain-English starting point and check it
against `--stats`.

## Features

- Parses BTSnoop HCI logs into friendly Python dicts — zero dependencies.
- Wireshark-style CLI table with direction colouring.
- **`--filter`** — filter by packet type and direction before processing.
- **`--pcap`** — export to PCAP (link type 201) for Wireshark / tshark.
- **`--stats`** — connection history, device list, and issue detection.
- **`--ai`** — ask a local LLM to diagnose capture issues in plain English (fully offline, optional extra).
- **`--link-keys`** — extract Classic BT link keys seen in HCI traffic (for use with your own authorized captures).
- Decodes common HCI command/event payloads.
- Corrects the Android ±378-day timestamp bug automatically.

## Installation

```bash
pip install btsnoop-parser
```

The `--ai` flag is an optional, heavier extra (pulls in `torch`/`transformers` —
several GB) — the rest of the library stays dependency-free:

```bash
pip install "btsnoop-parser[ai]"
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

# Ask a local LLM to diagnose issues — requires `pip install "btsnoop-parser[ai]"`
# Only the decoded/summarized capture is sent to the model (not raw packets),
# and everything runs locally: no cloud calls, only a one-time model download.
btsnoop_parser capture.log --ai
btsnoop_parser capture.log --ai --question "Why did the connection drop at 09:15?"

# Specialize --ai with a LoRA adapter you've fine-tuned yourself (see training/)
btsnoop_parser capture.log --ai --adapter-path training/checkpoints/hci-rootcause-lora

# Extract Classic BT link keys seen in the capture (your own authorized captures only)
btsnoop_parser capture.log --link-keys

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

## Local LLM analysis (`--ai`)

`--ai` prompts a local Hugging Face model (default: `Qwen/Qwen2.5-1.5B-Instruct`)
with a plain-text summary of the capture's connection history and detected
issues, and asks it to explain what went wrong. It works out of the box with
just the base model, or you can specialize it further by fine-tuning a LoRA
adapter on your own — see [`training/README.md`](training/README.md) for a
full walkthrough (dataset generation, LoRA training with `peft`, evaluation).

## Link key extraction (`--link-keys`)

Classic Bluetooth (BR/EDR) link keys pass over HCI in the clear — the
controller hands a freshly-paired key to the host via a *Link Key
Notification* event, and the host replays a cached key back via a *Link Key
Request Reply* command on every reconnection. `--link-keys` scans a capture
for both and prints the device address, key, and (when known) how the key
was derived — useful for e.g. loading a key into Wireshark to decrypt your
own encrypted captures.

A link key is credential material for that device — only run this against
captures you're authorized to analyze. BLE isn't covered (it negotiates an
LTK through a different mechanism).

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
