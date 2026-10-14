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

Loading Qwen/Qwen2.5-0.5B-Instruct (this may take a moment)...
Yes, something failed.
(1) What failed: the LE connection attempt to 11:22:33:44:55:66 (handle 0x002).
(2) When: at 09:15:44, after an earlier connection to AA:BB:CC:DD:EE:FF had ended normally.
(3) Likely root cause: Page Timeout — the other device never answered the connection request — it was most likely out of range, switched off, or not accepting connections.
```

That's unedited output for the capture above, from a 0.5B model fine-tuned for this job.
It runs on a laptop CPU in a few seconds. It is still a small model working from a summary,
so treat `--ai` as a plain-English starting point and check it against `--stats`.

## Features

- Parses BTSnoop HCI logs into friendly Python dicts — zero dependencies.
- Wireshark-style packet list: each answer names its command and result, failures in red, and data packets say what they carry (e.g. "AVRCP: Next pressed", "HFP: AT+CLCC").
- **`--filter`** — filter by packet type and direction before processing.
- **`--pcap`** — export to PCAP (link type 201) for Wireshark / tshark.
- **`--stats`** — connection history, device list, issue detection, and a per-device profile summary: music played and for how long, codec, buttons pressed, songs, volume changes (including a device overriding the phone), calls and cellular service, LE Audio streams, Android Auto start-up.
- **`--protocols`** — timeline of what the devices said above HCI: L2CAP channels, A2DP streaming (codec, start, pause, stalls), AVRCP buttons, volume and track changes, wireless Android Auto start-up, GATT (services, device name, battery, heart rate, LE Audio volume and media state), RFCOMM serial ports, HFP commands in plain English, voice links. Works on filtered Android logs too.
- **`--ai`** — a small local model, fine-tuned on HCI sessions, says in plain English whether anything failed and why (runs offline, optional extra).
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

# Decode the protocols above HCI (L2CAP channels, A2DP streaming, RFCOMM ports, HFP commands)
btsnoop_parser capture.log --protocols

# Ask a local LLM to diagnose issues — requires `pip install "btsnoop-parser[ai]"`
# Only the decoded/summarized capture is sent to the model (not raw packets),
# and everything runs locally: no cloud calls, only a one-time model download.
btsnoop_parser capture.log --ai
btsnoop_parser capture.log --ai --question "Why did the connection drop at 09:15?"

# Use your own model or LoRA adapter instead of the default (see training/)
btsnoop_parser capture.log --ai --base-model Qwen/Qwen2.5-1.5B-Instruct
btsnoop_parser capture.log --ai --adapter-path training/checkpoints/Qwen2.5-0.5B-Instruct-lora

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

`--ai` gives a local model a plain-text summary of the capture (connection history,
detected issues, routine failures, and a short note on each status code involved) and
asks whether anything actually failed, and if so what, when and why. The model never
sees raw packets, and nothing leaves your machine.

The default is [`Qwen/Qwen2.5-0.5B-Instruct`](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct)
with the [`kdonut/btsnoop-hci-qwen2.5-0.5b-lora`](https://huggingface.co/kdonut/btsnoop-hci-qwen2.5-0.5b-lora)
adapter, trained on synthetic HCI sessions with the scripts in [`training/`](training/README.md).
On 122 held-out sessions it gets 118 right; the same model without the adapter gets 1,
and the three-times-larger `Qwen2.5-1.5B-Instruct` gets 27. Those sessions are synthetic,
so expect lower accuracy on real captures.

- `--base-model` takes a Hugging Face model id or a local model folder; `BTSNOOP_AI_MODEL`
  changes the default. The default adapter is only applied to the default model.
- `--adapter-path` takes a local adapter folder or a Hugging Face repo id.
- Models are downloaded once (about 1 GB) and cached. `HF_HUB_OFFLINE=1` skips the
  network check on later runs.

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
