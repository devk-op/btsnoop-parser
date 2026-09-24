#!/usr/bin/env python3
"""Phase 2: synthesize a training set for HCI root-cause analysis.

There's no existing "Bluetooth HCI capture -> root cause explanation"
dataset, so this script builds one deterministically: it samples
combinations of real HCI error codes / opcodes (from
btsnoop_parser.constants) against the issue/event archetypes
btsnoop_parser.analysis.CaptureStats already produces, renders each through
the *same* btsnoop_parser.llm.build_context() used at inference time (so
training and inference text distributions match), and pairs it with a
deterministic template answer (training/templates/answer_templates.py).

One entire device (the 4th of four) is held out from train/val entirely and
only used to build eval_holdout.jsonl, so evaluation measures generalization
to unseen device/scenario combinations, not just memorized records.

Usage:
    python3 training/generate_dataset.py
"""
from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from btsnoop_parser.analysis import CaptureStats
from btsnoop_parser.constants import HCI_ERROR_CODES, HCI_OPCODE_NAMES
from btsnoop_parser.llm import DEFAULT_QUESTION, build_context
from training.templates import answer_templates as tmpl

_UTC = datetime.timezone.utc
_BASE_TIME = datetime.datetime(2024, 1, 1, 9, 0, 0, tzinfo=_UTC)

DEVICES = ["AA:BB:CC:11:22:33", "11:22:33:AA:BB:CC", "DE:AD:BE:EF:00:01", "C0:FF:EE:00:00:01"]
HOLDOUT_DEVICE = DEVICES[3]  # reserved entirely for eval_holdout

# A representative subset of HCI_ERROR_CODES plausible as connection/disconnect
# failure reasons — not exhaustive, just enough for training data diversity.
_NORMAL_DISCONNECT_REASONS = {0x00, 0x13, 0x14, 0x15, 0x16}
CONNECTION_ERROR_CODES = [
    code for code in (
        0x02, 0x03, 0x04, 0x05, 0x08, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x11, 0x17, 0x1F, 0x22, 0x25, 0x28, 0x2F, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
    )
    if code in HCI_ERROR_CODES and code not in _NORMAL_DISCONNECT_REASONS
]
COMMAND_ERROR_CODES = [0x01, 0x0C, 0x11, 0x12]
HARDWARE_ERROR_CODES = list(range(0x0B))
REPRESENTATIVE_OPCODES = list(HCI_OPCODE_NAMES.items())[:15]


def _stats_skeleton(index: int) -> CaptureStats:
    s = CaptureStats()
    s.total_packets = 20 + (index % 30)
    s.total_bytes = s.total_packets * 145
    s.start_time = _BASE_TIME + datetime.timedelta(minutes=index)
    s.end_time = s.start_time + datetime.timedelta(seconds=3 + (index % 5))
    return s


def _fail_time(s: CaptureStats) -> str:
    return s.end_time.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _abnormal_disconnect(index: int, device: str, error_code: int):
    s = _stats_skeleton(index)
    handle = f"0x{(index % 8) + 1:03X}"
    s.devices = {device: "Unknown"}
    error_name = HCI_ERROR_CODES[error_code]
    s.lifecycle_events = [{
        "timestamp": s.end_time, "event": "Disconnected", "handle": handle,
        "details": f"Reason: 0x{error_code:02X} {error_name} (Remote Device)", "is_error": True,
    }]
    s.issues = [{
        "timestamp": s.end_time, "level": "WARN", "title": "Abnormal Disconnect",
        "detail": f"Handle {handle} disconnected: 0x{error_code:02X} {error_name}",
    }]
    answer = tmpl.abnormal_disconnect(
        device=device, handle=handle, time=_fail_time(s), error_code=error_code, error_name=error_name
    )
    return s, answer


def _le_connection_failed(index: int, device: str, error_code: int):
    s = _stats_skeleton(index)
    handle = f"0x{(index % 8) + 1:03X}"
    error_name = HCI_ERROR_CODES[error_code]
    s.lifecycle_events = [{
        "timestamp": s.end_time, "event": "Connect Failed (LE)", "handle": handle,
        "details": f"Device: {device} — 0x{error_code:02X} {error_name}", "is_error": True,
    }]
    s.issues = [{
        "timestamp": s.end_time, "level": "WARN", "title": "LE Connection Failed",
        "detail": f"Failed to connect to {device}: 0x{error_code:02X} {error_name}",
    }]
    answer = tmpl.le_connection_failed(
        device=device, handle=handle, time=_fail_time(s), error_code=error_code, error_name=error_name
    )
    return s, answer


def _classic_connection_failed(index: int, device: str, error_code: int):
    s = _stats_skeleton(index)
    handle = f"0x{(index % 8) + 1:03X}"
    error_name = HCI_ERROR_CODES[error_code]
    s.lifecycle_events = [{
        "timestamp": s.end_time, "event": "Connect Failed (Classic)", "handle": handle,
        "details": f"Device: {device} — 0x{error_code:02X} {error_name}", "is_error": True,
    }]
    s.issues = [{
        "timestamp": s.end_time, "level": "WARN", "title": "Connection Failed",
        "detail": f"Failed to connect to {device}: 0x{error_code:02X} {error_name}",
    }]
    answer = tmpl.classic_connection_failed(
        device=device, handle=handle, time=_fail_time(s), error_code=error_code, error_name=error_name
    )
    return s, answer


def _command_failure(index: int, opcode: int, opcode_name: str, error_code: int):
    s = _stats_skeleton(index)
    error_name = HCI_ERROR_CODES[error_code]
    s.issues = [{
        "timestamp": s.end_time, "level": "ERROR", "title": "Command Failure",
        "detail": f"{opcode_name} failed: 0x{error_code:02X} {error_name}",
    }]
    answer = tmpl.command_failure(
        opcode_name=opcode_name, time=_fail_time(s), error_code=error_code, error_name=error_name
    )
    return s, answer


def _command_status_error(index: int, opcode: int, opcode_name: str, error_code: int):
    s = _stats_skeleton(index)
    error_name = HCI_ERROR_CODES[error_code]
    s.issues = [{
        "timestamp": s.end_time, "level": "ERROR", "title": "Command Status Error",
        "detail": f"{opcode_name} returned status 0x{error_code:02X} {error_name}",
    }]
    answer = tmpl.command_status_error(
        opcode_name=opcode_name, time=_fail_time(s), error_code=error_code, error_name=error_name
    )
    return s, answer


def _hardware_error(index: int, error_code: int):
    s = _stats_skeleton(index)
    s.issues = [{
        "timestamp": s.end_time, "level": "CRITICAL", "title": "Hardware Error",
        "detail": f"Controller reported hardware error code 0x{error_code:02X}",
    }]
    answer = tmpl.hardware_error(time=_fail_time(s), error_code=error_code)
    return s, answer


def generate_scenarios():
    """Yield (device, stats, answer) for every scenario across all archetypes."""
    index = 0
    for device in DEVICES:
        for error_code in CONNECTION_ERROR_CODES:
            for builder in (_abnormal_disconnect, _le_connection_failed, _classic_connection_failed):
                index += 1
                stats, answer = builder(index, device, error_code)
                yield device, stats, answer

    # Command failures/status errors aren't device-specific, but we still
    # tag each with a "device" for the same train/val/holdout split logic.
    for i, device in enumerate(DEVICES):
        opcodes = REPRESENTATIVE_OPCODES[i::len(DEVICES)] or REPRESENTATIVE_OPCODES
        for opcode, opcode_name in opcodes:
            for error_code in COMMAND_ERROR_CODES:
                for builder in (_command_failure, _command_status_error):
                    index += 1
                    stats, answer = builder(index, opcode, opcode_name, error_code)
                    yield device, stats, answer

    for i, device in enumerate(DEVICES):
        for error_code in HARDWARE_ERROR_CODES:
            index += 1
            stats, answer = _hardware_error(index, error_code)
            yield device, stats, answer


def main() -> None:
    train, val, holdout = [], [], []
    for i, (device, stats, answer) in enumerate(generate_scenarios()):
        context = build_context(stats)
        example = {
            "input": f"{context}\n\nQuestion: {DEFAULT_QUESTION}",
            "output": answer,
        }
        if device == HOLDOUT_DEVICE:
            holdout.append(example)
        elif i % 10 == 0:
            val.append(example)
        else:
            train.append(example)

    data_dir = ROOT / "training" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    for name, examples in (("train.jsonl", train), ("val.jsonl", val), ("eval_holdout.jsonl", holdout)):
        path = data_dir / name
        with open(path, "w") as f:
            f.writelines(json.dumps(ex) + "\n" for ex in examples)
        print(f"Wrote {len(examples):4d} examples to {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
