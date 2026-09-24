#!/usr/bin/env python3
"""Phase 1: baseline inference with the bare base model, no LoRA yet.

Run this first to confirm your environment (torch/transformers, MPS backend)
works, and to see what the un-tuned model's answers look like before you
train anything. This is the same code path `btsnoop_parser --ai` uses when
no --adapter-path is given.

Usage:
    python3 training/baseline_check.py
"""
from __future__ import annotations

import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from btsnoop_parser.analysis import CaptureStats
from btsnoop_parser.llm import DEFAULT_BASE_MODEL, ask

_UTC = datetime.timezone.utc


def _sample_failed_le_connection() -> CaptureStats:
    """Hand-built CaptureStats mimicking a real 'LE connection timed out' capture."""
    stats = CaptureStats()
    stats.total_packets = 42
    stats.total_bytes = 3180
    stats.start_time = datetime.datetime(2024, 6, 1, 9, 12, 0, tzinfo=_UTC)
    stats.end_time = stats.start_time + datetime.timedelta(seconds=4.5)
    stats.devices = {"AA:BB:CC:DD:EE:FF": "Unknown"}
    stats.lifecycle_events = [
        {
            "timestamp": stats.start_time + datetime.timedelta(seconds=4.2),
            "event": "Connect Failed (LE)",
            "handle": "0x001",
            "details": "Device: AA:BB:CC:DD:EE:FF — 0x08 Connection Timeout",
            "is_error": True,
        }
    ]
    stats.issues = [
        {
            "timestamp": stats.start_time + datetime.timedelta(seconds=4.2),
            "level": "WARN",
            "title": "LE Connection Failed",
            "detail": "Failed to connect to AA:BB:CC:DD:EE:FF: 0x08 Connection Timeout",
        }
    ]
    return stats


def main() -> None:
    stats = _sample_failed_le_connection()
    print(f"Loading {DEFAULT_BASE_MODEL} (first run downloads ~3GB, then it's cached)...\n")
    answer = ask(stats, question="Why did this Bluetooth connection fail? What is the root cause?")
    print("--- Model answer (base model, no LoRA) ---")
    print(answer)


if __name__ == "__main__":
    main()
