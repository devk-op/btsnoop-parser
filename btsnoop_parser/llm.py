"""Local LLM analysis of a parsed BTSnoop capture.

Turns a :class:`~btsnoop_parser.analysis.CaptureStats` into a compact text
prompt and asks a local Hugging Face model (optionally specialized with a
LoRA adapter trained under ``training/``) to explain what went wrong.

Nothing in this module is imported eagerly by the rest of the package —
``transformers``/``peft``/``torch`` are only imported inside :func:`ask`, so
``pip install btsnoop-parser`` (no extras) stays dependency-free.
"""
from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, Optional

from .analysis import format_duration

if TYPE_CHECKING:
    from .analysis import CaptureStats

DEFAULT_BASE_MODEL = "Qwen/Qwen2.5-1.5B-Instruct"
DEFAULT_QUESTION = "Why did this Bluetooth session fail? What is the most likely root cause?"

DEFAULT_MAX_ISSUES = 50
DEFAULT_MAX_EVENTS = 50

SYSTEM_PROMPT = """You are a Bluetooth protocol expert with deep knowledge of HCI, L2CAP, A2DP, AVDTP, RFCOMM, and BLE.

You will be given a pre-decoded, structured SUMMARY of a Bluetooth HCI capture — not raw packet bytes. \
The summary only covers HCI-transport-layer events (connection setup/teardown, command failures, hardware \
errors); it does not parse upper-layer protocol payloads such as A2DP audio or RFCOMM data. If the summary \
does not contain enough information to answer a question, say so plainly instead of speculating.

When you see an HCI error/status code, explain what it means in plain English using the text already given \
in the summary. Always structure your answer around: (1) what failed, (2) at what point in the sequence, \
(3) the likely root cause. Keep your answer concise — a few sentences per point, not an essay."""


class ModelUnavailableError(RuntimeError):
    """Raised when the optional ML dependencies for --ai are not installed."""


def _format_events(events: list[dict], max_events: int) -> list[str]:
    events = sorted(events, key=lambda e: e["timestamp"])
    if len(events) <= max_events:
        selected = events
        omitted = 0
    else:
        errors = [e for e in events if e["is_error"]]
        normal = [e for e in events if not e["is_error"]]
        budget = max(max_events - len(errors), 0)
        selected = errors + normal[-budget:] if budget else list(errors)
        omitted = len(events) - len(selected)
        selected.sort(key=lambda e: e["timestamp"])

    lines = []
    for evt in selected:
        t_str = evt["timestamp"].astimezone().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        lines.append(f"  {t_str} {evt['event']:<24} {evt['handle']} -> {evt['details']}")
    if omitted:
        lines.append(f"  ... {omitted} normal connection event(s) omitted")
    return lines


def _format_issues(issues: list[dict], max_issues: int) -> list[str]:
    if len(issues) <= max_issues:
        selected = sorted(issues, key=lambda i: i["timestamp"])
        omitted = 0
    else:
        severity_rank = {"CRITICAL": 0, "ERROR": 1, "WARN": 2}
        ranked = sorted(issues, key=lambda i: severity_rank.get(i["level"], 3))
        selected = ranked[:max_issues]
        omitted = len(issues) - len(selected)
        selected.sort(key=lambda i: i["timestamp"])

    lines = []
    for issue in selected:
        t_str = issue["timestamp"].astimezone().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        lines.append(f"  [{issue['level']}] {t_str} - {issue['title']}: {issue['detail']}")
    if omitted:
        lines.append(f"  ... {omitted} lower-severity issue(s) omitted")
    return lines


def build_context(
    stats: CaptureStats,
    max_issues: int = DEFAULT_MAX_ISSUES,
    max_events: int = DEFAULT_MAX_EVENTS,
) -> str:
    """Render a CaptureStats into a plain-text summary suitable for an LLM prompt.

    Unlike CaptureStats.print_summary(), this emits no ANSI color codes, and
    truncation (when the capture has more issues/events than the max_*
    limits) always keeps the highest-severity/error entries first, dropping
    normal/low-severity entries before ever dropping a real problem.
    """
    lines = ["Capture Summary:"]
    lines.append(f"  Duration: {format_duration(stats.start_time, stats.end_time)}")
    lines.append(f"  Total Packets: {stats.total_packets}")
    lines.append(f"  Data Volume: {stats.total_bytes / 1024:.2f} KB")
    if stats.packets_by_type:
        types = ", ".join(f"{name}={count}" for name, count in stats.packets_by_type.most_common())
        lines.append(f"  Packet Types: {types}")
    if stats.devices:
        devices = ", ".join(f"{addr} ({name})" for addr, name in stats.devices.items())
        lines.append(f"  Devices: {devices}")

    lines.append("")
    lines.append("Connection History:")
    if stats.lifecycle_events:
        lines.extend(_format_events(stats.lifecycle_events, max_events))
    else:
        lines.append("  No connection events recorded.")

    lines.append("")
    lines.append("Detected Issues:")
    if stats.issues:
        lines.extend(_format_issues(stats.issues, max_issues))
    else:
        lines.append("  No issues detected.")

    return "\n".join(lines)


def ask(
    stats: CaptureStats,
    question: str = DEFAULT_QUESTION,
    base_model: str = DEFAULT_BASE_MODEL,
    adapter_path: Optional[str] = None,
    max_issues: int = DEFAULT_MAX_ISSUES,
    max_events: int = DEFAULT_MAX_EVENTS,
) -> str:
    """Ask a local Hugging Face model to explain a capture's issues.

    Loads `base_model` (optionally wrapped with a LoRA adapter from
    `adapter_path`, if given and present) and generates an answer grounded in
    a text summary of `stats`. Runs entirely locally — no network access
    beyond the one-time Hugging Face Hub model download.
    """
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        raise ModelUnavailableError(
            "The 'transformers'/'torch' packages are required for --ai. "
            'Install them with: pip install "btsnoop-parser[ai]"'
        ) from exc

    context = build_context(stats, max_issues=max_issues, max_events=max_events)

    tokenizer = AutoTokenizer.from_pretrained(base_model)
    model = AutoModelForCausalLM.from_pretrained(base_model)

    if adapter_path and os.path.isdir(adapter_path):
        try:
            from peft import PeftModel
        except ImportError as exc:
            raise ModelUnavailableError(
                "The 'peft' package is required to use --adapter-path. "
                'Install it with: pip install "btsnoop-parser[ai]"'
            ) from exc
        model = PeftModel.from_pretrained(model, adapter_path)
    elif adapter_path:
        print(
            f"Warning: adapter path '{adapter_path}' not found — falling back to the base model.",
            file=sys.stderr,
        )

    device = "mps" if torch.backends.mps.is_available() else "cpu"
    model = model.to(device)
    model.eval()

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"{context}\n\nQuestion: {question}"},
    ]
    # return_dict=True gives the same shape on transformers 4.x and 5.x (5.x made it the default).
    inputs = tokenizer.apply_chat_template(
        messages, add_generation_prompt=True, return_dict=True, return_tensors="pt"
    ).to(device)

    with torch.no_grad():
        output = model.generate(
            **inputs,
            max_new_tokens=400,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )

    generated = output[0][inputs["input_ids"].shape[-1] :]
    return tokenizer.decode(generated, skip_special_tokens=True).strip()
