#!/usr/bin/env python3
"""Synthesize training data for HCI capture analysis.

Each scenario is built as raw HCI packets and run through the real
btsnoop_parser.analysis.CaptureStats and btsnoop_parser.llm.build_context, so
the training inputs have exactly the format the model sees at inference time.
Answers come from training/templates and only restate facts in that summary.

Scenarios cover failures (LE/Classic connection failures, unexpected
disconnects, command failures, hardware errors, LE Audio stream failures) and
normal sessions, with routine Android noise (vendor-command probes, Delete
Stored Link Key, Sniff Subrating rejections) mixed into both, so the model
learns to tell real problems from harmless ones.

Sessions vary from a single short link to a dual-mode device (LE and Classic
links to the same address) cycling several LE Audio streams, which is what
captures from real earbuds look like.

The holdout set uses devices, commands and status codes that never appear in
training, so evaluation measures whether the model reads the summary rather
than recalling memorized examples.

Usage:
    python3 training/generate_dataset.py
"""
from __future__ import annotations

import datetime
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from btsnoop_parser.analysis import CaptureStats
from btsnoop_parser.constants import HCI_ERROR_CODES, HCI_OPCODE_NAMES
from btsnoop_parser.core import HCI_PACKET_TYPES
from btsnoop_parser.llm import DEFAULT_QUESTION, build_context
from btsnoop_parser.report import ReportBuilder
from training.templates import answer_templates as tmpl
from training.templates import profile_answers

UTC = datetime.timezone.utc

# Never used in training scenarios; only in the holdout set.
HOLDOUT_CODES = {0x09, 0x0D, 0x0F, 0x1A, 0x22, 0x2A, 0x3B}

# Longer sessions are regenerated so every example fits train_lora.py's --max-len.
MAX_INPUT_CHARS = 3600

CONNECT_FAIL_CODES = [0x02, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0D, 0x0E, 0x10, 0x11, 0x1A, 0x1F, 0x22, 0x28, 0x2F, 0x3A, 0x3B, 0x3E]
DISCONNECT_CODES = [0x03, 0x05, 0x06, 0x08, 0x09, 0x0D, 0x0E, 0x1A, 0x1F, 0x22, 0x28, 0x3B, 0x3D]
# Any status can come back from a command, and the wide spread of names teaches the model to copy them.
COMMAND_FAIL_CODES = [c for c in HCI_ERROR_CODES if c not in (0x00, 0x13, 0x14, 0x15, 0x16)]
CIS_FAIL_CODES = [0x0D, 0x1F, 0x22, 0x3A, 0x3B, 0x3E]
NORMAL_REASONS = {0x13: "the other device", 0x15: "the other device (it powered off)", 0x16: "this phone"}

# Commands whose failure is reported via Command Status (they start a procedure).
STATUS_OPCODES = [0x0405, 0x0411, 0x0413, 0x0419, 0x041B, 0x041D, 0x0428, 0x200D, 0x2016, 0x2019]
BENIGN_OPCODES = {0x0C12, 0x0811}
COMPLETE_OPCODES = [op for op in HCI_OPCODE_NAMES if op not in BENIGN_OPCODES and op not in STATUS_OPCODES]

ROUTINE = [
    ("vendor", "the vendor-specific command probe"),
    ("delete_key", "Delete Stored Link Key"),
    ("sniff", "Sniff Subrating"),
]


def _mac(rng: random.Random) -> str:
    return ":".join(f"{rng.randrange(256):02X}" for _ in range(6))


def _hhmmss(ts: datetime.datetime) -> str:
    return ts.astimezone().strftime("%H:%M:%S")


class Session:
    """Builds a list of parsed-record dicts, as parse_btsnoop_file would return them."""

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.t = datetime.datetime(2025, 1, 1, tzinfo=UTC) + datetime.timedelta(
            days=rng.randrange(300), seconds=rng.randrange(86400)
        )
        self.records: list[dict] = []
        self._handles: set[int] = set()

    def handle(self, kind: str) -> int:
        """Pick an unused connection handle in the range controllers typically use for that link type."""
        base = {"classic": 0x001, "le": 0x040, "cis": 0x060}[kind]
        free = [h for h in range(base, base + 0x10) if h not in self._handles]
        handle = self.rng.choice(free)
        self._handles.add(handle)
        return handle

    def _add(self, ptype: int, payload: bytes, gap: float, direction: str | None = None) -> datetime.datetime:
        self.t += datetime.timedelta(seconds=gap)
        self.records.append({
            "index": len(self.records) + 1,
            "packet_type": ptype,
            "packet_type_name": HCI_PACKET_TYPES[ptype],
            "direction": direction or ("TX" if ptype in (0x01, 0x02) else "RX"),
            "payload": payload,
            "timestamp": self.t,
            "original_length": len(payload) + 1,
            "captured_length": len(payload) + 1,
        })
        return self.t

    def event(self, payload: bytes, gap: float = 0.05) -> datetime.datetime:
        return self._add(0x04, payload, gap)

    def command(self, opcode: int, gap: float = 0.01, params: bytes = b"") -> None:
        self._add(0x01, bytes([opcode & 0xFF, opcode >> 8, len(params)]) + params, gap)

    def traffic(self, n: int) -> None:
        for _ in range(n):
            self._add(0x02, bytes(self.rng.randrange(8, 64)), self.rng.uniform(0.01, 0.5))

    def cmd_complete(self, opcode: int, status: int, gap: float = 0.01) -> datetime.datetime:
        self.command(opcode)
        return self.event(bytes([0x0E, 0x04, 0x01, opcode & 0xFF, opcode >> 8, status]), gap)

    def cmd_status(self, opcode: int, status: int) -> datetime.datetime:
        self.command(opcode)
        return self.event(bytes([0x0F, 0x04, status, 0x01, opcode & 0xFF, opcode >> 8]))

    def le_connect(self, mac: str, handle: int, status: int, enhanced: bool) -> datetime.datetime:
        addr = bytes.fromhex(mac.replace(":", ""))[::-1]
        sub = 0x0A if enhanced else 0x01
        tail = bytes(19) if enhanced else bytes(7)
        self.command(0x200D)
        payload = bytes([0x3E, 0x13, sub, status, handle & 0xFF, handle >> 8, 0x00, 0x00]) + addr + tail
        return self.event(payload, gap=self.rng.uniform(0.2, 5.0))

    def classic_connect(self, mac: str, handle: int, status: int) -> datetime.datetime:
        addr = bytes.fromhex(mac.replace(":", ""))[::-1]
        self.command(0x0405)
        return self.event(bytes([0x03, 0x0B, status, handle & 0xFF, handle >> 8]) + addr + bytes([0x01, 0x00]),
                          gap=self.rng.uniform(0.2, 5.0))

    def cis(self, handle: int, status: int, acl_handle: int) -> datetime.datetime:
        # LE Create CIS ties the stream to its connection, which is how the summary knows the device.
        self.command(0x2064, gap=self.rng.uniform(1.0, 30.0),
                     params=bytes([0x01, handle & 0xFF, handle >> 8, acl_handle & 0xFF, acl_handle >> 8]))
        return self.event(bytes([0x3E, 0x1D, 0x19, status, handle & 0xFF, handle >> 8]) + bytes(22),
                          gap=self.rng.uniform(0.02, 0.4))

    def disconnect(self, handle: int, reason: int, gap: float | None = None) -> datetime.datetime:
        return self.event(bytes([0x05, 0x04, 0x00, handle & 0xFF, handle >> 8, reason]),
                          gap=self.rng.uniform(1.0, 60.0) if gap is None else gap)

    def hw_error(self, code: int) -> datetime.datetime:
        return self.event(bytes([0x10, 0x01, code]), gap=self.rng.uniform(0.5, 20.0))

    def startup(self) -> None:
        for op in (0x0C03, 0x1009, 0x0C01, 0x1001):
            self.cmd_complete(op, 0x00)

    def routine_noise(self, max_items: int = 2) -> list[str]:
        picked = self.rng.sample(ROUTINE, self.rng.randrange(max_items + 1))
        for kind, _ in picked:
            if kind == "vendor":
                self.cmd_complete(0xFC00 | self.rng.randrange(0x400), 0x01)
            elif kind == "delete_key":
                self.cmd_complete(0x0C12, 0x12)
            else:
                self.cmd_complete(0x0811, 0x12)
        return [label for _, label in picked]


def _audio_streams(s: Session, acl_handle: int, count: int, keep_last_open: bool) -> int | None:
    """Start and stop LE Audio streams; optionally leave the last one running and return its handle."""
    handle = s.handle("cis") if count else None
    for i in range(count):
        s.cis(handle, 0x00, acl_handle)
        s.traffic(s.rng.randrange(1, 4))
        if i == count - 1 and keep_last_open:
            return handle
        s.disconnect(handle, 0x16, gap=s.rng.uniform(2.0, 40.0))
    return None


def _normal_part(s: Session, mac: str) -> str:
    """Connect, exchange traffic and disconnect normally. Returns the story of what happened."""
    rng = s.rng
    kind = rng.choice(["le", "le_enh", "classic", "dual", "dual"])
    reason = rng.choice(list(NORMAL_REASONS))
    recon = ""
    if kind == "classic":
        handles = [s.handle("classic")]
        link = f"over Classic (BR/EDR) at {_hhmmss(s.classic_connect(mac, handles[0], 0x00))}"
    elif kind == "dual":
        handles = [s.handle("le"), s.handle("classic")]
        t_le = s.le_connect(mac, handles[0], 0x00, enhanced=True)
        t_classic = s.classic_connect(mac, handles[1], 0x00)
        link = f"over LE at {_hhmmss(t_le)} and over Classic (BR/EDR) at {_hhmmss(t_classic)}"
        if rng.random() < 0.4:
            s.disconnect(handles[1], 0x16, gap=rng.uniform(1.0, 4.0))
            t_again = s.classic_connect(mac, handles[1], 0x00)
            recon = f" (this phone closed the Classic link once and reconnected it at {_hhmmss(t_again)})"
    else:
        handles = [s.handle("le")]
        link = f"over LE at {_hhmmss(s.le_connect(mac, handles[0], 0x00, enhanced=kind == 'le_enh'))}"
    s.traffic(rng.randrange(2, 12))

    streams = 0
    if kind != "classic" and rng.random() < 0.6:
        streams = rng.randrange(1, 7)
        open_stream = _audio_streams(s, handles[0], streams, keep_last_open=rng.random() < 0.5)
        if open_stream is not None:
            s.disconnect(open_stream, reason)

    t_end = s.disconnect(handles[0], reason, gap=None if streams == 0 else 0.05)
    for handle in handles[1:]:
        s.disconnect(handle, reason, gap=0.07)
    audio = f", with {streams} LE Audio stream(s) started and stopped normally" if streams else ""
    ended = "both links ended" if len(handles) > 1 else "the connection ended"
    closed = "closed them" if len(handles) > 1 else "closed it"
    return (f"{mac} connected {link}{recon}{audio}; {ended} at {_hhmmss(t_end)} "
            f"when {NORMAL_REASONS[reason]} {closed}, which is a normal disconnect.")


def scenario_normal(s: Session, devices: list[str], codes: list[int]):
    s.startup()
    routine = s.routine_noise()
    stories = []
    for mac in s.rng.sample(devices, s.rng.randrange(1, 3)):
        stories.append(_normal_part(s, mac))
    answer = tmpl.normal_session(story=" ".join(stories), routine=routine)
    return answer, ["NORMAL"], None


def _earlier_ok(s: Session, devices: list[str], exclude: str):
    if s.rng.random() < 0.5:
        return None
    mac = s.rng.choice([d for d in devices if d != exclude])
    _normal_part(s, mac)
    return mac


def scenario_le_fail(s: Session, devices: list[str], codes: list[int]):
    s.startup()
    routine = s.routine_noise()
    mac, code = s.rng.choice(devices), s.rng.choice(codes)
    earlier = _earlier_ok(s, devices, mac)
    handle = s.handle("le")
    t = s.le_connect(mac, handle, code, enhanced=s.rng.random() < 0.6)
    name = HCI_ERROR_CODES[code]
    answer = tmpl.le_connect_failed(device=mac, handle=f"0x{handle:03X}", time=_hhmmss(t), code=code,
                                    name=name, routine=routine, earlier_ok=earlier)
    return answer, [mac, name], code


def scenario_classic_fail(s: Session, devices: list[str], codes: list[int]):
    s.startup()
    routine = s.routine_noise()
    mac, code = s.rng.choice(devices), s.rng.choice(codes)
    earlier = _earlier_ok(s, devices, mac)
    handle = s.handle("classic")
    t = s.classic_connect(mac, handle, code)
    name = HCI_ERROR_CODES[code]
    answer = tmpl.classic_connect_failed(device=mac, handle=f"0x{handle:03X}", time=_hhmmss(t), code=code,
                                         name=name, routine=routine, earlier_ok=earlier)
    return answer, [mac, name], code


def scenario_abnormal_disconnect(s: Session, devices: list[str], codes: list[int]):
    s.startup()
    routine = s.routine_noise()
    mac, code = s.rng.choice(devices), s.rng.choice(codes)
    _earlier_ok(s, devices, mac)
    if s.rng.random() < 0.5:
        handle = s.handle("classic")
        t0, kind = s.classic_connect(mac, handle, 0x00), "Classic (BR/EDR)"
    else:
        handle = s.handle("le")
        t0, kind = s.le_connect(mac, handle, 0x00, enhanced=s.rng.random() < 0.6), "LE"
    s.traffic(s.rng.randrange(3, 15))
    t = s.disconnect(handle, code)
    name = HCI_ERROR_CODES[code]
    answer = tmpl.abnormal_disconnect(device=mac, handle=f"0x{handle:03X}", kind=kind, connected_at=_hhmmss(t0),
                                      time=_hhmmss(t), code=code, name=name, routine=routine)
    return answer, [mac, name], code


def scenario_command_fail(s: Session, devices: list[str], codes: list[int], opcodes: list[int]):
    s.startup()
    routine = s.routine_noise()
    if s.rng.random() < 0.5:
        _normal_part(s, s.rng.choice(devices))
    via_status = s.rng.random() < 0.4
    code = s.rng.choice(codes)
    if via_status:
        opcode = s.rng.choice([op for op in STATUS_OPCODES if op in opcodes] or STATUS_OPCODES)
        t = s.cmd_status(opcode, code)
    else:
        opcode = s.rng.choice(opcodes)
        t = s.cmd_complete(opcode, code)
    name, op_name = HCI_ERROR_CODES[code], HCI_OPCODE_NAMES[opcode]
    answer = tmpl.command_failed(opcode_name=op_name, time=_hhmmss(t), code=code, name=name,
                                 routine=routine, via_status=via_status)
    return answer, [op_name, name], code


def scenario_hardware_error(s: Session, devices: list[str], codes: list[int]):
    s.startup()
    routine = s.routine_noise()
    if s.rng.random() < 0.5:
        _normal_part(s, s.rng.choice(devices))
    hw = f"0x{s.rng.randrange(0x100):02X}"
    t = s.hw_error(int(hw, 16))
    answer = tmpl.hardware_error(time=_hhmmss(t), hw_code=hw, routine=routine)
    return answer, [hw], None


def scenario_audio_fail(s: Session, devices: list[str], codes: list[int]):
    s.startup()
    routine = s.routine_noise()
    mac, code = s.rng.choice(devices), s.rng.choice(codes)
    _earlier_ok(s, devices, mac)
    acl_handle = s.handle("le")
    s.le_connect(mac, acl_handle, 0x00, enhanced=True)
    s.traffic(s.rng.randrange(2, 6))
    _audio_streams(s, acl_handle, s.rng.randrange(0, 3), keep_last_open=False)
    handle = s.handle("cis")
    t = s.cis(handle, code, acl_handle)
    name = HCI_ERROR_CODES[code]
    answer = tmpl.audio_stream_failed(device=mac, handle=f"0x{handle:03X}", time=_hhmmss(t), code=code,
                                      name=name, routine=routine)
    return answer, [mac, name], code


# (connection-level scenario, status codes it draws from, train count, holdout count)
PLAN = [
    (scenario_normal, [], 180, 20),
    (scenario_le_fail, CONNECT_FAIL_CODES, 130, 15),
    (scenario_classic_fail, CONNECT_FAIL_CODES, 100, 15),
    (scenario_abnormal_disconnect, DISCONNECT_CODES, 130, 15),
    (scenario_command_fail, COMMAND_FAIL_CODES, 150, 15),
    (scenario_hardware_error, [], 60, 10),
    (scenario_audio_fail, CIS_FAIL_CODES, 50, 10),
]


def _example(context: str, answer: str, facts: list[str], kind: str, legacy: bool = False) -> dict:
    example = {"input": f"{context}\n\nQuestion: {DEFAULT_QUESTION}", "output": answer, "facts": facts, "kind": kind}
    if legacy:
        example["system"] = "legacy"  # older btsnoop-parser: old system prompt, no Device Activity section
    return example


def _report(records):
    builder = ReportBuilder()
    for record in records:
        builder.analyze_record(record)
    return builder.stats, builder.build()


def _run(fn, rng, devices, codes, opcodes, legacy: bool = False) -> dict:
    s = Session(rng)
    if fn is scenario_command_fail:
        answer, facts, code = fn(s, devices, codes, opcodes)
    else:
        answer, facts, code = fn(s, devices, codes)
    stats, report = _report(s.records)
    context = build_context(stats) if legacy else build_context(stats, report=report)
    return _example(context, answer, facts, fn.__name__.removeprefix("scenario_"), legacy)


# Choices each protocol-level problem draws from; the holdout set uses the others.
PROFILE_CHOICES = {
    "a2dp_reject": ("a2dp_reject", [0xC2, 0xC3, 0xC6, 0x29, 0x31], [0xD4, 0x13]),
    "le_audio_fail": ("le_failure", [(0, 0x06, 0x00), (1, 0x07, 0x06), (1, 0x0D, 0x00), (2, 0x0B, 0x00)],
                [(1, 0x08, 0x08), (0, 0x09, 0x02)]),
    "sync_fail": ("sync_fail", [0xC3], [0xC1]),
    "aa_fail": ("aa_status", [-1, -2, -3, -5], [-10, -11]),
}

# (protocol-level scenario, train count, holdout count)
PROFILE_PLAN = [
    ("car_normal", 80, 12), ("headset_normal", 60, 10), ("le_normal", 50, 8), ("volume_override", 60, 10),
    ("player_error", 55, 10), ("no_service", 55, 10), ("stall", 55, 10), ("a2dp_reject", 55, 10),
    ("le_audio_fail", 55, 10), ("aa_fail", 45, 8), ("lost_pairing", 45, 8), ("sync_fail", 45, 8),
    ("multi", 300, 30),
]


def _run_profile(kind: str, rng, devices, holdout: bool) -> dict:
    from training.profile_scenarios import build_profile_session, pick_problems  # import this module's Session

    problems = pick_problems(rng) if kind == "multi" else [kind]
    choices = {}
    for problem in problems:
        if problem in PROFILE_CHOICES:
            key, train_values, held_values = PROFILE_CHOICES[problem]
            choices[key] = rng.choice(held_values if holdout else train_values)
    mac = rng.choice(devices)
    session = build_profile_session(rng, mac, kind, problems=problems if kind == "multi" else None, **choices)
    stats, report = _report(session.records)
    routine = [label for label in ("the vendor-specific command probe", "Delete Stored Link Key", "Sniff Subrating")
               if any(i["level"] == "INFO" and _routine_matches(label, i["detail"]) for i in stats.issues)]
    context = build_context(stats, report=report)
    has_problem = "WARNING" in context or any(i["level"] != "INFO" for i in stats.issues)
    if kind.endswith("_normal"):
        if has_problem:
            return {"input": "x" * (MAX_INPUT_CHARS + 1)}  # rejected by keep(): a "normal" session must be clean
        answer, facts = profile_answers.normal_answer(report, routine), ["NORMAL"]
    else:
        if kind == "multi":
            answer, facts = profile_answers.multi_answer(report, stats, mac, problems, routine)
        else:
            answer, facts = profile_answers.problem_answer(report, stats, mac, kind, routine)
        # Every problem must be visible in the model's input, or the answer would teach it to invent.
        if not has_problem or len(facts) < len(problems) + 1 or not all(
                profile_answers.visible(report, stats, mac, problem) for problem in problems):
            return {"input": "x" * (MAX_INPUT_CHARS + 1)}
    return _example(context, answer, facts, kind)


def _routine_matches(label: str, detail: str) -> bool:
    return {"the vendor-specific command probe": "Vendor-specific", "Delete Stored Link Key": "Delete Stored",
            "Sniff Subrating": "Sniff Subrating"}[label] in detail


def main() -> None:
    rng = random.Random(1234)
    train_devices = [_mac(rng) for _ in range(60)]
    holdout_devices = [_mac(rng) for _ in range(15)]
    opcodes = sorted(COMPLETE_OPCODES)
    holdout_opcodes = opcodes[::5]
    train_opcodes = [op for op in opcodes if op not in holdout_opcodes]

    train, holdout = [], []

    def keep(split: list, make, count: int) -> None:
        made = 0
        while made < count:
            example = make()
            if len(example["input"]) <= MAX_INPUT_CHARS:
                split.append(example)
                made += 1

    for fn, codes, n_train, n_holdout in PLAN:
        train_codes = [c for c in codes if c not in HOLDOUT_CODES] or codes
        held_codes = [c for c in codes if c in HOLDOUT_CODES] or codes
        for split, count, split_devices, split_codes, split_opcodes in (
            (train, n_train, train_devices, train_codes, train_opcodes),
            (holdout, n_holdout, holdout_devices, held_codes, holdout_opcodes),
        ):
            # Most examples in the current format; a fifth in the older one, so older installs keep working.
            legacy = count // 5
            keep(split, lambda: _run(fn, rng, split_devices, split_codes, split_opcodes), count - legacy)
            keep(split, lambda: _run(fn, rng, split_devices, split_codes, split_opcodes, legacy=True), legacy)

    for kind, n_train, n_holdout in PROFILE_PLAN:
        keep(train, lambda: _run_profile(kind, rng, train_devices, holdout=False), n_train)
        keep(holdout, lambda: _run_profile(kind, rng, holdout_devices, holdout=True), n_holdout)

    rng.shuffle(train)
    n_val = len(train) // 20
    splits = {"train.jsonl": train[n_val:], "val.jsonl": train[:n_val], "eval_holdout.jsonl": holdout}

    data_dir = ROOT / "training" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    for name, examples in splits.items():
        path = data_dir / name
        with open(path, "w") as f:
            f.writelines(json.dumps(ex) + "\n" for ex in examples)
        print(f"Wrote {len(examples):4d} examples to {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
