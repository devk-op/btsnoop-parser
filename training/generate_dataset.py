#!/usr/bin/env python3
"""Phase 2: synthesize training data for HCI capture analysis.

Each scenario is built as raw HCI packets and run through the real
btsnoop_parser.analysis.CaptureStats and btsnoop_parser.llm.build_context, so
the training inputs have exactly the format the model sees at inference time.
Answers come from training/templates and only restate facts in that summary.

Scenarios cover failures (LE/Classic connection failures, unexpected
disconnects, command failures, hardware errors, LE Audio stream failures) and
normal sessions, with routine Android noise (vendor-command probes, Delete
Stored Link Key, Sniff Subrating rejections) mixed into both, so the model
learns to tell real problems from harmless ones.

The holdout set uses devices and status codes that never appear in training,
so evaluation measures whether the model reads the summary rather than
recalling memorized examples.

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
from training.templates import answer_templates as tmpl

UTC = datetime.timezone.utc

# Never used in training scenarios; only in the holdout set.
HOLDOUT_CODES = {0x09, 0x0D, 0x1A, 0x22, 0x3B}

CONNECT_FAIL_CODES = [0x02, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0D, 0x0E, 0x10, 0x11, 0x1A, 0x1F, 0x22, 0x28, 0x2F, 0x3A, 0x3B, 0x3E]
DISCONNECT_CODES = [0x03, 0x05, 0x06, 0x08, 0x09, 0x0D, 0x0E, 0x1A, 0x1F, 0x22, 0x28, 0x3B, 0x3D]
COMMAND_FAIL_CODES = [0x01, 0x0C, 0x0D, 0x11, 0x12, 0x1A, 0x1F, 0x3A]
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

    def _add(self, ptype: int, payload: bytes, gap: float) -> datetime.datetime:
        self.t += datetime.timedelta(seconds=gap)
        self.records.append({
            "packet_type": ptype,
            "packet_type_name": HCI_PACKET_TYPES[ptype],
            "payload": payload,
            "timestamp": self.t,
            "original_length": len(payload) + 1,
        })
        return self.t

    def event(self, payload: bytes, gap: float = 0.05) -> datetime.datetime:
        return self._add(0x04, payload, gap)

    def command(self, opcode: int, gap: float = 0.01) -> None:
        self._add(0x01, bytes([opcode & 0xFF, opcode >> 8, 0]), gap)

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

    def cis(self, handle: int, status: int) -> datetime.datetime:
        return self.event(bytes([0x3E, 0x1D, 0x19, status, handle & 0xFF, handle >> 8]) + bytes(22),
                          gap=self.rng.uniform(1.0, 30.0))

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


def _normal_part(s: Session, mac: str, handle: int) -> tuple[str, str]:
    """Connect, exchange traffic and disconnect normally. Returns (story, end time)."""
    rng = s.rng
    kind = rng.choice(["le", "le_enh", "classic"])
    if kind == "classic":
        t0 = s.classic_connect(mac, handle, 0x00)
        link = "Classic (BR/EDR)"
    else:
        t0 = s.le_connect(mac, handle, 0x00, enhanced=kind == "le_enh")
        link = "LE"
    s.traffic(rng.randrange(2, 12))
    streams = 0
    if kind != "classic" and rng.random() < 0.4:
        streams = rng.randrange(1, 4)
        for i in range(streams):
            cis_handle = 0x060 + i
            s.cis(cis_handle, 0x00)
            s.traffic(rng.randrange(1, 4))
            s.disconnect(cis_handle, 0x16)
    reason = rng.choice(list(NORMAL_REASONS))
    t_end = s.disconnect(handle, reason)
    audio = f", with {streams} LE Audio stream(s) started and stopped normally" if streams else ""
    story = (f"{mac} connected over {link} at {_hhmmss(t0)}{audio}; the connection ended at {_hhmmss(t_end)} "
             f"when {NORMAL_REASONS[reason]} closed it, which is a normal disconnect.")
    return story, mac


def scenario_normal(s: Session, devices: list[str], codes: list[int]):
    s.startup()
    routine = s.routine_noise()
    stories = []
    for i, mac in enumerate(s.rng.sample(devices, s.rng.randrange(1, 3))):
        story, _ = _normal_part(s, mac, 0x001 + i)
        stories.append(story)
    answer = tmpl.normal_session(story=" ".join(stories), routine=routine)
    return answer, ["NORMAL"], None


def _earlier_ok(s: Session, devices: list[str], exclude: str):
    if s.rng.random() < 0.5:
        return None
    mac = s.rng.choice([d for d in devices if d != exclude])
    _normal_part(s, mac, 0x001)
    return mac


def scenario_le_fail(s: Session, devices: list[str], codes: list[int]):
    s.startup()
    routine = s.routine_noise()
    mac, code = s.rng.choice(devices), s.rng.choice(codes)
    earlier = _earlier_ok(s, devices, mac)
    handle = 0x002
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
    handle = 0x00B
    t = s.classic_connect(mac, handle, code)
    name = HCI_ERROR_CODES[code]
    answer = tmpl.classic_connect_failed(device=mac, handle=f"0x{handle:03X}", time=_hhmmss(t), code=code,
                                         name=name, routine=routine, earlier_ok=earlier)
    return answer, [mac, name], code


def scenario_abnormal_disconnect(s: Session, devices: list[str], codes: list[int]):
    s.startup()
    routine = s.routine_noise()
    mac, code = s.rng.choice(devices), s.rng.choice(codes)
    handle = 0x040
    if s.rng.random() < 0.5:
        t0, kind = s.classic_connect(mac, handle, 0x00), "Classic (BR/EDR)"
    else:
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
        _normal_part(s, s.rng.choice(devices), 0x001)
    hw = f"0x{s.rng.randrange(0x40):02X}"
    t = s.hw_error(int(hw, 16))
    answer = tmpl.hardware_error(time=_hhmmss(t), hw_code=hw, routine=routine)
    return answer, [hw], None


def scenario_audio_fail(s: Session, devices: list[str], codes: list[int]):
    s.startup()
    routine = s.routine_noise()
    mac, code = s.rng.choice(devices), s.rng.choice(codes)
    s.le_connect(mac, 0x040, 0x00, enhanced=True)
    s.traffic(s.rng.randrange(2, 6))
    t = s.cis(0x060, code)
    name = HCI_ERROR_CODES[code]
    answer = tmpl.audio_stream_failed(device=mac, handle="0x060", time=_hhmmss(t), code=code,
                                      name=name, routine=routine)
    return answer, [name], code


# (scenario, status codes it draws from, train count, holdout count)
PLAN = [
    (scenario_normal, [], 260, 25),
    (scenario_le_fail, CONNECT_FAIL_CODES, 200, 20),
    (scenario_classic_fail, CONNECT_FAIL_CODES, 150, 15),
    (scenario_abnormal_disconnect, DISCONNECT_CODES, 200, 20),
    (scenario_command_fail, COMMAND_FAIL_CODES, 160, 15),
    (scenario_hardware_error, [], 50, 8),
    (scenario_audio_fail, CIS_FAIL_CODES, 70, 10),
]


def _example(stats: CaptureStats, answer: str, facts: list[str], kind: str) -> dict:
    context = build_context(stats)
    return {"input": f"{context}\n\nQuestion: {DEFAULT_QUESTION}", "output": answer, "facts": facts, "kind": kind}


def _run(fn, rng, devices, codes, opcodes):
    s = Session(rng)
    if fn is scenario_command_fail:
        answer, facts, code = fn(s, devices, codes, opcodes)
    else:
        answer, facts, code = fn(s, devices, codes)
    stats = CaptureStats()
    for record in s.records:
        stats.analyze_record(record)
    return stats, answer, facts


def main() -> None:
    rng = random.Random(1234)
    train_devices = [_mac(rng) for _ in range(60)]
    holdout_devices = [_mac(rng) for _ in range(15)]
    opcodes = sorted(COMPLETE_OPCODES)
    holdout_opcodes = opcodes[::5]
    train_opcodes = [op for op in opcodes if op not in holdout_opcodes]

    train, holdout = [], []
    for fn, codes, n_train, n_holdout in PLAN:
        kind = fn.__name__.removeprefix("scenario_")
        train_codes = [c for c in codes if c not in HOLDOUT_CODES] or codes
        held_codes = [c for c in codes if c in HOLDOUT_CODES] or codes
        for _ in range(n_train):
            stats, answer, facts = _run(fn, rng, train_devices, train_codes, train_opcodes)
            train.append(_example(stats, answer, facts, kind))
        for _ in range(n_holdout):
            stats, answer, facts = _run(fn, rng, holdout_devices, held_codes, holdout_opcodes)
            holdout.append(_example(stats, answer, facts, kind))

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
