"""Deterministic answers for the synthetic training set.

Every answer only restates facts that appear in the capture summary the model
is given, including its "Status Code Notes" section. Failure answers follow
the "(1) what failed, (2) when, (3) likely root cause" shape from the system
prompt; normal sessions say so plainly instead of inventing a problem.
"""
from __future__ import annotations

from btsnoop_parser.code_notes import CODE_NOTES


def _cause(code: int, name: str) -> str:
    note = CODE_NOTES.get(code)
    if note:
        return f"{name} — {note}."
    return f"the controller reported {name}; the summary gives no more detail than that."


def _routine_note(routine: list[str]) -> str:
    if not routine:
        return ""
    items = ", ".join(routine)
    return (
        f"\nThe routine failures listed ({items}) are common on Android and are not a problem by themselves."
    )


def _failure(what: str, when: str, cause: str, routine: list[str], extra: str = "") -> str:
    text = f"Yes, something failed.\n(1) What failed: {what}.\n(2) When: {when}.\n(3) Likely root cause: {cause}"
    if extra:
        text += f"\n{extra}"
    return text + _routine_note(routine)


def le_connect_failed(*, device, handle, time, code, name, routine, earlier_ok=None):
    when = f"at {time}"
    if earlier_ok:
        when += f", after an earlier connection to {earlier_ok} had ended normally"
    return _failure(f"the LE connection attempt to {device} (handle {handle})", when, _cause(code, name), routine)


def classic_connect_failed(*, device, handle, time, code, name, routine, earlier_ok=None):
    when = f"at {time}"
    if earlier_ok:
        when += f", after an earlier connection to {earlier_ok} had ended normally"
    return _failure(
        f"the Classic (BR/EDR) connection attempt to {device} (handle {handle})", when, _cause(code, name), routine
    )


def abnormal_disconnect(*, device, handle, kind, connected_at, time, code, name, routine):
    return _failure(
        f"the {kind} connection to {device} (handle {handle}) dropped unexpectedly",
        f"at {time}; it had connected at {connected_at}",
        _cause(code, name),
        routine,
        extra="This was not a normal disconnect requested by either side.",
    )


def command_failed(*, opcode_name, time, code, name, routine, via_status):
    event = "a Command Status event, so the command never started" if via_status else "a Command Complete event"
    return _failure(
        f"the HCI command '{opcode_name}'",
        f"at {time}, reported through {event}",
        _cause(code, name),
        routine,
    )


def hardware_error(*, time, hw_code, routine):
    return _failure(
        "the Bluetooth controller itself",
        f"at {time}",
        f"the controller reported hardware error code {hw_code}. This points to a fault in the Bluetooth chip or its "
        "firmware rather than the other device; the stack usually has to reset the controller to recover.",
        routine,
    )


def audio_stream_failed(*, device, handle, time, code, name, routine):
    return _failure(
        f"an LE Audio stream (CIS, handle {handle}) while connected to {device}",
        f"at {time}",
        _cause(code, name),
        routine,
        extra="The underlying LE connection itself was established.",
    )


def normal_session(*, story: str, routine: list[str]) -> str:
    return f"Nothing failed — the session looks normal. {story}" + _routine_note(routine)
