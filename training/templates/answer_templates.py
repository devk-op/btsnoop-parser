"""Deterministic, slot-filled answer templates for the synthetic training set.

Each function takes the same facts that end up in the rendered capture
context (device, handle, error code/name, timestamp, ...) and returns a
grounded answer text in the "(1) what failed, (2) at what point, (3) root
cause" structure the SYSTEM_PROMPT asks for. Templates only ever restate
facts already present in the context — this is what keeps the training data
free of hallucination without needing a larger model to generate/verify it.
"""
from __future__ import annotations


def abnormal_disconnect(*, device: str, handle: str, time: str, error_code: int, error_name: str) -> str:
    return (
        f"(1) The connection on handle {handle} to {device} disconnected. "
        f"(2) This happened at {time}. "
        f"(3) The disconnect reason was 0x{error_code:02X} ({error_name}), which is not a normal "
        f"user- or host-initiated termination, so the root cause is: {error_name.lower()}."
    )


def le_connection_failed(*, device: str, handle: str, time: str, error_code: int, error_name: str) -> str:
    return (
        f"(1) The LE connection attempt to {device} (handle {handle}) failed to establish. "
        f"(2) The failure occurred at {time}. "
        f"(3) The controller reported status 0x{error_code:02X} ({error_name}) as the root cause."
    )


def classic_connection_failed(*, device: str, handle: str, time: str, error_code: int, error_name: str) -> str:
    return (
        f"(1) The classic BR/EDR connection attempt to {device} (handle {handle}) failed to establish. "
        f"(2) The failure occurred at {time}. "
        f"(3) The controller reported status 0x{error_code:02X} ({error_name}) as the root cause."
    )


def command_failure(*, opcode_name: str, time: str, error_code: int, error_name: str) -> str:
    return (
        f"(1) The HCI command '{opcode_name}' failed. "
        f"(2) The failure was reported at {time} via a Command Complete event. "
        f"(3) The status code was 0x{error_code:02X} ({error_name}), which is the root cause of the failure."
    )


def command_status_error(*, opcode_name: str, time: str, error_code: int, error_name: str) -> str:
    return (
        f"(1) The HCI command '{opcode_name}' did not start successfully. "
        f"(2) This was reported at {time} via a Command Status event, before any Command Complete. "
        f"(3) The status code was 0x{error_code:02X} ({error_name}), which is the root cause."
    )


def hardware_error(*, time: str, error_code: int) -> str:
    return (
        f"(1) The Bluetooth controller reported a hardware error. "
        f"(2) This occurred at {time}. "
        f"(3) The controller-reported hardware error code was 0x{error_code:02X}. This indicates a "
        f"low-level fault in the Bluetooth chip/firmware itself, not a protocol negotiation issue — "
        f"typically not recoverable by the host without a controller reset."
    )
