"""One-line descriptions of HCI commands and events for the packet list.

Each description names what the packet is about (which command an answer
belongs to, which device or connection) and whether it reports a failure.
"""
from __future__ import annotations

from typing import Optional

from .constants import HCI_ERROR_CODES, HCI_OPCODE_NAMES

EVENT_NAMES = {
    0x01: "Inquiry Complete",
    0x02: "Inquiry Result",
    0x03: "Connection Complete",
    0x04: "Connection Request",
    0x05: "Disconnection Complete",
    0x06: "Authentication Complete",
    0x07: "Remote Name Request Complete",
    0x08: "Encryption Change",
    0x09: "Change Connection Link Key Complete",
    0x0B: "Read Remote Supported Features Complete",
    0x0C: "Read Remote Version Information Complete",
    0x0D: "QoS Setup Complete",
    0x0E: "Command Complete",
    0x0F: "Command Status",
    0x10: "Hardware Error",
    0x11: "Flush Occurred",
    0x12: "Role Change",
    0x13: "Number Of Completed Packets",
    0x14: "Mode Change",
    0x15: "Return Link Keys",
    0x16: "PIN Code Request",
    0x17: "Link Key Request",
    0x18: "Link Key Notification",
    0x1A: "Data Buffer Overflow",
    0x1B: "Max Slots Change",
    0x1C: "Read Clock Offset Complete",
    0x1D: "Connection Packet Type Changed",
    0x20: "Page Scan Repetition Mode Change",
    0x22: "Inquiry Result with RSSI",
    0x23: "Read Remote Extended Features Complete",
    0x2C: "Synchronous Connection Complete",
    0x2D: "Synchronous Connection Changed",
    0x2E: "Sniff Subrating",
    0x2F: "Extended Inquiry Result",
    0x30: "Encryption Key Refresh Complete",
    0x31: "IO Capability Request",
    0x32: "IO Capability Response",
    0x33: "User Confirmation Request",
    0x34: "User Passkey Request",
    0x36: "Simple Pairing Complete",
    0x38: "Link Supervision Timeout Changed",
    0x39: "Enhanced Flush Complete",
    0x3B: "User Passkey Notification",
    0x3D: "Remote Host Supported Features Notification",
    0x3E: "LE Meta Event",
    0x48: "Authenticated Payload Timeout Expired",
    0x59: "Encryption Change (V2)",
    0xFF: "Vendor Event",
}

LE_SUBEVENT_NAMES = {
    0x01: "LE Connection Complete",
    0x02: "LE Advertising Report",
    0x03: "LE Connection Update Complete",
    0x04: "LE Read Remote Features Complete",
    0x05: "LE Long Term Key Request",
    0x06: "LE Remote Connection Parameter Request",
    0x07: "LE Data Length Change",
    0x08: "LE Read Local P-256 Public Key Complete",
    0x09: "LE Generate DHKey Complete",
    0x0A: "LE Enhanced Connection Complete",
    0x0B: "LE Directed Advertising Report",
    0x0C: "LE PHY Update Complete",
    0x0D: "LE Extended Advertising Report",
    0x0E: "LE Periodic Advertising Sync Established",
    0x0F: "LE Periodic Advertising Report",
    0x10: "LE Periodic Advertising Sync Lost",
    0x11: "LE Scan Timeout",
    0x12: "LE Advertising Set Terminated",
    0x13: "LE Scan Request Received",
    0x14: "LE Channel Selection Algorithm",
    0x19: "LE CIS Established",
    0x1A: "LE CIS Request",
    0x1B: "LE Create BIG Complete",
    0x1C: "LE Terminate BIG Complete",
    0x1D: "LE BIG Sync Established",
    0x1E: "LE BIG Sync Lost",
    0x1F: "LE Request Peer SCA Complete",
    0x20: "LE Path Loss Threshold",
    0x21: "LE Transmit Power Reporting",
    0x22: "LE BIGInfo Advertising Report",
    0x23: "LE Subrate Change",
    0x29: "LE Enhanced Connection Complete (V2)",
}

# LE subevents whose first parameter is a status.
_LE_WITH_STATUS = {0x01, 0x03, 0x04, 0x0A, 0x0C, 0x0E, 0x12, 0x19, 0x1B, 0x1D, 0x1F, 0x23, 0x29}
_MODES = {0x00: "active", 0x01: "hold", 0x02: "sniff"}
_ROLES = {0x00: "central", 0x01: "peripheral"}


def command_name(opcode: int) -> str:
    if opcode >> 10 == 0x3F:
        return f"Vendor command 0x{opcode:04X}"
    return HCI_OPCODE_NAMES.get(opcode, f"Opcode 0x{opcode:04X}")


def _status(code: int) -> str:
    return "Success" if code == 0 else HCI_ERROR_CODES.get(code, f"error 0x{code:02X}")


def _addr(data: bytes) -> str:
    return ":".join(f"{b:02X}" for b in data[::-1])


def _u16(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8)


def describe_command(payload: bytes) -> str:
    if len(payload) < 3:
        return "Command (short)"
    opcode = _u16(payload, 0)
    name, params = command_name(opcode), payload[3:]
    if opcode == 0x0405 and len(params) >= 6:  # Create Connection
        return f"{name} to {_addr(params[:6])}"
    if opcode == 0x0406 and len(params) >= 3:  # Disconnect
        return f"{name} handle 0x{_u16(params, 0) & 0x0FFF:03X} ({HCI_ERROR_CODES.get(params[2], hex(params[2]))})"
    if opcode in (0x0409, 0x040A, 0x0419) and len(params) >= 6:  # Accept/Reject Connection, Remote Name Request
        return f"{name} {_addr(params[:6])}"
    if opcode in (0x0803, 0x0804, 0x080B) and len(params) >= 2:  # Sniff, Exit Sniff, Switch Role
        return f"{name} handle 0x{_u16(params, 0) & 0x0FFF:03X}"
    return name


def describe_event(payload: bytes) -> tuple[str, bool]:
    """Return (description, reports a failure) for an HCI event."""
    if len(payload) < 2:
        return "Event (short)", False
    code, params = payload[0], payload[2:]
    name = EVENT_NAMES.get(code, f"Event 0x{code:02X}")

    if code == 0x0E and len(params) >= 3:  # Command Complete: NumCmds, Opcode, return parameters
        opcode = _u16(params, 1)
        if opcode == 0:
            return "Command Complete (controller ready)", False
        if len(params) < 4:
            return f"Command Complete: {command_name(opcode)}", False
        return f"Command Complete: {command_name(opcode)} - {_status(params[3])}", params[3] != 0
    if code == 0x0F and len(params) >= 4:  # Command Status: Status, NumCmds, Opcode
        opcode = _u16(params, 2)
        state = "started" if params[0] == 0 else _status(params[0])
        return f"Command Status: {command_name(opcode)} - {state}", params[0] != 0
    if code == 0x03 and len(params) >= 9:
        return (f"{name}: {_addr(params[3:9])} handle 0x{_u16(params, 1) & 0x0FFF:03X} - {_status(params[0])}",
                params[0] != 0)
    if code == 0x05 and len(params) >= 4:
        return (f"Disconnected: handle 0x{_u16(params, 1) & 0x0FFF:03X} - "
                f"{HCI_ERROR_CODES.get(params[3], hex(params[3]))}", params[0] != 0)
    if code == 0x2C and len(params) >= 9:
        return f"{name}: {_addr(params[3:9])} - {_status(params[0])}", params[0] != 0
    if code in (0x04, 0x07, 0x12, 0x17, 0x18, 0x31, 0x33, 0x36) and len(params) >= 7:
        start = 1 if code in (0x07, 0x12, 0x36) else 0  # these carry a status first
        text = f"{name}: {_addr(params[start:start + 6])}"
        if code == 0x12 and len(params) >= 8:
            text += f" now {_ROLES.get(params[7], hex(params[7]))}"
        failed = start == 1 and params[0] != 0
        return text + (f" - {_status(params[0])}" if failed else ""), failed
    if code in (0x06, 0x08, 0x59, 0x0B, 0x0C, 0x30) and len(params) >= 3:
        text = f"{name}: handle 0x{_u16(params, 1) & 0x0FFF:03X}"
        if code in (0x08, 0x59) and len(params) >= 4 and params[0] == 0:
            text += " encryption " + ("on" if params[3] else "off")
        return text + f" - {_status(params[0])}", params[0] != 0
    if code == 0x14 and len(params) >= 4:
        return (f"{name}: handle 0x{_u16(params, 1) & 0x0FFF:03X} now {_MODES.get(params[3], hex(params[3]))}"
                + ("" if params[0] == 0 else f" - {_status(params[0])}"), params[0] != 0)
    if code == 0x13 and params:
        sent = sum(_u16(params, 3 + 4 * i) for i in range(params[0]) if 5 + 4 * i <= len(params))
        return f"{name}: {sent} sent", False
    if code == 0x10 and params:
        return f"{name}: code 0x{params[0]:02X}", True
    if code == 0x3E and params:
        sub = params[0]
        sub_name = LE_SUBEVENT_NAMES.get(sub, f"LE Subevent 0x{sub:02X}")
        if sub in _LE_WITH_STATUS and len(params) >= 2:
            text = sub_name
            if sub in (0x01, 0x0A, 0x29) and len(params) >= 12:
                text += f": {_addr(params[6:12])} handle 0x{_u16(params, 2) & 0x0FFF:03X}"
            elif len(params) >= 4:
                text += f": handle 0x{_u16(params, 2) & 0x0FFF:03X}"
            return f"{text} - {_status(params[1])}", params[1] != 0
        return sub_name, False
    return name, False


def describe(packet_type: int, payload: bytes) -> tuple[Optional[str], bool]:
    """Description for commands and events; None for data packets."""
    if packet_type == 0x01:
        return describe_command(payload), False
    if packet_type == 0x04:
        return describe_event(payload)
    return None, False
