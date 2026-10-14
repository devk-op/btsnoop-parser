"""Analysis module for processing BTSnoop statistics."""
from __future__ import annotations

import collections
import datetime
import logging
from typing import Any, Optional

from .constants import HCI_ERROR_CODES, HCI_OPCODE_NAMES

LOG = logging.getLogger(__name__)

_VENDOR_SPECIFIC_OGF = 0x3F
# Failures that are routine on Android and don't affect connectivity.
_BENIGN_FAILURE_OPCODES = {
    0x0C12,  # Delete Stored Link Key: Android keeps keys host-side, controller often has none
    0x0811,  # Sniff Subrating: power-saving tuning, rejected params only cost battery
}
# Entering or leaving sniff (power-saving) mode is refused with Command Disallowed when the link
# is already changing mode; the link settles on its own, so this is not a fault.
_BENIGN_FAILURES = {(0x0803, 0x0C), (0x0804, 0x0C)}


def _command_failure(opcode: int, status: int) -> tuple[str, str]:
    """Return (level, human-readable command name) for a failed command."""
    if opcode >> 10 == _VENDOR_SPECIFIC_OGF:
        return "INFO", f"Vendor-specific command 0x{opcode:04X}"
    name = HCI_OPCODE_NAMES.get(opcode, f"0x{opcode:04X}")
    benign = opcode in _BENIGN_FAILURE_OPCODES or (opcode, status) in _BENIGN_FAILURES
    return ("INFO" if benign else "ERROR"), name


def format_duration(start_time: Optional[datetime.datetime], end_time: Optional[datetime.datetime]) -> str:
    """Render a start/end timestamp pair as a human-readable duration string."""
    if not start_time or not end_time:
        return "N/A"
    diff = end_time - start_time
    total_s = int(diff.total_seconds())
    h, rem = divmod(total_s, 3600)
    m, s = divmod(rem, 60)
    ms = diff.microseconds // 1000
    if h:
        return f"{h}h {m:02d}m {s:02d}.{ms:03d}s"
    if m:
        return f"{m}m {s:02d}.{ms:03d}s"
    return f"{s}.{ms:03d}s"


class CaptureStats:
    """Aggregates statistics for a BTSnoop capture."""

    def __init__(self):
        self.total_packets = 0
        self.packets_by_type: collections.Counter[str] = collections.Counter()
        self.start_time: Optional[datetime.datetime] = None
        self.end_time: Optional[datetime.datetime] = None
        self.total_bytes = 0
        self.devices: dict[str, str] = {}  # Addr -> Name (if known)
        self.lifecycle_events: list[dict[str, Any]] = [] # Connects and Disconnects
        self.issues: list[dict[str, Any]] = []
        self._cis_handles: set[int] = set()
        self._handle_devices: dict[int, str] = {}  # connection handle -> address
        self._cis_devices: dict[int, str] = {}  # LE Audio stream handle -> address of the device it serves

    def _track_device(self, addr: str, name: Optional[str] = None):
        """Register a device address and update its name if available."""
        if not addr or addr == "00:00:00:00:00:00":
            return
        current_name = self.devices.get(addr)
        if name:
            self.devices[addr] = name
        elif not current_name:
            self.devices[addr] = "Unknown"

    def analyze_record(self, record: dict[str, Any]):
        """Ingest a single record and update stats/issues."""
        self.total_packets += 1
        self.total_bytes += record["original_length"]

        ptype = record["packet_type_name"]
        self.packets_by_type[ptype] += 1

        ts = record["timestamp"]
        if self.start_time is None or ts < self.start_time:
            self.start_time = ts
        if self.end_time is None or ts > self.end_time:
            self.end_time = ts

        # LE Create CIS names the connection each audio stream belongs to.
        # Payload: [OpcodeLSB(0), OpcodeMSB(1), Len(2), Count(3), then CISHandle(2) + ACLHandle(2) per stream]
        if record["packet_type"] == 0x01:
            payload = record["payload"]
            if len(payload) >= 4 and payload[0] | (payload[1] << 8) == 0x2064:
                for offset in range(4, min(len(payload), 4 + 4 * payload[3]) - 3, 4):
                    cis_handle = (payload[offset] | (payload[offset + 1] << 8)) & 0x0FFF
                    acl_handle = (payload[offset + 2] | (payload[offset + 3] << 8)) & 0x0FFF
                    if acl_handle in self._handle_devices:
                        self._cis_devices[cis_handle] = self._handle_devices[acl_handle]
            return

        # --- Issue Detection ---
        
        # 1. HCI Event Analysis
        if record["packet_type"] == 0x04:  # EVENT
            payload = record["payload"]
            if len(payload) < 2:
                return
            
            event_code = payload[0]
            
            # --- CONNECTION LIFECYCLE ---

            # Disconnection Complete (0x05)
            # Payload: Status (1), Handle (2), Reason (1)
            # Struct: [Event(0), Len(1), Status(2), HandleLSB(3), HandleMSB(4), Reason(5)]
            if event_code == 0x05 and len(payload) >= 6:
                status = payload[2]
                handle = payload[3] | (payload[4] << 8)
                reason = payload[5]
                reason_str = HCI_ERROR_CODES.get(reason, f"0x{reason:02X}")
                
                # Contextualize "Local Host"
                if reason == 0x16:
                    reason_str += " (Phone/Local)"
                elif reason == 0x13:
                    reason_str += " (Remote Device)"

                # 0x13=Remote User Terminated, 0x14=Remote Low Resources,
                # 0x15=Remote Power Off, 0x16=Local Terminated
                _normal_reasons = (0x00, 0x13, 0x14, 0x15, 0x16)
                is_cis = handle in self._cis_handles
                self._cis_handles.discard(handle)
                self._handle_devices.pop(handle, None)
                self.lifecycle_events.append({
                    "timestamp": ts,
                    "event": "Disconnected (LE Audio)" if is_cis else "Disconnected",
                    "handle": f"0x{handle:03X}",
                    "details": f"Reason: {reason_str}",
                    "is_error": reason not in _normal_reasons,
                })

                if reason not in _normal_reasons:
                     self.issues.append({
                         "timestamp": ts,
                         "level": "WARN",
                         "title": "Abnormal Disconnect",
                         "detail": f"Handle 0x{handle:03X} disconnected: {reason_str}",
                         "code": reason,
                     })

            # LE Meta Event (0x3E) -> LE Connection Complete
            elif event_code == 0x3E and len(payload) >= 3:
                subevent = payload[2]
                # LE Connection Complete (0x01)
                # Payload: [Subevent(2), Status(3), Handle(4,5), Role(6), AddrType(7), Addr(8..13), ...]
                if subevent == 0x01 and len(payload) >= 14:
                    status = payload[3]
                    handle = payload[4] | (payload[5] << 8)
                    bd_addr = ":".join(f"{x:02X}" for x in payload[8:14][::-1])
                    
                    if status == 0x00:
                        self._track_device(bd_addr)
                        self._handle_devices[handle] = bd_addr
                        self.lifecycle_events.append({
                            "timestamp": ts,
                            "event": "Connected (LE)",
                            "handle": f"0x{handle:03X}",
                            "details": f"Device: {bd_addr}",
                            "is_error": False
                        })
                    else:
                        err_str = HCI_ERROR_CODES.get(status, f"0x{status:02X}")
                        self.lifecycle_events.append({
                            "timestamp": ts,
                            "event": "Connect Failed (LE)",
                            "handle": f"0x{handle:03X}",
                            "details": f"Device: {bd_addr} — {err_str}",
                            "is_error": True,
                        })
                        self.issues.append({
                            "timestamp": ts,
                            "level": "WARN",
                            "title": "LE Connection Failed",
                            "detail": f"Failed to connect to {bd_addr}: {err_str}",
                            "code": status,
                        })

                # LE Enhanced Connection Complete (0x0A) - used in Bluetooth 5.x
                elif subevent == 0x0A and len(payload) >= 14:
                    status = payload[3]
                    handle = payload[4] | (payload[5] << 8)
                    # Addr is at 8..13 just like 0x01
                    bd_addr = ":".join(f"{x:02X}" for x in payload[8:14][::-1])
                    
                    if status == 0x00:
                        self._track_device(bd_addr)
                        self._handle_devices[handle] = bd_addr
                        self.lifecycle_events.append({
                            "timestamp": ts,
                            "event": "Connected (LE Enhanced)",
                            "handle": f"0x{handle:03X}",
                            "details": f"Device: {bd_addr}",
                            "is_error": False
                        })
                    else:
                        err_str = HCI_ERROR_CODES.get(status, f"0x{status:02X}")
                        self.lifecycle_events.append({
                            "timestamp": ts,
                            "event": "Connect Failed (LE)",
                            "handle": f"0x{handle:03X}",
                            "details": f"Device: {bd_addr} — {err_str}",
                            "is_error": True,
                        })
                        self.issues.append({
                            "timestamp": ts,
                            "level": "WARN",
                            "title": "LE Connection Failed",
                            "detail": f"Failed to connect to {bd_addr}: {err_str}",
                            "code": status,
                        })

                # LE CIS Request (0x1A) - the other device asks to start an audio stream
                # Payload: [Subevent(2), ACLHandle(3,4), CISHandle(5,6), ...]
                elif subevent == 0x1A and len(payload) >= 7:
                    acl_handle = payload[3] | (payload[4] << 8)
                    if acl_handle in self._handle_devices:
                        self._cis_devices[payload[5] | (payload[6] << 8)] = self._handle_devices[acl_handle]

                # LE CIS Established (0x19) - LE Audio isochronous stream
                # Payload: [Subevent(2), Status(3), Handle(4,5), ...]
                elif subevent == 0x19 and len(payload) >= 6:
                    status = payload[3]
                    handle = payload[4] | (payload[5] << 8)
                    device = self._cis_devices.get(handle)
                    if status == 0x00:
                        self._cis_handles.add(handle)
                        self.lifecycle_events.append({
                            "timestamp": ts,
                            "event": "Connected (LE Audio)",
                            "handle": f"0x{handle:03X}",
                            "details": "Audio stream (CIS) established" + (f" with {device}" if device else ""),
                            "is_error": False,
                            "device": device,
                        })
                    else:
                        err_str = HCI_ERROR_CODES.get(status, f"0x{status:02X}")
                        self.lifecycle_events.append({
                            "timestamp": ts,
                            "event": "Connect Failed (LE Audio)",
                            "handle": f"0x{handle:03X}",
                            "details": f"Audio stream (CIS) — {err_str}",
                            "is_error": True,
                        })
                        self.issues.append({
                            "timestamp": ts,
                            "level": "WARN",
                            "title": "LE Audio Stream Failed",
                            "detail": f"Audio stream on handle 0x{handle:03X} failed: {err_str}",
                            "code": status,
                        })
            
            # Connection Complete (0x03)
            elif event_code == 0x03 and len(payload) >= 13:
                status = payload[2]
                handle = payload[3] | (payload[4] << 8)
                bd_addr = ":".join(f"{x:02X}" for x in payload[5:11][::-1])
                self._track_device(bd_addr)
                
                if status == 0x00:
                    self._handle_devices[handle] = bd_addr
                    self.lifecycle_events.append({
                        "timestamp": ts,
                        "event": "Connected (Classic)",
                        "handle": f"0x{handle:03X}",
                        "details": f"Device: {bd_addr}",
                        "is_error": False
                    })
                else:
                    err_str = HCI_ERROR_CODES.get(status, f"0x{status:02X}")
                    self.lifecycle_events.append({
                        "timestamp": ts,
                        "event": "Connect Failed (Classic)",
                        "handle": f"0x{handle:03X}",
                        "details": f"Device: {bd_addr} — {err_str}",
                        "is_error": True,
                    })
                    self.issues.append({
                        "timestamp": ts,
                        "level": "WARN",
                        "title": "Connection Failed",
                        "detail": f"Failed to connect to {bd_addr}: {err_str}",
                        "code": status,
                    })

            # Synchronous Connection Complete (0x2C)
            elif event_code == 0x2C and len(payload) >= 19:
                status = payload[2]
                handle = payload[3] | (payload[4] << 8)
                bd_addr = ":".join(f"{x:02X}" for x in payload[5:11][::-1])
                self._track_device(bd_addr)
                
                if status == 0x00:
                    self.lifecycle_events.append({
                        "timestamp": ts,
                        "event": "Connected (Sync)",
                        "handle": f"0x{handle:03X}",
                        "details": f"Device: {bd_addr}",
                        "is_error": False
                    })

            # --- OTHER EVENTS ---

            # Command Complete (0x0E)
            elif event_code == 0x0E and len(payload) >= 6:
                opcode = payload[3] | (payload[4] << 8)
                status = payload[5]
                if status != 0x00:
                    err_str = HCI_ERROR_CODES.get(status, f"0x{status:02X}")
                    level, opcode_name = _command_failure(opcode, status)
                    self.issues.append({
                        "timestamp": ts,
                        "level": level,
                        "title": "Command Failure",
                        "detail": f"{opcode_name} failed: {err_str}",
                        "code": status,
                    })

            # Command Status (0x0F)
            elif event_code == 0x0F and len(payload) >= 6:
                status = payload[2]
                opcode = payload[4] | (payload[5] << 8)
                if status != 0x00:
                    err_str = HCI_ERROR_CODES.get(status, f"0x{status:02X}")
                    level, opcode_name = _command_failure(opcode, status)
                    self.issues.append({
                        "timestamp": ts,
                        "level": level,
                        "title": "Command Status Error",
                        "detail": f"{opcode_name} returned status {err_str}",
                        "code": status,
                    })

            # Authentication Complete (0x06) failed: [Event, Len, Status, Handle(2)]
            elif event_code == 0x06 and len(payload) >= 5 and payload[2] != 0x00:
                status = payload[2]
                handle = payload[3] | (payload[4] << 8)
                self.issues.append({
                    "timestamp": ts,
                    "level": "WARN",
                    "title": "Authentication Failed",
                    "detail": f"Handle 0x{handle:03X} could not authenticate: "
                              f"{HCI_ERROR_CODES.get(status, f'0x{status:02X}')}",
                    "code": status,
                })

            # Simple Pairing Complete (0x36) failed: [Event, Len, Status, Addr(6)]
            elif event_code == 0x36 and len(payload) >= 9 and payload[2] != 0x00:
                status = payload[2]
                bd_addr = ":".join(f"{x:02X}" for x in payload[3:9][::-1])
                self.issues.append({
                    "timestamp": ts,
                    "level": "WARN",
                    "title": "Pairing Failed",
                    "detail": f"Pairing with {bd_addr} failed: {HCI_ERROR_CODES.get(status, f'0x{status:02X}')}",
                    "code": status,
                })

            # Hardware Error (0x10)
            # Payload: [Event(0), Len(1), HardwareCode(2)]
            elif event_code == 0x10 and len(payload) >= 3:
                code = payload[2]
                self.issues.append({
                     "timestamp": ts,
                     "level": "CRITICAL",
                     "title": "Hardware Error",
                     "detail": f"Controller reported hardware error code 0x{code:02X}"
                 })


    def print_summary(self, color: bool = True):
        """Print a summary to stdout (ANSI-colored unless color=False)."""
        if color:
            BOLD, RED, YELLOW, GREEN, CYAN, DIM, RESET = (
                "\033[1m", "\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[2m", "\033[0m"
            )
        else:
            BOLD = RED = YELLOW = GREEN = CYAN = DIM = RESET = ""

        duration = format_duration(self.start_time, self.end_time)

        print(f"\n{BOLD} Capture Statistics ───{RESET}")
        print(f"  {BOLD}Duration:{RESET}      {duration}")
        print(f"  {BOLD}Total Packets:{RESET} {self.total_packets:,}")
        print(f"  {BOLD}Data Volume:{RESET}   {self.total_bytes / 1024:.2f} KB")

        print(f"\n{BOLD}Packet Types:{RESET}")
        for ptype, count in self.packets_by_type.most_common():
            print(f"  {ptype:<15} {count:>8,}")

        if self.devices:
            print(f"\n{BOLD}Detected Devices:{RESET}")
            for addr, name in self.devices.items():
                print(f"  {CYAN}{addr}{RESET}  {name}")

        if self.lifecycle_events:
            print(f"\n{BOLD}Connection History:{RESET}")
            # Sort by timestamp just in case
            self.lifecycle_events.sort(key=lambda x: x["timestamp"])
            
            for evt in self.lifecycle_events:
                local_ts = evt["timestamp"].astimezone()
                t_str = local_ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                
                etype = evt["event"]
                handle = evt["handle"]
                details = evt["details"]
                is_err = evt["is_error"]
                
                # Colors
                c_evt = GREEN if "Connected" in etype else (RED if is_err else YELLOW)
                
                print(f"  {t_str} {c_evt}{etype:<24}{RESET} {handle} -> {details}")

        # Abnormal disconnects are already highlighted in the connection history.
        shown = [i for i in self.issues if i["title"] != "Abnormal Disconnect"]
        problems = [i for i in shown if i["level"] != "INFO"]
        notes = [i for i in shown if i["level"] == "INFO"]

        def _print_issues(items, colour_for):
            for issue in items:
                t_str = issue["timestamp"].astimezone().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                c = colour_for(issue["level"])
                print(f"  {c}[{issue['level']}] {t_str} - {issue['title']}{RESET}: {issue['detail']}")

        if problems:
            print(f"\n{BOLD}Potential Issues ({len(problems)}):{RESET}")
            _print_issues(problems, lambda lvl: RED if lvl in ("ERROR", "CRITICAL") else YELLOW)
        elif not any(i["title"] == "Abnormal Disconnect" for i in self.issues):
            print(f"\n{BOLD}{GREEN}No obvious issues detected.{RESET}")

        if notes:
            print(f"\n{BOLD}Informational ({len(notes)}):{RESET} {DIM}routine failures, usually harmless{RESET}")
            _print_issues(notes, lambda lvl: DIM)
