
from __future__ import annotations

import collections
import datetime
import logging
from typing import Any, Optional

from .constants import HCI_ERROR_CODES

LOG = logging.getLogger(__name__)


class CaptureStats:
    """Aggregates statistics for a BTSnoop capture."""

    def __init__(self):
        self.total_packets = 0
        self.packets_by_type: collections.Counter[str] = collections.Counter()
        self.error_events: collections.Counter[str] = collections.Counter()
        self.start_time: Optional[datetime.datetime] = None
        self.end_time: Optional[datetime.datetime] = None
        self.total_bytes = 0
        self.devices: dict[str, str] = {}  # Addr -> Name (if known)
        self.disconnects: list[dict[str, Any]] = []
        self.issues: list[dict[str, Any]] = []

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

        # --- Issue Detection ---
        
        # 1. HCI Event Analysis
        if record["packet_type"] == 0x04:  # EVENT
            payload = record["payload"]
            if len(payload) < 2:
                return
            
            event_code = payload[0]
            
            # Disconnection Complete (0x05)
            # Payload: Status (1), Handle (2), Reason (1)
            # Struct: [Event(0), Len(1), Status(2), HandleLSB(3), HandleMSB(4), Reason(5)]
            if event_code == 0x05 and len(payload) >= 6:
                status = payload[2]
                handle = payload[3] | (payload[4] << 8)
                reason = payload[5]
                reason_str = HCI_ERROR_CODES.get(reason, f"0x{reason:02X}")
                
                # If reason is normal, it's just a log. If it's a timeout/error, it's an issue.
                issue_entry = {
                    "timestamp": ts,
                    "type": "Disconnect",
                    "handle": f"0x{handle:03X}",
                    "reason": reason_str,
                    "reason_code": reason,
                    "is_error": reason not in (0x13, 0x16, 0x00) # 0x13=Remote User Terminated, 0x16=Local Terminated
                }
                self.disconnects.append(issue_entry)
                
                if issue_entry["is_error"]:
                     self.issues.append({
                         "timestamp": ts,
                         "level": "WARN",
                         "title": "Abnormal Disconnect",
                         "detail": f"Handle 0x{handle:03X} disconnected: {reason_str}"
                     })

            # Command Complete (0x0E) - check for non-zero status
            # Struct: [Event(0), Len(1), NumHCI(2), OpcodeLSB(3), OpcodeMSB(4), ReturnParams...(5)]
            elif event_code == 0x0E and len(payload) >= 6:
                # num_hci = payload[2]
                opcode = payload[3] | (payload[4] << 8)
                # Status is usually the first return parameter at index 5
                # But some commands don't return status. However, most failure items do.
                if len(payload) > 5:
                    status = payload[5]
                    if status != 0x00:
                        err_str = HCI_ERROR_CODES.get(status, f"0x{status:02X}")
                        self.issues.append({
                             "timestamp": ts,
                             "level": "ERROR",
                             "title": "Command Failure",
                             "detail": f"Opcode 0x{opcode:04X} failed with status {err_str}"
                         })

            # Command Status (0x0F) - check for non-zero status
            # Struct: [Event(0), Len(1), Status(2), NumHCI(3), OpcodeLSB(4), OpcodeMSB(5)]
            elif event_code == 0x0F and len(payload) >= 6:
                status = payload[2]
                opcode = payload[4] | (payload[5] << 8)
                if status != 0x00:
                    err_str = HCI_ERROR_CODES.get(status, f"0x{status:02X}")
                    self.issues.append({
                         "timestamp": ts,
                         "level": "ERROR",
                         "title": "Command Status Error",
                         "detail": f"Opcode 0x{opcode:04X} returned status {err_str}"
                     })
            
            # Connection Complete (0x03) - check for failure
            # Struct: [Event(0), Len(1), Status(2), HandleLSB(3), HandleMSB(4), BD_ADDR(6 bytes)...]
            elif event_code == 0x03 and len(payload) >= 13:
                status = payload[2]
                handle = payload[3] | (payload[4] << 8)
                # Address is 6 bytes at 5..10 inclusive (slice 5:11)
                bd_addr = ":".join(f"{x:02X}" for x in payload[5:11][::-1])
                self._track_device(bd_addr)
                
                if status != 0x00:
                    err_str = HCI_ERROR_CODES.get(status, f"0x{status:02X}")
                    self.issues.append({
                         "timestamp": ts,
                         "level": "WARN",
                         "title": "Connection Failed",
                         "detail": f"Failed to connect to {bd_addr}: {err_str}"
                     })

            # Page Timeout (often seen as a dedicated error or just a failure to connect)
            
            # Hardware Error (0x10)
            elif event_code == 0x10 and len(payload) >= 2:
                code = payload[1]
                self.issues.append({
                     "timestamp": ts,
                     "level": "CRITICAL",
                     "title": "Hardware Error",
                     "detail": f"Controller reported hardware error code 0x{code:02X}"
                 })


    def print_summary(self):
        """Print a colored summary to stdout."""
        # Simple ANSI colors
        BOLD = "\033[1m"
        RED = "\033[91m"
        YELLOW = "\033[93m"
        GREEN = "\033[92m"
        CYAN = "\033[96m"
        RESET = "\033[0m"

        duration = "N/A"
        if self.start_time and self.end_time:
            diff = self.end_time - self.start_time
            duration = str(diff)

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

        if self.issues:
            print(f"\n{BOLD}Potential Issues ({len(self.issues)}):{RESET}")
            for issue in self.issues:
                color = RED if issue["level"] in ("ERROR", "CRITICAL") else YELLOW
                t_str = issue["timestamp"].strftime("%H:%M:%S.%f")[:-3]
                print(f"  {color}[{issue['level']}] {t_str} - {issue['title']}{RESET}: {issue['detail']}")
        else:
            print(f"\n{BOLD}{GREEN}No obvious issues detected.{RESET}")

        if self.disconnects:
            print(f"\n{BOLD}Disconnections:{RESET}")
            for d in self.disconnects:
                reason = d["reason"]
                color = RED if d["is_error"] else GREEN
                t_str = d["timestamp"].strftime("%H:%M:%S.%f")[:-3]
                print(f"  {t_str} Handle {d['handle']} -> {color}{reason}{RESET}")
