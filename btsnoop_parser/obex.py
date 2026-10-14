"""Phonebook (PBAP) and message (MAP) sync activity over OBEX.

Cars and watches download the phone's contacts, call history and messages
with OBEX, carried here over L2CAP channels in Enhanced Retransmission Mode.
This module reports the activity only: which service, what was requested,
how many entries came back, how much data, how long it took, and whether it
failed. Contact details and message text are never decoded; entries are
counted by their record markers.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Optional

SERVICES = {
    bytes.fromhex("796135f0f0c511d809660800200c9a66"): "Phonebook (PBAP)",
    bytes.fromhex("bb582b40420c11dbb0de0800200c9a66"): "Messages (MAP)",
    bytes.fromhex("bb582b41420c11dbb0de0800200c9a66"): "Message alerts (MAP)",
    bytes.fromhex("f9ec7bc4953c11d2984e525400dc9e09"): "File transfer (FTP)",
}

_REQUESTS = {0x80: "Connect", 0x81: "Disconnect", 0x02: "Put", 0x82: "Put", 0x03: "Get", 0x83: "Get",
             0x85: "Set folder", 0xFF: "Abort"}
_RESPONSES = {
    0x90: "continue", 0xA0: "ok", 0xC0: "bad request", 0xC1: "unauthorized", 0xC3: "forbidden",
    0xC4: "not found", 0xC5: "not allowed", 0xC6: "not acceptable", 0xCF: "unsupported type",
    0xD0: "internal error", 0xD1: "not implemented", 0xD3: "service unavailable",
}

# What a request is for, from its Type header.
_TYPES = {
    b"x-bt/phonebook": ("phonebook", b"BEGIN:VCARD"),
    b"x-bt/vcard-listing": ("contact list", b"<card"),
    b"x-bt/vcard": ("single contact", None),
    b"x-bt/MAP-msg-listing": ("message list", b"<msg"),
    b"x-bt/message": ("single message", None),
    b"x-bt/MAPfolder-listing": ("folder list", b"<folder"),
    b"x-bt/MAP-NotificationRegistration": ("new-message alerts setting", None),
    b"x-bt/MAP-event-report": ("new-message alert", None),
    b"x-bt/MAP-messageUpdate": ("message update", None),
    b"x-bt/MASInstanceInformation": ("message account info", None),
    b"x-bt/MAP-notification-filter": ("new-message alerts filter", None),
    b"x-bt/messageStatus": ("message status change", None),
    b"x-obex/folder-listing": ("folder list", b"<file"),
}

# Phonebook object names (telecom/pb.vcf, SIM1/telecom/ich.vcf, ...).
_PHONEBOOKS = {"pb": "contacts", "ich": "incoming calls", "och": "outgoing calls", "mch": "missed calls",
               "cch": "call history", "spd": "speed dial", "fav": "favourites"}


def _headers(data: bytes) -> dict[int, bytes]:
    """OBEX headers as id -> value (only those fully present)."""
    found, offset = {}, 0
    while offset < len(data):
        header = data[offset]
        kind = header >> 6
        if kind in (0, 1):
            if offset + 3 > len(data):
                break
            length = int.from_bytes(data[offset + 1:offset + 3], "big")
            if length < 3 or offset + length > len(data):
                break
            found[header] = data[offset + 3:offset + length]
            offset += length
        else:
            size = 1 if kind == 2 else 4
            found[header] = data[offset + 1:offset + 1 + size]
            offset += 1 + size
    return found


def _phonebook_name(name: str) -> Optional[str]:
    leaf = name.rsplit("/", 1)[-1].lower()
    stem = leaf[:-4] if leaf.endswith(".vcf") else leaf
    return _PHONEBOOKS.get(stem)


@dataclass
class Transfer:
    """Totals for one kind of request on one connection."""

    what: str
    requests: int = 0
    failures: list[str] = field(default_factory=list)
    entries: int = 0
    size: int = 0
    first: Optional[datetime.datetime] = None
    last: Optional[datetime.datetime] = None


@dataclass
class ObexChannel:
    """One OBEX session on one L2CAP channel."""

    service: Optional[str] = None
    client: Optional[str] = None  # direction the requests travel
    transfers: dict[str, Transfer] = field(default_factory=dict)
    _current: Optional[Transfer] = None
    _marker: Optional[bytes] = None
    _pending: Optional[str] = None  # request awaiting its answer
    _last_request: Optional[str] = None  # with single-response mode one request gets many answers

    def feed(self, direction: str, payload: bytes, when: datetime.datetime) -> Optional[tuple[str, str, bool]]:
        """Ingest one ERTM frame; return (summary, detail, is_error) for connects, failures and endings."""
        if len(payload) < 2 or payload[0] & 0x01:
            return None  # supervisory frame: acknowledgements only
        sar = (payload[1] >> 6) & 0x03
        data = payload[4:] if sar == 1 else payload[2:]
        if sar in (2, 3):  # continuation of a long OBEX packet
            if direction != self.client:
                self._count(data)
            return None
        if len(data) < 3:
            return None
        code = data[0]
        if self.client is None and code == 0x80:
            self.client = direction
        if direction == self.client:
            return self._request(code, data, when)
        return self._response(code, data, when)

    def _count(self, data: bytes) -> None:
        if self._current is None:
            return
        self._current.size += len(data)
        if self._marker:
            self._current.entries += data.count(self._marker)

    def _request(self, code: int, data: bytes, when: datetime.datetime) -> Optional[tuple[str, str, bool]]:
        name = _REQUESTS.get(code)
        if name is None:
            return None
        self._pending = self._last_request = name
        if code == 0x80:
            headers = _headers(data[7:])
            self.service = SERVICES.get(headers.get(0x46, b""), "Object push" if 0x46 not in headers else "OBEX")
            return None
        if code == 0x81:
            return ("Disconnect", f"{self.service or 'OBEX'}: session closed", False)
        if code not in (0x02, 0x82, 0x03, 0x83):
            return None
        headers = _headers(data[3:])
        kind = headers.get(0x42, b"").rstrip(b"\x00")
        if kind or self._current is None:
            what, marker = _TYPES.get(kind, (kind.decode("ascii", "replace") or "object", None))
            object_name = headers.get(0x01, b"").decode("utf-16-be", "replace").rstrip("\x00")
            book = _phonebook_name(object_name) if what == "phonebook" else None
            what = f"{what} ({book})" if book else what
            self._current = self.transfers.setdefault(what, Transfer(what))
            self._marker = marker
            self._current.requests += 1
            self._current.first = self._current.first or when
        self._current.last = when
        return None

    def _response(self, code: int, data: bytes, when: datetime.datetime) -> Optional[tuple[str, str, bool]]:
        request, self._pending = self._pending, None
        if request == "Connect":
            if code == 0xA0:
                return ("Connect", f"{self.service or 'OBEX'} session opened", False)
            reason = _RESPONSES.get(code, f"0x{code:02X}")
            return ("Connect", f"{self.service or 'OBEX'} session refused: {reason}", True)
        if self._current is None or self._last_request not in ("Get", "Put"):
            return None
        self._current.last = when
        self._count(data[3:])
        if code not in (0x90, 0xA0):
            reason = _RESPONSES.get(code & 0x7F | 0x80, f"0x{code:02X}")
            self._current.failures.append(reason)
            return ("Failed", f"{self.service or 'OBEX'}: {self._current.what} request failed: {reason}", True)
        return None


def describe_transfer(transfer: Transfer) -> str:
    """One line: what was synced, how many entries, how much data, how long."""
    parts = []
    if transfer.entries:
        parts.append(f"{transfer.entries:,} entries")
    elif transfer.what.startswith("single"):
        ok = transfer.requests - len(transfer.failures)
        parts.append(f"{ok:,} downloaded")
    elif transfer.requests > 1:
        parts.append(f"{transfer.requests:,} requests")
    if transfer.size >= 1024:
        parts.append(f"{transfer.size / 1024:.0f} KB")
    if transfer.first and transfer.last and transfer.last > transfer.first:
        seconds = (transfer.last - transfer.first).total_seconds()
        length = f"{seconds:.1f} s" if seconds < 60 else f"{seconds / 60:.1f} min"
        if seconds >= 0.05:
            parts.append(f"over {length}" if transfer.requests > 1 else f"took {length}")
    if transfer.failures:
        parts.append(f"{len(transfer.failures)} failed ({transfer.failures[0]})")
    return f"{transfer.what}: " + (", ".join(parts) if parts else "requested")
