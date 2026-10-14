"""L2CAP reassembly and channel tracking.

ACL packets carry L2CAP frames, possibly split across several packets. Each
frame is addressed to a channel id (CID). A few CIDs are fixed (signaling, ATT,
SMP); the rest are allocated at runtime by a signaling exchange that names the
protocol (PSM) the channel will carry. :class:`L2capDecoder` reassembles the
frames and follows that signaling, so every frame can be labelled with the
protocol it belongs to.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

PSM_NAMES = {
    0x0001: "SDP",
    0x0003: "RFCOMM",
    0x000F: "BNEP",
    0x0011: "HID Control",
    0x0013: "HID Interrupt",
    0x0017: "AVCTP",
    0x0019: "AVDTP",
    0x001B: "AVCTP Browsing",
    0x001F: "ATT",
    0x0023: "IPSP",
    0x0025: "OTS",
    0x0027: "EATT",
}

FIXED_CID_NAMES = {
    0x0001: "L2CAP Signaling",
    0x0002: "Connectionless",
    0x0004: "ATT",
    0x0005: "L2CAP Signaling",
    0x0006: "SMP",
    0x0007: "SMP",
}

_SIGNALING_CIDS = (0x0001, 0x0005)

_CONNECT_RESULTS = {
    0x0002: "PSM not supported",
    0x0003: "security block",
    0x0004: "no resources available",
    0x0006: "invalid source CID",
    0x0007: "source CID already allocated",
}

# LE credit-based results use a different numbering from the classic ones.
_LE_CONNECT_RESULTS = {
    0x0002: "PSM not supported",
    0x0004: "no resources available",
    0x0005: "insufficient authentication",
    0x0006: "insufficient authorization",
    0x0007: "encryption key size too short",
    0x0008: "insufficient encryption",
    0x0009: "invalid source CID",
    0x000A: "source CID already allocated",
    0x000B: "unacceptable parameters",
}


def psm_name(psm: int) -> str:
    return PSM_NAMES.get(psm, f"PSM 0x{psm:04X}")


def _u16(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8)


def _other(direction: str) -> str:
    return "RX" if direction == "TX" else "TX"


@dataclass
class L2capFrame:
    """One reassembled L2CAP frame."""

    index: int
    timestamp: datetime.datetime
    direction: str
    handle: int
    cid: int
    psm: Optional[int]
    protocol: str
    payload: bytes
    # The frame's length as declared in its header; larger than len(payload) when truncated.
    length: int = 0
    # True when the capture stored only the start of the frame (Android's filtered snoop mode).
    truncated: bool = False
    # 0 for the first channel opened for this PSM on the connection, 1 for the second, ...
    channel_index: Optional[int] = None
    # (text, is_error) pairs describing channel setup/teardown carried by a signaling frame.
    notes: list[tuple[str, bool]] = field(default_factory=list)


class L2capDecoder:
    """Reassemble L2CAP frames from ACL records and label them by protocol."""

    def __init__(self) -> None:
        # (handle, direction) -> [first record index, expected total length, buffer]
        self._partial: dict[tuple[int, str], list[Any]] = {}
        # (handle, direction the data travels) -> {cid: psm}
        self._channels: dict[tuple[int, str], dict[int, int]] = {}
        # (handle, direction of the request, identifier) -> (psm, source CIDs)
        self._pending: dict[tuple[int, str, int], tuple[int, list[int]]] = {}
        # (handle, direction the data travels) -> {cid: position among channels opened for its PSM}
        self._order: dict[tuple[int, str], dict[int, int]] = {}

    def forget_handle(self, handle: int) -> None:
        """Drop all state for a connection handle (call when it disconnects)."""
        for store in (self._partial, self._channels, self._pending, self._order):
            for key in [k for k in store if k[0] == handle]:
                del store[key]

    def feed(self, record: Mapping[str, Any]) -> Optional[L2capFrame]:
        """Ingest one ACL record; return a frame once it is complete."""
        data = record["payload"]
        if record["packet_type"] != 0x02 or len(data) < 4:
            return None
        handle = _u16(data, 0) & 0x0FFF
        boundary = (data[1] >> 4) & 0x03
        fragment = data[4:]
        key = (handle, record["direction"])

        if boundary == 0x01:  # continuation
            partial = self._partial.get(key)
            if partial is None:
                return None  # capture started mid-frame
            partial[2] += fragment
        else:
            partial = [record["index"], None, bytearray(fragment)]
            self._partial[key] = partial

        buffer = partial[2]
        if partial[1] is None and len(buffer) >= 4:
            partial[1] = _u16(buffer, 0) + 4
        # A record the capture cut short will never be completed by later fragments.
        truncated = record.get("captured_length", 0) < record.get("original_length", 0)
        if partial[1] is None or (len(buffer) < partial[1] and not truncated):
            return None

        del self._partial[key]
        if partial[1] is None:
            return None
        cid = _u16(buffer, 2)
        payload = bytes(buffer[4:partial[1]])
        psm = self._channels.get(key, {}).get(cid)
        if cid in FIXED_CID_NAMES:
            protocol = FIXED_CID_NAMES[cid]
        elif psm is not None:
            protocol = psm_name(psm)
        else:
            protocol = "L2CAP"  # channel was opened before the capture started
        frame = L2capFrame(
            index=partial[0],
            timestamp=record["timestamp"],
            direction=record["direction"],
            handle=handle,
            cid=cid,
            psm=psm,
            protocol=protocol,
            payload=payload,
            length=partial[1] - 4,
            truncated=len(payload) < partial[1] - 4,
            channel_index=self._order.get(key, {}).get(cid),
        )
        if cid in _SIGNALING_CIDS:
            self._signaling(frame)
        return frame

    def _signaling(self, frame: L2capFrame) -> None:
        data = frame.payload
        offset = 0
        while offset + 4 <= len(data):
            code, ident = data[offset], data[offset + 1]
            length = _u16(data, offset + 2)
            body = data[offset + 4:offset + 4 + length]
            offset += 4 + length
            self._command(frame, code, ident, body)

    def _open(self, frame: L2capFrame, psm: int, scid: int, dcid: int) -> None:
        # The requester receives on its source CID; the responder (this frame's sender) on the destination CID.
        # A2DP tells its channels apart by order: the first AVDTP channel open on a link is signaling.
        position = sum(1 for p in self._channels.get((frame.handle, frame.direction), {}).values() if p == psm)
        self._channels.setdefault((frame.handle, frame.direction), {})[scid] = psm
        self._channels.setdefault((frame.handle, _other(frame.direction)), {})[dcid] = psm
        self._order.setdefault((frame.handle, frame.direction), {})[scid] = position
        self._order.setdefault((frame.handle, _other(frame.direction)), {})[dcid] = position
        frame.notes.append((f"{psm_name(psm)} channel opened", False))

    def _command(self, frame: L2capFrame, code: int, ident: int, body: bytes) -> None:
        handle, direction = frame.handle, frame.direction
        request_key = (handle, _other(direction), ident)

        if code == 0x02 and len(body) >= 4:  # Connection Request
            self._pending[(handle, direction, ident)] = (_u16(body, 0), [_u16(body, 2)])

        elif code == 0x03 and len(body) >= 8:  # Connection Response
            dcid, scid, result = _u16(body, 0), _u16(body, 2), _u16(body, 4)
            if result == 0x0001:  # pending: the final answer comes in a later response
                return
            pending = self._pending.pop(request_key, None)
            if pending is None:
                return
            psm = pending[0]
            if result == 0x0000:
                self._open(frame, psm, scid, dcid)
            else:
                reason = _CONNECT_RESULTS.get(result, f"result 0x{result:04X}")
                frame.notes.append((f"{psm_name(psm)} channel refused: {reason}", True))

        elif code == 0x06 and len(body) >= 4:  # Disconnection Request
            dcid, scid = _u16(body, 0), _u16(body, 2)
            psm = self._channels.get((handle, direction), {}).pop(dcid, None)
            self._channels.get((handle, _other(direction)), {}).pop(scid, None)
            self._order.get((handle, direction), {}).pop(dcid, None)
            self._order.get((handle, _other(direction)), {}).pop(scid, None)
            if psm is not None:
                frame.notes.append((f"{psm_name(psm)} channel closed", False))

        elif code == 0x14 and len(body) >= 4:  # LE Credit Based Connection Request
            self._pending[(handle, direction, ident)] = (_u16(body, 0), [_u16(body, 2)])

        elif code == 0x15 and len(body) >= 10:  # LE Credit Based Connection Response
            pending = self._pending.pop(request_key, None)
            if pending is None:
                return
            psm, scids = pending
            result = _u16(body, 8)
            if result == 0x0000:
                self._open(frame, psm, scids[0], _u16(body, 0))
            else:
                reason = _LE_CONNECT_RESULTS.get(result, f"result 0x{result:04X}")
                frame.notes.append((f"{psm_name(psm)} channel refused: {reason}", True))

        elif code == 0x17 and len(body) >= 10:  # Enhanced Credit Based Connection Request
            scids = [_u16(body, i) for i in range(8, len(body) - 1, 2)]
            self._pending[(handle, direction, ident)] = (_u16(body, 0), scids)

        elif code == 0x18 and len(body) >= 8:  # Enhanced Credit Based Connection Response
            pending = self._pending.pop(request_key, None)
            if pending is None:
                return
            psm, scids = pending
            dcids = [_u16(body, i) for i in range(8, len(body) - 1, 2)]
            opened = [(s, d) for s, d in zip(scids, dcids) if d != 0]
            for scid, dcid in opened:
                self._open(frame, psm, scid, dcid)
            if not opened:
                result = _u16(body, 6)
                reason = _LE_CONNECT_RESULTS.get(result, f"result 0x{result:04X}")
                frame.notes.append((f"{psm_name(psm)} channel refused: {reason}", True))
