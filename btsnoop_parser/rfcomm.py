"""RFCOMM frame decoding.

RFCOMM emulates serial ports over one L2CAP channel. Each port is a DLCI;
DLCI 0 is the multiplexer's own control channel. Profiles such as HFP send
their data in UIH frames on a non-zero DLCI.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

FRAME_TYPES = {
    0x2F: "SABM",  # open a channel
    0x63: "UA",    # accept
    0x0F: "DM",    # refuse / already closed
    0x43: "DISC",  # close a channel
    0xEF: "UIH",   # data
}


@dataclass
class RfcommFrame:
    dlci: int
    frame_type: str
    payload: bytes

    @property
    def channel(self) -> int:
        """Server channel number (the number SDP records advertise)."""
        return self.dlci >> 1


def parse_frame(data: bytes) -> Optional[RfcommFrame]:
    """Decode one RFCOMM frame, or return None if it is malformed."""
    if len(data) < 4:
        return None
    dlci = data[0] >> 2
    control = data[1]
    frame_type = FRAME_TYPES.get(control & 0xEF)
    if frame_type is None:
        return None

    if data[2] & 0x01:
        length, offset = data[2] >> 1, 3
    else:
        length, offset = (data[2] >> 1) | (data[3] << 7), 4
    # A UIH frame with the poll/final bit set carries one byte of flow-control credits first.
    if control == 0xFF and dlci != 0:
        offset += 1
    payload = data[offset:offset + length]
    if len(payload) < length:
        return None
    return RfcommFrame(dlci=dlci, frame_type=frame_type, payload=payload)
