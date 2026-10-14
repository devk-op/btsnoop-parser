"""Protocol-level training sessions: music, controls, calls, sync, LE Audio, Android Auto.

Each scenario writes the packets a real phone and device exchange (L2CAP
channel set-up, AVDTP, AVRCP, HFP over RFCOMM, OBEX, ATT, the Android Auto
start-up messages) and runs them through the real ReportBuilder, so the
"Device Activity" section the model sees is exactly what --ai produces.
Answers are written from that report, not from the scenario's intent.

Names, numbers and contacts in these sessions are invented.
"""
from __future__ import annotations

import datetime
import random
import struct
from dataclasses import dataclass

from btsnoop_parser.android_auto import SERVICE_UUID

from training.generate_dataset import Session

_PBAP = bytes.fromhex("796135f0f0c511d809660800200c9a66")
_MAP = bytes.fromhex("bb582b40420c11dbb0de0800200c9a66")
_SBC_CAPS = bytes([0x07, 0x06, 0x00, 0x00, 0xFF, 0xFF, 0x02, 0xFA])
_SBC_CONFIG = bytes([0x07, 0x06, 0x00, 0x00, 0x21, 0x15, 0x02, 0x35])
_AAC_CAPS = bytes([0x07, 0x08, 0x00, 0x02, 0x80, 0x01, 0x8C, 0x84, 0xE2, 0x00])
_AAC_CONFIG = bytes([0x07, 0x08, 0x00, 0x02, 0x80, 0x01, 0x04, 0x84, 0xE2, 0x00])
_WORDS = ["Blue", "Night", "River", "Summer", "Echo", "Golden", "Rain", "City", "Fire", "Ocean", "Paper", "Wild",
          "Silver", "Dream", "Light", "Road", "Heart", "Storm", "Velvet", "Neon"]
_NAMES = {"car": ["MyCar", "Car Audio", "CarPlay Unit", "Family SUV", "Head Unit"],
          "headset": ["Buds Pro", "Earbuds", "Headphones X", "Sport Buds", "Studio Cans"],
          "speaker": ["Party Speaker", "Mini Boom", "Soundbar"]}

# AVDTP set-up rejections and LE Audio stream-control failures the scenarios draw from.
A2DP_REJECTS = [0xC2, 0xC3, 0xC6, 0x29, 0x31, 0x13, 0xD4]
ASE_FAILURES = [(0x06, 0x00), (0x07, 0x02), (0x08, 0x02), (0x0D, 0x00), (0x04, 0x00), (0x09, 0x03)]
AA_FAILURES = [-1, -2, -3, -5, -10, -11]


@dataclass
class Channel:
    handle: int
    phone_cid: int
    device_cid: int


class ProfileSession(Session):
    """A Session that can also write the ACL traffic of each profile."""

    def __init__(self, rng: random.Random):
        super().__init__(rng)
        self._next_cid = 0x40
        self._label = 0

    # --- L2CAP -------------------------------------------------------------------------------------

    def acl(self, handle: int, direction: str, cid: int, payload: bytes, gap: float = 0.01) -> None:
        frame = struct.pack("<HH", len(payload), cid) + payload
        self._add(0x02, struct.pack("<HH", handle | 0x2000, len(frame)) + frame, gap, direction)

    def send(self, channel: Channel, direction: str, payload: bytes, gap: float = 0.01) -> None:
        cid = channel.device_cid if direction == "TX" else channel.phone_cid
        self.acl(channel.handle, direction, cid, payload, gap)

    def open_channel(self, handle: int, psm: int, phone_starts: bool) -> Channel:
        phone_cid, self._next_cid = self._next_cid, self._next_cid + 1
        device_cid = self.rng.randrange(0x40, 0x80)
        ident = self.rng.randrange(1, 255)
        if phone_starts:
            self.acl(handle, "TX", 0x0001, struct.pack("<BBHHH", 0x02, ident, 4, psm, phone_cid))
            self.acl(handle, "RX", 0x0001, struct.pack("<BBHHHHH", 0x03, ident, 8, device_cid, phone_cid, 0, 0))
        else:
            self.acl(handle, "RX", 0x0001, struct.pack("<BBHHH", 0x02, ident, 4, psm, device_cid))
            self.acl(handle, "TX", 0x0001, struct.pack("<BBHHHHH", 0x03, ident, 8, phone_cid, device_cid, 0, 0))
        return Channel(handle, phone_cid, device_cid)

    # --- A2DP ----------------------------------------------------------------------------------------

    def _avdtp(self, channel: Channel, direction: str, message_type: int, signal: int, body: bytes = b"",
               gap: float = 0.01) -> None:
        self.send(channel, direction, bytes([(self._label << 4) | message_type, signal]) + body, gap)

    def a2dp_setup(self, handle: int, codec: str, reject: int | None = None) -> tuple[Channel, Channel | None]:
        sig = self.open_channel(handle, 0x0019, phone_starts=True)
        self._label = (self._label + 1) % 16
        self._avdtp(sig, "TX", 0, 0x01)
        self._avdtp(sig, "RX", 2, 0x01, bytes([0x04, 0x08]))
        self._avdtp(sig, "TX", 0, 0x0C, bytes([0x04]))
        caps = _SBC_CAPS + (_AAC_CAPS if codec == "AAC" else b"") + bytes([0x01, 0x00, 0x08, 0x00])
        self._avdtp(sig, "RX", 2, 0x0C, caps)
        config = _AAC_CONFIG if codec == "AAC" else _SBC_CONFIG
        self._label = (self._label + 1) % 16
        self._avdtp(sig, "TX", 0, 0x03, bytes([0x04, 0x04, 0x01, 0x00]) + config)
        if reject is not None:
            self._avdtp(sig, "RX", 3, 0x03, bytes([0x07, reject]), gap=0.02)
            return sig, None
        self._avdtp(sig, "RX", 2, 0x03)
        self._label = (self._label + 1) % 16
        self._avdtp(sig, "TX", 0, 0x06, bytes([0x04]))
        self._avdtp(sig, "RX", 2, 0x06)
        media = self.open_channel(handle, 0x0019, phone_starts=True)
        return sig, media

    def a2dp_play(self, sig: Channel, media: Channel, seconds: float, offload: bool, stall: float = 0.0) -> None:
        self._label = (self._label + 1) % 16
        self._avdtp(sig, "TX", 0, 0x07, bytes([0x04]), gap=self.rng.uniform(0.5, 5.0))
        self._avdtp(sig, "RX", 2, 0x07)
        if offload:
            self.t += datetime.timedelta(seconds=seconds)
        else:
            packets, stall_at = int(seconds / 0.25), self.rng.randrange(2, 6)
            for i in range(packets):
                gap = stall if (stall and i == stall_at) else 0.25
                rtp = bytes([0x80, 0x60]) + struct.pack(">HII", i, i * 640, 1) + bytes([0x05]) + bytes(600)
                self.send(media, "TX", rtp, gap=gap)
        self._label = (self._label + 1) % 16
        self._avdtp(sig, "TX", 0, 0x09, bytes([0x04]), gap=0.2)
        self._avdtp(sig, "RX", 2, 0x09)

    # --- AVRCP ---------------------------------------------------------------------------------------

    def avrcp_open(self, handle: int) -> Channel:
        return self.open_channel(handle, 0x0017, phone_starts=False)

    def _avctp(self, channel: Channel, direction: str, response: bool, ctype: int, opcode: int, rest: bytes,
               gap: float = 0.01) -> None:
        self._label = (self._label + 1) % 16
        header = bytes([(self._label << 4) | (0x02 if response else 0), 0x11, 0x0E, ctype, 0x48, opcode])
        self.send(channel, direction, header + rest, gap)

    def _vendor(self, channel: Channel, direction: str, response: bool, ctype: int, pdu: int, params: bytes,
                gap: float = 0.01) -> None:
        rest = b"\x00\x19\x58" + bytes([pdu, 0]) + struct.pack(">H", len(params)) + params
        self._avctp(channel, direction, response, ctype, 0x00, rest, gap)

    def button(self, channel: Channel, button: int) -> None:
        self._avctp(channel, "RX", False, 0x0, 0x7C, bytes([button, 0]), gap=self.rng.uniform(1.0, 8.0))
        self._avctp(channel, "TX", True, 0x9, 0x7C, bytes([button, 0]))
        self._avctp(channel, "RX", False, 0x0, 0x7C, bytes([button | 0x80, 0]), gap=0.08)
        self._avctp(channel, "TX", True, 0x9, 0x7C, bytes([button | 0x80, 0]))

    def play_status(self, channel: Channel, status: int, gap: float = 0.05) -> None:
        self._vendor(channel, "TX", True, 0xD, 0x31, bytes([0x01, status]), gap)

    def track(self, channel: Channel, title: str, artist: str) -> None:
        self._vendor(channel, "TX", True, 0xD, 0x31, bytes([0x02]) + bytes(8), gap=0.05)
        self._vendor(channel, "RX", False, 0x1, 0x20, bytes(9), gap=0.1)
        params = bytes([2])
        for attribute, value in ((1, title), (2, artist)):
            data = value.encode()
            params += struct.pack(">IHH", attribute, 106, len(data)) + data
        self._vendor(channel, "TX", True, 0xC, 0x20, params)

    def phone_volume(self, channel: Channel, percent: int, device_answers: int | None = None) -> None:
        level = round(percent * 127 / 100)
        self._vendor(channel, "TX", False, 0x0, 0x50, bytes([level]), gap=self.rng.uniform(0.3, 2.0))
        self._vendor(channel, "RX", True, 0x9, 0x50, bytes([level]))
        if device_answers is not None:
            reported = round(device_answers * 127 / 100)
            self._vendor(channel, "RX", True, 0xD, 0x31, bytes([0x0D, reported]), gap=0.05)

    def device_volume(self, channel: Channel, percent: int) -> None:
        self._vendor(channel, "RX", True, 0xD, 0x31, bytes([0x0D, round(percent * 127 / 100)]),
                     gap=self.rng.uniform(0.3, 2.0))

    # --- HFP and Android Auto over RFCOMM ------------------------------------------------------------

    def rfcomm_open(self, handle: int) -> Channel:
        return self.open_channel(handle, 0x0003, phone_starts=False)

    def rfcomm(self, channel: Channel, direction: str, dlci: int, control: int, payload: bytes = b"",
               gap: float = 0.01) -> None:
        size = len(payload)
        length = bytes([(size << 1) | 0x01]) if size < 128 else bytes([(size << 1) & 0xFE, size >> 7])
        frame = bytes([(dlci << 2) | 0x03, control]) + length + payload + b"\x00"
        self.send(channel, direction, frame, gap)

    def at(self, channel: Channel, direction: str, line: str, gap: float = 0.02) -> None:
        text = f"{line}\r" if direction == "RX" else f"\r\n{line}\r\n"
        self.rfcomm(channel, direction, 6, 0xEF, text.encode(), gap)

    def hfp_setup(self, channel: Channel, service: int) -> None:
        self.rfcomm(channel, "RX", 6, 0x3F, gap=0.1)
        self.rfcomm(channel, "TX", 6, 0x73)
        for hf, ag in (("AT+BRSF=959", "+BRSF: 3943"), ("AT+BAC=1,2", None),
                       ("AT+CIND=?", '+CIND: ("call",(0,1)),("callsetup",(0-3)),("service",(0,1)),'
                                     '("signal",(0-5)),("roam",(0,1)),("battchg",(0-5)),("callheld",(0-2))'),
                       ("AT+CIND?", f"+CIND: 0,0,{service},{4 if service else 0},0,5,0"),
                       ("AT+CMER=3,0,0,1", None), ("AT+CHLD=?", "+CHLD: (0,1,2,3)")):
            self.at(channel, "RX", hf)
            if ag:
                self.at(channel, "TX", ag)
            self.at(channel, "TX", "OK")

    def hfp_call(self, channel: Channel, handle: int, mac: str, sco: int, seconds: float) -> None:
        self.at(channel, "TX", "+CIEV: 2,1", gap=self.rng.uniform(5.0, 30.0))
        self.at(channel, "TX", "RING")
        self.at(channel, "TX", f'+CLIP: "555{self.rng.randrange(1000000, 9999999)}",129')
        self.at(channel, "RX", "ATA", gap=self.rng.uniform(1.0, 6.0))
        self.at(channel, "TX", "OK")
        self.at(channel, "TX", "+CIEV: 1,1")
        self.at(channel, "TX", "+CIEV: 2,0")
        addr = bytes.fromhex(mac.replace(":", ""))[::-1]
        self.event(bytes([0x2C, 0x11, 0x00, sco & 0xFF, sco >> 8]) + addr
                   + bytes([0x02, 0x0C, 0x06, 0x3C, 0x00, 0x3C, 0x00, 0x03]), gap=0.3)
        self.at(channel, "RX", "AT+CHUP", gap=seconds)
        self.at(channel, "TX", "OK")
        self.at(channel, "TX", "+CIEV: 1,0")
        self.event(bytes([0x05, 0x04, 0x00, sco & 0xFF, sco >> 8, 0x16]), gap=0.2)

    def android_auto(self, handle: int, rfcomm: Channel, status: int) -> None:
        sdp = self.open_channel(handle, 0x0001, phone_starts=True)
        self.send(sdp, "TX", b"\x06\x00\x01\x00\x0f\x35\x11\x1c" + SERVICE_UUID + b"\x00\x40\x00", gap=0.1)
        self.send(sdp, "RX", b"\x07\x00\x01\x00\x20\x00\x1d\x35\x1b\x1c" + SERVICE_UUID + bytes(12))
        self.rfcomm(rfcomm, "RX", 10, 0x3F, gap=0.1)
        self.rfcomm(rfcomm, "TX", 10, 0x73)

        def message(direction: str, number: int, body: bytes = b"", gap: float = 0.03) -> None:
            self.rfcomm(rfcomm, direction, 10, 0xEF, struct.pack(">HH", len(body), number) + body, gap)

        message("RX", 4, b"\x08\x01\x10\x07")
        message("TX", 5, b"\x08\x01\x10\x07")
        message("RX", 1, b"\x0a\x04\xc0\xa8\x01\x01", gap=self.rng.uniform(2.0, 60.0))
        message("TX", 2)
        message("TX", 7, b"\x18\x00")
        message("RX", 3, b"\x0a\x06" + b"CarNet" + b"\x12\x08" + bytes(8))
        message("TX", 6, b"\x08" + _varint(status), gap=self.rng.uniform(3.0, 12.0))

    # --- Phonebook / messages over OBEX ------------------------------------------------------------

    def obex(self, handle: int, service: str, entries: int, fail: int | None) -> None:
        psm = 0x1001 + 2 * self.rng.randrange(1, 8)
        channel = self.open_channel(handle, psm, phone_starts=False)
        seq = [0]

        def frame(direction: str, packet: bytes, gap: float = 0.02) -> None:
            seq[0] = (seq[0] + 1) % 64
            self.send(channel, direction, bytes([seq[0] << 1, 0x00]) + packet, gap)

        def obex(code: int, headers: bytes = b"", prefix: bytes = b"") -> bytes:
            return bytes([code]) + struct.pack(">H", 3 + len(prefix) + len(headers)) + prefix + headers

        def header(hid: int, value: bytes) -> bytes:
            return bytes([hid]) + struct.pack(">H", 3 + len(value)) + value

        target = _PBAP if service == "pbap" else _MAP
        frame("RX", obex(0x80, header(0x46, target), b"\x10\x00\x03\xed"), gap=self.rng.uniform(1.0, 10.0))
        frame("TX", obex(0xA0, b"", b"\x10\x00\x03\xed"))
        if service == "pbap":
            kind, name = b"x-bt/phonebook\x00", "telecom/pb.vcf\x00".encode("utf-16-be")
            record = b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Person\r\nTEL:5550100\r\nEND:VCARD\r\n"
        else:
            kind, name = b"x-bt/MAP-msg-listing\x00", "inbox\x00".encode("utf-16-be")
            record = b'<msg handle="1" subject="hi" type="SMS_GSM"/>'
        frame("RX", obex(0x83, header(0x42, kind) + header(0x01, name)), gap=0.1)
        if fail is not None:
            frame("TX", obex(fail), gap=0.05)
        else:
            sent = 0
            while sent < entries:
                batch = min(entries - sent, 8)
                sent += batch
                frame("TX", obex(0x90 if sent < entries else 0xA0, header(0x48, record * batch)), gap=0.03)
        frame("RX", obex(0x81), gap=0.2)
        frame("TX", obex(0xA0))

    # --- LE Audio over ATT -------------------------------------------------------------------------

    def le_audio_stream(self, handle: int, cis: int, context: int, seconds: float,
                        failure: tuple[int, int, int] | None) -> bool:
        """Set up one LE Audio stream; failure is (step, response code, reason). Returns True if it streamed."""
        def att(direction: str, payload: bytes, gap: float = 0.02) -> None:
            self.acl(handle, direction, 0x0004, payload, gap)

        config = bytes([0x02, 0x01, 0x08, 0x02, 0x02, 0x01, 0x03, 0x04, 0x78, 0x00])  # LC3 48 kHz, 10 ms, 120 bytes
        lc3 = bytes([0x06, 0, 0, 0, 0])
        qos = bytes([0x10, 0x27, 0x00, 0x00, 0x02, 0x78, 0x00, 0x0D, 0x1E, 0x00, 0x40, 0x9C, 0x00])
        metadata = bytes([0x03, 0x02]) + struct.pack("<H", context)
        commands = [
            bytes([0x01, 0x01, 0x01, 0x02, 0x02]) + lc3 + bytes([len(config)]) + config,
            bytes([0x02, 0x01, 0x01, 0x01, 0x00]) + qos,
            bytes([0x03, 0x01, 0x01, len(metadata)]) + metadata,
        ]
        states = [
            bytes([0x01, 0x01, 0x00, 0x02, 0x02, 0x1E, 0x00]) + bytes(12) + lc3 + bytes([len(config)]) + config,
            bytes([0x01, 0x02, 0x01, 0x00]) + qos,
            bytes([0x01, 0x03, 0x01, 0x00, len(metadata)]) + metadata,
        ]
        for step, (command, state) in enumerate(zip(commands, states)):
            att("TX", bytes([0x52, 0x15, 0x01]) + command, gap=self.rng.uniform(0.02, 0.2) if step else 1.0)
            if failure is not None and failure[0] == step:
                att("RX", bytes([0x1B, 0x15, 0x01, command[0], 1, 1, failure[1], failure[2]]))
                return False
            att("RX", bytes([0x1B, 0x15, 0x01, command[0], 1, 1, 0, 0]))
            att("RX", bytes([0x1B, 0x02, 0x01]) + state)
        self.command(0x2064, params=bytes([0x01, cis & 0xFF, cis >> 8, handle & 0xFF, handle >> 8]), gap=0.05)
        self.event(bytes([0x3E, 0x1D, 0x19, 0x00, cis & 0xFF, cis >> 8]) + bytes(22), gap=0.1)
        att("RX", bytes([0x1B, 0x02, 0x01, 0x01, 0x04, 0x01, 0x00, len(metadata)]) + metadata)
        self.t += datetime.timedelta(seconds=seconds)
        att("TX", bytes([0x52, 0x15, 0x01, 0x08, 0x01, 0x01]))
        att("RX", bytes([0x1B, 0x15, 0x01, 0x08, 1, 1, 0, 0]))
        self.event(bytes([0x05, 0x04, 0x00, cis & 0xFF, cis >> 8, 0x16]), gap=0.05)
        return True


def _varint(value: int) -> bytes:
    """Protobuf varint; negative numbers use the 10-byte two's-complement form."""
    value &= 2 ** 64 - 1
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def song(rng: random.Random) -> tuple[str, str]:
    return f"{rng.choice(_WORDS)} {rng.choice(_WORDS)}", f"The {rng.choice(_WORDS)}s"


def device_name(rng: random.Random, kind: str) -> str:
    return rng.choice(_NAMES[kind])


# --- Scenarios -------------------------------------------------------------------------------------

BUTTONS = {0x44: "Play", 0x46: "Pause", 0x4B: "Next", 0x4C: "Previous", 0x41: "Volume Up", 0x42: "Volume Down"}
PROFILE_KINDS = ["car_normal", "headset_normal", "le_normal", "volume_override", "player_error", "no_service",
                 "stall", "a2dp_reject", "le_audio_fail", "aa_fail", "lost_pairing", "sync_fail"]


def _addr(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))[::-1]


def _encrypt(s: ProfileSession, handle: int) -> None:
    s.event(bytes([0x59, 0x05, 0x00, handle & 0xFF, handle >> 8, 0x01, 0x10]), gap=0.3)


def classic_session(s: ProfileSession, mac: str, kind: str, rng: random.Random, *, car: bool,
                    a2dp_reject: int | None = None, sync_fail: int | None = None, aa_status: int | None = None):
    """A phone connecting to a car or headset and using it; `kind` picks the one thing that goes wrong."""
    handle = s.handle("classic")
    s.classic_connect(mac, handle, 0x00)
    _encrypt(s, handle)
    rfcomm = s.rfcomm_open(handle)
    s.hfp_setup(rfcomm, service=0 if kind == "no_service" else 1)
    avrcp = s.avrcp_open(handle)
    sig, media = s.a2dp_setup(handle, rng.choice(["SBC", "SBC", "AAC"]), reject=a2dp_reject)
    if car and (kind == "sync_fail" or rng.random() < 0.6):
        s.obex(handle, "pbap", rng.randrange(5, 120), sync_fail if kind == "sync_fail" else None)
        if rng.random() < 0.5:
            s.obex(handle, "map", rng.randrange(1, 40), None)
    if media is not None:
        offload = rng.random() < 0.5 and kind != "stall"
        for play in range(rng.randrange(1, 4)):
            title, artist = song(rng)
            s.track(avrcp, title, artist)
            s.play_status(avrcp, 1)
            s.a2dp_play(sig, media, rng.uniform(6.0, 40.0), offload,
                        stall=rng.uniform(2.6, 9.0) if kind == "stall" and play == 0 else 0.0)
            for _ in range(rng.randrange(0, 4)):
                s.button(avrcp, rng.choice(list(BUTTONS)))
                if kind == "player_error" and play == 0:
                    s.play_status(avrcp, 0xFF, gap=0.6)
            if kind == "player_error" and play == 0:
                s.play_status(avrcp, 0xFF, gap=0.4)
            s.play_status(avrcp, 2)
        overrides = kind == "volume_override"
        fixed = rng.randrange(10, 40)
        for _ in range(rng.randrange(3, 7) if overrides else rng.randrange(0, 3)):
            target = rng.randrange(20, 90)
            s.phone_volume(avrcp, target, device_answers=fixed if overrides else target)
    if rng.random() < 0.3 and kind != "no_service":
        s.hfp_call(rfcomm, handle, mac, s.handle("classic"), rng.uniform(10.0, 90.0))
    if car and (kind == "aa_fail" or rng.random() < 0.3):
        s.android_auto(handle, rfcomm, aa_status if kind == "aa_fail" else 0)
    s.disconnect(handle, rng.choice([0x13, 0x16]))
    if kind == "lost_pairing":
        s.classic_connect(mac, handle, 0x00)
        s.event(bytes([0x06, 0x03, 0x06, handle & 0xFF, handle >> 8]), gap=0.1)
        s.event(bytes([0x36, 0x07, 0x18]) + _addr(mac), gap=0.05)
        s.event(bytes([0x06, 0x03, 0x05, handle & 0xFF, handle >> 8]), gap=0.01)
        s.disconnect(handle, 0x16, gap=0.08)


def le_session(s: ProfileSession, mac: str, kind: str, rng: random.Random, failure=None) -> None:
    """A phone streaming to LE Audio earbuds."""
    handle = s.handle("le")
    s.le_connect(mac, handle, 0x00, enhanced=True)
    _encrypt(s, handle)
    for i in range(rng.randrange(1, 4)):
        context = rng.choice([0x0004, 0x0004, 0x0002, 0x0080])
        fail = failure if (kind == "le_audio_fail" and i == 0) else None
        if not s.le_audio_stream(handle, s.handle("cis"), context, rng.uniform(5.0, 60.0), fail):
            break
    s.disconnect(handle, rng.choice([0x13, 0x16]))


def build_profile_session(rng: random.Random, mac: str, kind: str, **choices) -> ProfileSession:
    s = ProfileSession(rng)
    s.startup()
    s.routine_noise()
    if kind in ("le_normal", "le_audio_fail"):
        le_session(s, mac, kind, rng, choices.get("le_failure"))
    else:
        car = kind in ("car_normal", "aa_fail", "sync_fail", "lost_pairing") or (
            kind not in ("headset_normal",) and rng.random() < 0.5)
        classic_session(s, mac, kind, rng, car=car, a2dp_reject=choices.get("a2dp_reject"),
                        sync_fail=choices.get("sync_fail"), aa_status=choices.get("aa_status"))
    return s
