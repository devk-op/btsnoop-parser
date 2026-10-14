"""Protocol-level view of a capture: what the devices said above HCI.

:class:`ProtocolTrace` feeds every record through the L2CAP decoder, counts
traffic per protocol, and builds a timeline of the decoded exchanges (channel
setup, RFCOMM ports, HFP commands, A2DP streaming, AVRCP remote control,
voice links).

Captures often start after a connection's channels were opened, so a channel
whose setup was not seen is identified from its contents where that is
reliable: A2DP audio by its RTP header, AVDTP signaling by a command and its
matching answer.
"""
from __future__ import annotations

import collections
import datetime
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from . import android_auto, avdtp, avrcp, gatt, obex
from .constants import HCI_ERROR_CODES
from .hfp import HfpSession, decode_text, looks_like_at, split_lines
from .l2cap import L2capDecoder, L2capFrame
from .rfcomm import parse_frame

_AIR_MODES = {0x00: "u-law", 0x01: "A-law", 0x02: "CVSD", 0x03: "mSBC/transparent"}


@dataclass
class ProtocolEvent:
    """One line of the protocol timeline."""

    index: int
    timestamp: datetime.datetime
    direction: str
    handle: int
    device: str
    protocol: str
    summary: str
    detail: str = ""
    is_error: bool = False
    # Bookkeeping traffic (status polls, acknowledgements) that print_trace leaves out.
    routine: bool = False


@dataclass
class _Stream:
    """A2DP audio sent on one connection since the stream last started."""

    started: Optional[L2capFrame] = None  # the Start accept, when it was captured
    packets: int = 0
    size: int = 0
    first: Optional[L2capFrame] = None
    last: Optional[L2capFrame] = None
    gaps: list[float] = field(default_factory=list)


@dataclass
class DeviceProfiles:
    """What each profile did with one remote device, for the --stats summary."""

    codec: Optional[str] = None
    # (start, end, audio packets in the log, started before the capture)
    streams: list[tuple[datetime.datetime, datetime.datetime, int, bool]] = field(default_factory=list)
    stalls: int = 0
    buttons: collections.Counter[str] = field(default_factory=collections.Counter)
    volume_sets: list[tuple[datetime.datetime, int]] = field(default_factory=list)
    volume_reports: list[tuple[datetime.datetime, int]] = field(default_factory=list)
    volume_overrides: list[tuple[int, int]] = field(default_factory=list)  # (phone set, device reported)
    player_errors: int = 0
    tracks: list[tuple[datetime.datetime, str, str]] = field(default_factory=list)
    hfp_first: Optional[datetime.datetime] = None
    hfp_last: Optional[datetime.datetime] = None
    hfp_connections: int = 0
    hfp_codecs: str = ""
    calls: int = 0
    incoming: int = 0
    outgoing: int = 0
    no_service: bool = False
    hfp_errors: int = 0
    voice_links: list[tuple[datetime.datetime, Optional[datetime.datetime], str]] = field(default_factory=list)
    # GATT: services the device offers, phone services it used, and values seen
    gatt_services: list[str] = field(default_factory=list)
    gatt_phone_services: list[str] = field(default_factory=list)
    device_info: dict[str, str] = field(default_factory=dict)
    battery: list[int] = field(default_factory=list)
    heart_rates: list[int] = field(default_factory=list)
    gatt_states: dict[str, str] = field(default_factory=dict)
    gatt_updates: collections.Counter[str] = field(default_factory=collections.Counter)
    gatt_errors: list[str] = field(default_factory=list)
    le_audio_codec: str = ""
    le_audio_qos: str = ""
    le_audio_uses: collections.Counter[str] = field(default_factory=collections.Counter)
    # LE Audio streams: (start, end or None while open)
    le_audio: list[tuple[datetime.datetime, Optional[datetime.datetime]]] = field(default_factory=list)
    # Phonebook / message sync: "service" -> transfers
    syncs: dict[str, list[obex.Transfer]] = field(default_factory=dict)
    sync_failures: list[str] = field(default_factory=list)
    android_auto_start: Optional[datetime.datetime] = None
    android_auto_wifi: Optional[tuple[datetime.datetime, bool]] = None

    def active(self) -> bool:
        return any((self.streams, self.buttons, self.volume_sets, self.volume_reports, self.tracks, self.hfp_first,
                    self.voice_links, self.android_auto_start, self.codec, self.le_audio,
                    self.gatt_services, self.gatt_phone_services, self.device_info, self.gatt_updates,
                    self.gatt_errors, self.syncs))


# A source keeps sending packets while a stream is started, so a longer silence is a stall.
_STALL_SECONDS = 2.0
# How long an unconfirmed AVDTP command waits for its answer.
_ANSWER_WINDOW = datetime.timedelta(seconds=3)


def _timestamp(source: Any) -> datetime.datetime:
    return source.timestamp if isinstance(source, L2capFrame) else source["timestamp"]


def _addr(data: bytes) -> str:
    return ":".join(f"{b:02X}" for b in data[::-1])


class ProtocolTrace:
    """Decodes the protocols carried in a capture's ACL data."""

    def __init__(self, show_personal: bool = False) -> None:
        # Phone numbers and phone/SIM identifiers are masked unless show_personal is set.
        self.show_personal = show_personal
        self.events: list[ProtocolEvent] = []
        self.frame_counts: collections.Counter[tuple[str, str]] = collections.Counter()
        self._l2cap = L2capDecoder()
        # (device, serial port) -> [data frames, bytes, carries HFP]
        self.serial_ports: dict[tuple[str, int], list[Any]] = {}
        # (device, serial port) -> what the port carries, when it is not HFP
        self.serial_labels: dict[tuple[str, int], str] = {}
        self._android_auto_cars: set[int] = set()  # handles that advertised wireless Android Auto
        self._android_auto_ports: set[tuple[int, int]] = set()  # (handle, dlci)
        self._devices: dict[int, str] = {}
        self._voice_handles: set[int] = set()
        # (handle, dlci) -> HFP state; (handle, dlci, direction) -> unfinished AT text
        self._hfp: dict[tuple[int, int], HfpSession] = {}
        self._at_buffers: dict[tuple[int, int, str], str] = {}
        self.data_frames = 0
        self.truncated_frames = 0
        self.profiles: dict[str, DeviceProfiles] = {}
        self.frame_labels: dict[int, str] = {}  # record index of a frame's first packet -> protocol
        self._events_by_index: Optional[dict[int, list[ProtocolEvent]]] = None
        self._last_timestamp: Optional[datetime.datetime] = None
        self._gatt = gatt.GattTracker()
        self._obex: dict[tuple[int, int, int], obex.ObexChannel] = {}  # (handle, psm, channel position)
        self._cis_owner: dict[int, int] = {}  # LE Audio stream handle -> connection handle
        self._open_cis: set[int] = set()
        # (handle, direction, cid) -> protocol, for channels identified from their contents
        self._labels: dict[tuple[int, str, int], str] = {}
        self._candidates: list[tuple[L2capFrame, avdtp.AvdtpSignal]] = []
        self._streams: dict[int, _Stream] = {}
        self._codecs: dict[int, str] = {}
        self._pending_codecs: dict[tuple[int, int], str] = {}
        self._streamed_before_capture: set[int] = set()
        self._started: set[int] = set()
        self._finished = False

    def device(self, handle: int) -> str:
        return self._devices.get(handle, f"handle 0x{handle:03X}")

    def profile(self, handle: int) -> DeviceProfiles:
        return self.profiles.setdefault(self.device(handle), DeviceProfiles())

    def analyze_record(self, record: Mapping[str, Any]) -> None:
        """Ingest a single record."""
        self._last_timestamp = record.get("timestamp", self._last_timestamp)
        payload = record["payload"]
        # LE Create CIS: [OpcodeLSB, OpcodeMSB, Len, Count, then CISHandle(2) + ACLHandle(2) per stream]
        if record["packet_type"] == 0x01 and len(payload) >= 4 and payload[0] | (payload[1] << 8) == 0x2064:
            for offset in range(4, min(len(payload), 4 + 4 * payload[3]) - 3, 4):
                cis = (payload[offset] | (payload[offset + 1] << 8)) & 0x0FFF
                self._cis_owner[cis] = (payload[offset + 2] | (payload[offset + 3] << 8)) & 0x0FFF
        if record["packet_type"] == 0x04:
            self._event(record)
        elif record["packet_type"] == 0x02:
            frame = self._l2cap.feed(record)
            if frame is not None:
                self._frame(frame)

    def _add(self, source: Any, handle: int, protocol: str, summary: str, detail: str = "",
             is_error: bool = False, direction: Optional[str] = None, routine: bool = False) -> None:
        if isinstance(source, L2capFrame):
            index, timestamp, direction = source.index, source.timestamp, direction or source.direction
        else:
            index, timestamp, direction = source["index"], source["timestamp"], direction or source["direction"]
        self.events.append(ProtocolEvent(index, timestamp, direction, handle, self.device(handle),
                                         protocol, summary, detail, is_error, routine))

    def _event(self, record: Mapping[str, Any]) -> None:
        payload = record["payload"]
        if len(payload) < 2:
            return
        code = payload[0]

        if code == 0x03 and len(payload) >= 12 and payload[2] == 0x00 and payload[11] == 0x01:  # ACL Connection Complete
            handle = payload[3] | (payload[4] << 8)
            self._devices[handle] = _addr(payload[5:11])
            self._add(record, handle, "HCI", "Connected", detail="Classic (BR/EDR) link")

        elif code == 0x3E and len(payload) >= 6 and payload[2] == 0x19 and payload[3] == 0x00:  # LE CIS Established
            cis = payload[4] | (payload[5] << 8)
            if cis in self._cis_owner:
                self._open_cis.add(cis)
                self.profile(self._cis_owner[cis]).le_audio.append((record["timestamp"], None))

        elif code == 0x3E and len(payload) >= 7 and payload[2] == 0x1A:  # LE CIS Request: ACL handle, CIS handle
            self._cis_owner[payload[5] | (payload[6] << 8)] = payload[3] | (payload[4] << 8)

        elif code == 0x3E and len(payload) >= 14 and payload[2] in (0x01, 0x0A, 0x29) and payload[3] == 0x00:
            handle = payload[4] | (payload[5] << 8)
            self._devices[handle] = _addr(payload[8:14])
            self._add(record, handle, "HCI", "Connected", detail="LE link")

        elif code == 0x2C and len(payload) >= 19:  # Synchronous Connection Complete
            status, handle = payload[2], payload[3] | (payload[4] << 8)
            link = "eSCO" if payload[11] == 0x02 else "SCO"
            if status == 0x00:
                self._devices[handle] = _addr(payload[5:11])
                self._voice_handles.add(handle)
                codec = _AIR_MODES.get(payload[18], f"air mode 0x{payload[18]:02X}")
                self._add(record, handle, "Voice", f"Voice link opened ({link}, {codec})")
                self.profile(handle).voice_links.append((record["timestamp"], None, codec))
            else:
                reason = HCI_ERROR_CODES.get(status, f"0x{status:02X}")
                self._devices.setdefault(handle, _addr(payload[5:11]))
                self._add(record, handle, "Voice", f"Voice link failed: {reason}", is_error=True)

        elif code == 0x05 and len(payload) >= 6 and payload[2] == 0x00:  # Disconnection Complete
            handle = payload[3] | (payload[4] << 8)
            reason = HCI_ERROR_CODES.get(payload[5], f"0x{payload[5]:02X}")
            if handle in self._open_cis:
                self._open_cis.discard(handle)
                streams = self.profile(self._cis_owner[handle]).le_audio
                if streams and streams[-1][1] is None:
                    streams[-1] = (streams[-1][0], record["timestamp"])
                return
            if handle in self._voice_handles:
                self._voice_handles.discard(handle)
                self._add(record, handle, "Voice", f"Voice link closed ({reason})")
                links = self.profile(handle).voice_links
                if links and links[-1][1] is None:
                    links[-1] = (links[-1][0], record["timestamp"], links[-1][2])
            else:
                self._stop_stream(record, handle, "")
                self._add(record, handle, "HCI", "Disconnected", detail=reason)
            self._stop_stream(record, handle, "")
            self._l2cap.forget_handle(handle)
            self._gatt.forget(handle)
            self._candidates = [c for c in self._candidates if c[0].handle != handle]
            self._android_auto_cars.discard(handle)
            self._android_auto_ports = {k for k in self._android_auto_ports if k[0] != handle}
            for store in (self._hfp, self._at_buffers, self._labels):
                for key in [k for k in store if k[0] == handle]:
                    del store[key]
            self._devices.pop(handle, None)

    def _frame(self, frame: L2capFrame) -> None:
        self.data_frames += 1
        self.truncated_frames += frame.truncated
        protocol = self._identify(frame)
        self.frame_labels[frame.index] = protocol
        self.frame_counts[(self.device(frame.handle), protocol)] += 1
        for text, is_error in frame.notes:
            self._add(frame, frame.handle, "L2CAP", text, is_error=is_error)
        if protocol == "SDP" and android_auto.SERVICE_UUID in frame.payload:
            self._android_auto_cars.add(frame.handle)
        if protocol == "L2CAP Signaling":
            self._closed_identified_channels(frame)
        elif protocol == "RFCOMM":
            self._rfcomm(frame)
        elif protocol == "AVDTP":
            self._avdtp(frame)
        elif protocol == "A2DP Media":
            self._media(frame)
        elif protocol == "AVCTP":
            self._avrcp(frame)
        elif protocol == "ATT":
            self._att(frame)
        if frame.psm is not None and frame.psm >= 0x1001:
            self._obex_frame(frame)

    def _closed_identified_channels(self, frame: L2capFrame) -> None:
        """Report the closing of channels that were identified from their contents."""
        data, offset = frame.payload, 0
        while offset + 8 <= len(data):
            code, length = data[offset], data[offset + 2] | (data[offset + 3] << 8)
            if code == 0x06:  # Disconnection Request: data sent the same way used the destination CID
                dcid = data[offset + 4] | (data[offset + 5] << 8)
                scid = data[offset + 6] | (data[offset + 7] << 8)
                label = self._labels.pop((frame.handle, frame.direction, dcid), None)
                other = "RX" if frame.direction == "TX" else "TX"
                label = self._labels.pop((frame.handle, other, scid), None) or label
                if label:
                    name = {"AVDTP": "A2DP signaling", "A2DP Media": "A2DP audio", "AVCTP": "AVRCP"}[label]
                    self._add(frame, frame.handle, "L2CAP", f"{name} channel closed")
            offset += 4 + length

    def _identify(self, frame: L2capFrame) -> str:
        """Name the protocol a frame belongs to, inspecting channels whose setup was not captured."""
        if frame.protocol == "AVDTP":
            return "A2DP Media" if frame.channel_index else "AVDTP"
        if frame.psm is not None and frame.psm >= 0x1001:
            channel = self._obex.get((frame.handle, frame.psm, frame.channel_index or 0))
            if channel is not None and channel.service:
                return channel.service
        if frame.protocol != "L2CAP":
            return frame.protocol
        key = (frame.handle, frame.direction, frame.cid)
        if key in self._labels:
            return self._labels[key]

        if avdtp.is_media_packet(frame.payload, frame.length):
            self._labels[key] = "A2DP Media"
            return "A2DP Media"
        if frame.payload[1:3] in (b"\x11\x0e", b"\x11\x0c", b"\x11\x0f") and frame.payload[0] & 0x0C == 0:
            self._labels[key] = "AVCTP"  # remote control (AVRCP) messages
            return "AVCTP"

        sig = avdtp.parse_signal(frame.payload)
        if sig is None:
            return "L2CAP"
        if avdtp.plausible_command(sig, frame.length):
            self._candidates = [c for c in self._candidates if frame.timestamp - c[0].timestamp < _ANSWER_WINDOW]
            self._candidates.append((frame, sig))
            return "L2CAP"
        for i, (command, command_sig) in enumerate(self._candidates):
            if (command.handle == frame.handle and command.direction != frame.direction
                    and (command_sig.label, command_sig.signal) == (sig.label, sig.signal)
                    and frame.timestamp - command.timestamp < _ANSWER_WINDOW):
                del self._candidates[i]
                self._labels[key] = "AVDTP"
                self._labels[(command.handle, command.direction, command.cid)] = "AVDTP"
                device = self.device(command.handle)
                self.frame_counts[(device, "L2CAP")] -= 1
                self.frame_counts[(device, "AVDTP")] += 1
                if self.frame_counts[(device, "L2CAP")] <= 0:
                    del self.frame_counts[(device, "L2CAP")]
                self._avdtp(command)
                return "AVDTP"
        return "L2CAP"

    def _avdtp(self, frame: L2capFrame) -> None:
        sig = avdtp.parse_signal(frame.payload)
        if sig is None:
            return  # continuation of a long message
        handle = frame.handle
        summary = sig.name if sig.is_command else f"{sig.name} {avdtp.MESSAGE_TYPES[sig.message_type]}"
        detail, is_error = avdtp.describe(sig)
        self._add(frame, handle, "A2DP", summary, detail=detail, is_error=is_error)

        accepted = sig.message_type == 2
        if sig.is_command and sig.signal in (0x03, 0x05):
            codecs, _ = avdtp._capabilities(sig.body[2:] if sig.signal == 0x03 else sig.body[1:])
            if codecs:
                self._pending_codecs[(handle, sig.label)] = codecs[0]
        elif accepted and sig.signal in (0x03, 0x05) and (handle, sig.label) in self._pending_codecs:
            self._codecs[handle] = self._pending_codecs.pop((handle, sig.label))
            self.profile(handle).codec = self._codecs[handle]
        elif accepted and sig.signal == 0x04:
            codecs, _ = avdtp._capabilities(sig.body)
            if codecs:
                self._codecs[handle] = codecs[0]
                self.profile(handle).codec = codecs[0]
        elif accepted and sig.signal == 0x07:
            self._started.add(handle)
            self._streams[handle] = _Stream(started=frame)
        elif accepted and sig.signal in (0x08, 0x09, 0x0A):
            self._stop_stream(frame, handle, "")
            self._started.discard(handle)

    def _obex_frame(self, frame: L2capFrame) -> None:
        """Phonebook and message sync (OBEX over L2CAP): activity only, never contents."""
        key = (frame.handle, frame.psm, frame.channel_index or 0)
        channel = self._obex.get(key)
        if channel is None:
            if len(frame.payload) < 3 or frame.payload[0] & 1 or frame.payload[2] != 0x80:
                return  # only start following a channel at its OBEX Connect
            channel = self._obex[key] = obex.ObexChannel()
        result = channel.feed(frame.direction, frame.payload, frame.timestamp)
        if channel.service:
            self.profile(frame.handle).syncs[channel.service] = list(channel.transfers.values())
        if result is not None:
            summary, detail, is_error = result
            self._add(frame, frame.handle, "OBEX", summary, detail=detail, is_error=is_error)
            if is_error:
                self.profile(frame.handle).sync_failures.append(detail)

    def _att(self, frame: L2capFrame) -> None:
        msg = self._gatt.feed(frame.handle, frame.direction, frame.payload)
        if msg is None:
            return
        self._add(frame, frame.handle, "GATT", msg.summary, detail=msg.detail, is_error=msg.is_error,
                  routine=msg.routine)
        profile = self.profile(frame.handle)
        if msg.summary == "Services":
            profile.gatt_services = self._gatt.services(frame.handle, "RX")
            profile.gatt_phone_services = self._gatt.services(frame.handle, "TX")
        if msg.is_error:
            profile.gatt_errors.append(msg.detail)
        if msg.value is None:
            return
        uuid, decoded, raw = msg.value
        name = gatt.CHARACTERISTICS.get(uuid, "") if uuid is not None else ""
        from_device = frame.direction == "RX"
        self._le_audio_facts(profile, uuid, raw, msg.summary, from_device, frame.timestamp)
        if msg.summary in ("Notification", "Indication") and from_device:
            profile.gatt_updates[msg.detail.split(": ")[0]] += 1
        if decoded is None or not from_device and msg.summary != "Write":
            return
        if uuid in (0x2A29, 0x2A24, 0x2A26, 0x2A28, 0x2A00, 0x2A01) and from_device and decoded != "unknown":
            profile.device_info[name] = decoded
        elif uuid == 0x2A19 and from_device:
            profile.battery.append(int(decoded.rstrip("%")))
        elif uuid == 0x2A37 and from_device:
            profile.heart_rates.append(int(decoded.split()[0]))
        elif uuid in (0x2B7D, 0x2BA3, 0x2BC3, 0x2B97) and from_device:
            profile.gatt_states[name] = decoded

    @staticmethod
    def _le_audio_facts(profile: DeviceProfiles, uuid: Optional[int], raw: bytes, kind: str,
                        from_device: bool, when: datetime.datetime) -> None:
        """Stream setup, buttons, volume and calls carried over LE Audio's GATT services."""
        from . import le_audio
        if not raw:
            return
        if uuid in (0x2BC4, 0x2BC5) and len(raw) >= 2:
            state = raw[1]
            if state == 1 and len(raw) >= 25:
                profile.le_audio_codec = le_audio.describe_codec(raw[19:24], raw[25:25 + raw[24]])
            elif state == 2 and len(raw) >= 17:
                profile.le_audio_qos = le_audio._qos(raw, 4)
            elif state == 4 and len(raw) >= 5:
                mask = le_audio.metadata_contexts(raw[5:5 + raw[4]])
                profile.le_audio_uses[le_audio.contexts(mask) if mask is not None else "unspecified"] += 1
        elif uuid == 0x2BA4 and kind == "Write" and from_device:
            command = gatt.decode_value(0x2BA4, raw)
            if command:
                profile.buttons[command] += 1
        elif uuid == 0x2B7E and kind == "Write" and not from_device and raw[0] == 0x04 and len(raw) >= 3:
            profile.volume_sets.append((when, round(raw[2] * 100 / 255)))
        elif uuid == 0x2B7D and kind in ("Notification", "Indication", "Read Response") and from_device:
            profile.volume_reports.append((when, round(raw[0] * 100 / 255)))
        elif uuid == 0x2BBD and kind in ("Notification", "Indication"):
            for _, state in le_audio.call_states(raw):
                if state == "incoming":
                    profile.incoming += 1
                elif state == "active":
                    profile.calls += 1

    def _avrcp(self, frame: L2capFrame) -> None:
        msg = avrcp.parse(frame.payload, frame.length)
        if msg is None:
            return
        # Snoop logs are recorded on the phone, so what it sent (TX) is the phone's side.
        summary, detail, is_error = avrcp.describe(msg, from_phone=frame.direction == "TX")
        self._avrcp_facts(frame, avrcp.facts(msg))
        self._add(frame, frame.handle, "AVRCP", summary, detail=detail, is_error=is_error,
                  routine=avrcp.is_routine(msg))

    def _avrcp_facts(self, frame: L2capFrame, facts: dict) -> None:
        profile, when = self.profile(frame.handle), frame.timestamp
        if "button" in facts:
            profile.buttons[facts["button"]] += 1
        if "volume_set" in facts and frame.direction == "TX":
            profile.volume_sets.append((when, facts["volume_set"]))
        if "volume_report" in facts and frame.direction == "RX":
            profile.volume_reports.append((when, facts["volume_report"]))
            # A device that answers the phone's new volume with a different one is overriding it.
            if profile.volume_sets:
                set_at, level = profile.volume_sets[-1]
                if (when - set_at).total_seconds() < 1.5 and abs(level - facts["volume_report"]) > 3:
                    profile.volume_overrides.append((level, facts["volume_report"]))
        if facts.get("play_status") == "error":
            profile.player_errors += 1
        if "track" in facts and (not profile.tracks or profile.tracks[-1][1:] != facts["track"]):
            profile.tracks.append((when, *facts["track"]))

    def _media(self, frame: L2capFrame) -> None:
        handle = frame.handle
        stream = self._streams.get(handle)
        if stream is None:
            stream = self._streams[handle] = _Stream()
            if handle not in self._started and handle not in self._streamed_before_capture:
                self._streamed_before_capture.add(handle)
                self._add(frame, handle, "A2DP", "Audio streaming",
                          detail="Already streaming when the capture began")
        if stream.last is not None:
            silence = (frame.timestamp - stream.last.timestamp).total_seconds()
            if silence > _STALL_SECONDS:
                self.profile(handle).stalls += 1
                self._add(frame, handle, "A2DP", "Audio stalled", is_error=True,
                          detail=f"No audio sent for {silence:.1f} s while the stream was started")
        stream.first = stream.first or frame
        stream.last = frame
        stream.packets += 1
        stream.size += frame.length

    def _stop_stream(self, source: Any, handle: int, note: str) -> None:
        stream = self._streams.pop(handle, None)
        if stream is None:
            return
        if stream.first is None:
            if stream.started is not None:
                self.profile(handle).streams.append((stream.started.timestamp, _timestamp(source), 0, False))
                seconds = (_timestamp(source) - stream.started.timestamp).total_seconds()
                self._add(source, handle, "A2DP", "Stream summary", direction=stream.started.direction,
                          detail=f"Streamed for {seconds:.1f} s, but no audio packets are in the log: the phone's "
                                 "Bluetooth chip encoded and sent the audio itself (hardware offload)")
            return
        start = stream.started.timestamp if stream.started is not None else stream.first.timestamp
        self.profile(handle).streams.append((start, stream.last.timestamp, stream.packets, stream.started is None))
        seconds = (stream.last.timestamp - stream.first.timestamp).total_seconds()
        rate = f", about {stream.size * 8 / seconds / 1000:.0f} kbit/s" if seconds > 0 else ""
        codec = f" {self._codecs[handle]}" if handle in self._codecs else ""
        detail = f"{seconds:.1f} s of{codec} audio: {stream.packets:,} packets, {stream.size / 1024:.0f} KB{rate}{note}"
        self._add(source, handle, "A2DP", "Stream summary", detail=detail, direction=stream.first.direction)

    def events_by_index(self) -> dict[int, list[ProtocolEvent]]:
        """Timeline events grouped by the record index they came from."""
        self.finish()
        if self._events_by_index is None:
            grouped: dict[int, list[ProtocolEvent]] = collections.defaultdict(list)
            for event in self.events:
                grouped[event.index].append(event)
            self._events_by_index = dict(grouped)
        return self._events_by_index

    def finish(self) -> None:
        """Close out streams still running at the end of the capture and order the timeline."""
        if self._finished:
            return
        self._finished = True
        for handle, stream in list(self._streams.items()):
            if stream.last is not None:
                self._stop_stream(stream.last, handle, " (still streaming when the capture ended)")
            elif stream.started is not None and self._last_timestamp is not None:
                end = {"index": stream.started.index, "timestamp": self._last_timestamp,
                       "direction": stream.started.direction}
                self._stop_stream(end, handle, "")
        self.events.sort(key=lambda e: e.index)

    def _rfcomm(self, frame: L2capFrame) -> None:
        rfcomm = parse_frame(frame.payload)
        if rfcomm is None or rfcomm.dlci == 0:
            return  # DLCI 0 is multiplexer housekeeping
        port = f"port {rfcomm.channel}"
        if rfcomm.frame_type == "SABM":
            self._add(frame, frame.handle, "RFCOMM", f"Opening serial {port}")
        elif rfcomm.frame_type == "DISC":
            self._add(frame, frame.handle, "RFCOMM", f"Closing serial {port}")
        elif rfcomm.frame_type == "DM":
            self._add(frame, frame.handle, "RFCOMM", f"Serial {port} refused or already closed", is_error=True)
        elif rfcomm.frame_type == "UIH" and rfcomm.payload:
            usage = self.serial_ports.setdefault((self.device(frame.handle), rfcomm.channel), [0, 0, False])
            usage[0] += 1
            usage[1] += len(rfcomm.payload)
            if self._android_auto(frame, rfcomm.dlci, rfcomm.payload):
                self.serial_labels[(self.device(frame.handle), rfcomm.channel)] = "wireless Android Auto setup"
            elif self._serial_data(frame, rfcomm.dlci, rfcomm.payload):
                usage[2] = True

    def _android_auto(self, frame: L2capFrame, dlci: int, payload: bytes) -> bool:
        """Decode wireless Android Auto set-up messages on a car that advertised the service."""
        key = (frame.handle, dlci)
        if key not in self._android_auto_ports:
            if frame.handle not in self._android_auto_cars or not android_auto.is_message(payload):
                return False
            self._android_auto_ports.add(key)
        if android_auto.is_message(payload):
            summary, detail, is_error = android_auto.describe(payload)
            profile, message = self.profile(frame.handle), int.from_bytes(payload[2:4], "big")
            if message == 1 and profile.android_auto_start is None:
                profile.android_auto_start = frame.timestamp
            elif message == 6:
                profile.android_auto_wifi = (frame.timestamp, not is_error)
            self._add(frame, frame.handle, "AAuto", summary, detail=detail, is_error=is_error)
        return True

    def _serial_data(self, frame: L2capFrame, dlci: int, payload: bytes) -> bool:
        """Decode AT traffic on a serial port; return False if the data is something else."""
        text = decode_text(payload)
        key = (frame.handle, dlci)
        buffer_key = (frame.handle, dlci, frame.direction)
        pending = self._at_buffers.get(buffer_key, "")
        if text is None or not (key in self._hfp or pending or looks_like_at(text)):
            return False  # some other profile is using this serial port
        session = self._hfp.setdefault(key, HfpSession())
        lines, self._at_buffers[buffer_key] = split_lines(pending + text)
        profile = self.profile(frame.handle)
        for line in lines:
            profile.hfp_first = profile.hfp_first or frame.timestamp
            profile.hfp_last = frame.timestamp
            upper = line.strip().upper()
            if upper.startswith("AT+BRSF"):
                profile.hfp_connections += 1
            elif upper.startswith("AT+BAC="):
                profile.hfp_codecs = session.describe(line)[0].split(": ", 1)[-1]
            elif upper.startswith(("ATD", "AT+BLDN")):
                profile.outgoing += 1
            elif upper.startswith("+CME ERROR"):
                profile.hfp_errors += 1
            for name, value in session.updates(line).items():
                if name == "call" and value == 1:
                    profile.calls += 1
                elif name == "callsetup" and value == 1:
                    profile.incoming += 1
                elif name == "service":
                    profile.no_service = value == 0
            shown = line.strip() if self.show_personal else session.redact(line)
            summary, is_error = session.describe(shown)
            self._add(frame, frame.handle, "HFP", shown, detail=summary, is_error=is_error)
        return True


def print_trace(trace: ProtocolTrace, color: bool = True) -> None:
    """Print the protocol overview and timeline to stdout."""
    if color:
        BOLD, RED, CYAN, DIM, RESET = "\033[1m", "\033[91m", "\033[96m", "\033[2m", "\033[0m"
    else:
        BOLD = RED = CYAN = DIM = RESET = ""

    trace.finish()
    print(f"\n{BOLD} Protocol Traffic ───{RESET}")
    if trace.truncated_frames:
        print(f"  {DIM}Filtered capture: {trace.truncated_frames:,} of {trace.data_frames:,} data frames were stored "
              f"cut short, so some details are missing.{RESET}")
    if not trace.frame_counts:
        print("  No L2CAP data found (the capture may hold HCI commands and events only).")
    by_device: dict[str, list[tuple[str, int]]] = collections.defaultdict(list)
    for (device, protocol), count in trace.frame_counts.most_common():
        by_device[device].append((protocol, count))
    for device, protocols in by_device.items():
        print(f"  {CYAN}{device}{RESET}")
        for protocol, count in protocols:
            print(f"    {protocol:<18} {count:>7,} frames")

    if trace.serial_ports:
        print(f"\n{BOLD} Serial Ports (RFCOMM) ───{RESET}")
        for (device, port), (frames, size, is_hfp) in sorted(trace.serial_ports.items()):
            use = "HFP commands" if is_hfp else trace.serial_labels.get((device, port), "app/vendor data (not decoded)")
            print(f"  {CYAN}{device}{RESET}  port {port:<3} {frames:>6,} data frames  {size / 1024:>8.1f} KB  {use}")

    print(f"\n{BOLD} Protocol Timeline ───{RESET}")
    events = [e for e in trace.events if not e.routine]
    hidden = len(trace.events) - len(events)
    if hidden:
        print(f"  {DIM}{hidden:,} routine messages hidden (status polls, notification sign-ups, acknowledgements).{RESET}")
    if not events:
        print("  No decoded protocol activity.")
        return
    width = max(len(e.summary) for e in events if e.detail) if any(e.detail for e in events) else 0
    width = min(width, 32)
    for event in events:
        t_str = event.timestamp.astimezone().strftime("%H:%M:%S.%f")[:-3]
        arrow = "->" if event.direction == "TX" else "<-"
        c = RED if event.is_error else ""
        text = f"{event.summary:<{width}}  {DIM}{event.detail}{RESET}" if event.detail else event.summary
        print(f"  {t_str} {arrow} {CYAN}{event.device}{RESET}  {event.protocol:<7} {c}{text}{RESET}")


def _clock(ts: datetime.datetime) -> str:
    return ts.astimezone().strftime("%H:%M:%S")


def _span(start: datetime.datetime, end: datetime.datetime) -> str:
    from .analysis import format_duration
    return format_duration(start, end)


def _profile_lines(p: DeviceProfiles) -> list[tuple[str, str, bool]]:
    """(label, text, is_warning) lines describing one device's profiles."""
    lines: list[tuple[str, str, bool]] = []

    if p.streams or p.codec:
        total = sum(((end - start) for start, end, _, _ in p.streams), datetime.timedelta())
        offloaded = p.streams and all(packets == 0 for _, _, packets, _ in p.streams)
        text = p.codec or "codec not captured"
        if p.streams:
            text += f"; played {len(p.streams)} time(s), {_span(datetime.datetime.min, datetime.datetime.min + total)} in total"
        if offloaded:
            text += " (audio sent by the phone's chip, not in the log)"
        lines.append(("Music (A2DP)", text, False))
        for start, end, _, before in p.streams[:8]:
            note = " (already playing when the capture began)" if before else ""
            lines.append(("", f"{_clock(start)} - {_clock(end)}  {_span(start, end)}{note}", False))
        if len(p.streams) > 8:
            lines.append(("", f"... {len(p.streams) - 8} more", False))
        if p.stalls:
            lines.append(("", f"Audio stalled {p.stalls} time(s) while playing", True))

    if p.buttons or p.volume_sets or p.volume_reports or p.player_errors:
        if p.buttons:
            pressed = ", ".join(f"{name} x{count}" for name, count in p.buttons.most_common())
            lines.append(("Controls (AVRCP)", f"Buttons pressed on the device: {pressed}", False))
        volume = []
        if p.volume_sets:
            volume.append(f"phone changed it {len(p.volume_sets)} time(s), last to {p.volume_sets[-1][1]}%")
        if p.volume_reports:
            volume.append(f"device reported {len(p.volume_reports)} change(s), last {p.volume_reports[-1][1]}%")
        if volume:
            lines.append(("" if p.buttons else "Controls (AVRCP)", "Volume: " + "; ".join(volume), False))
        if p.volume_overrides:
            example = p.volume_overrides[-1]
            lines.append(("", f"Device overrode the phone's volume {len(p.volume_overrides)} time(s) "
                              f"(e.g. phone set {example[0]}%, device answered {example[1]}%)", True))
        if p.player_errors:
            lines.append(("", f"Music app reported a playback error {p.player_errors} time(s)", True))

    if p.tracks:
        for i, (when, title, artist) in enumerate(p.tracks[:15]):
            song = f"{title} - {artist}" if artist else title
            lines.append(("Songs" if i == 0 else "", f"{_clock(when)}  {song}", False))
        if len(p.tracks) > 15:
            lines.append(("", f"... {len(p.tracks) - 15} more", False))

    if p.hfp_first:
        text = f"Active {_clock(p.hfp_first)} - {_clock(p.hfp_last)}"
        if p.hfp_connections > 1:
            text += f", connected {p.hfp_connections} times"
        if p.hfp_codecs:
            text += f"; voice codecs {p.hfp_codecs}"
        calls = []
        if p.incoming:
            calls.append(f"{p.incoming} incoming")
        if p.outgoing:
            calls.append(f"{p.outgoing} outgoing")
        text += "; calls: " + (", ".join(calls) if calls else ("none" if not p.calls else f"{p.calls} active"))
        lines.append(("Calls (HFP)", text, False))
        if p.no_service:
            lines.append(("", "Phone reported no cellular service, so calls through this device would fail", True))
        if p.hfp_errors:
            lines.append(("", f"Phone answered {p.hfp_errors} hands-free request(s) with an error "
                              "(often unsupported features such as text messages)", False))
    services = [s for s in p.gatt_services if s not in ("Generic Access", "Generic Attribute")]
    if services:
        lines.append(("GATT services", ", ".join(services), False))
    if p.device_info:
        lines.append(("Device info", "; ".join(f"{k}: {v}" for k, v in p.device_info.items()), False))
    used = [s for s in p.gatt_phone_services if s not in ("Generic Access", "Generic Attribute")]
    if used:
        lines.append(("Uses on the phone", ", ".join(used), False))
    if p.battery:
        change = f"{p.battery[0]}%" if len(set(p.battery)) == 1 else f"{p.battery[0]}% -> {p.battery[-1]}%"
        lines.append(("Battery", f"{change} ({len(p.battery)} reading(s))", False))
    if p.heart_rates:
        lines.append(("Heart rate", f"{len(p.heart_rates)} readings, {min(p.heart_rates)}-{max(p.heart_rates)} bpm",
                      False))
    if p.gatt_states:
        lines.append(("LE Audio state", "; ".join(f"{k}: {v}" for k, v in p.gatt_states.items()), False))
    if p.gatt_updates:
        top = ", ".join(f"{name} x{count:,}" for name, count in p.gatt_updates.most_common(4))
        lines.append(("GATT updates", top, False))
    if p.gatt_errors:
        lines.append(("", f"{len(p.gatt_errors)} GATT request(s) failed (e.g. {p.gatt_errors[0]})", True))

    if p.le_audio or p.le_audio_codec:
        closed = [(s, e) for s, e in p.le_audio if e is not None]
        total = sum(((e - s) for s, e in closed), datetime.timedelta())
        lines.append(("LE Audio", f"{len(p.le_audio)} audio stream(s), "
                                  f"{_span(datetime.datetime.min, datetime.datetime.min + total)} in total", False))
        if p.le_audio_codec:
            lines.append(("", f"Codec: {p.le_audio_codec}", False))
        if p.le_audio_qos:
            lines.append(("", f"Link: {p.le_audio_qos}", False))
        if p.le_audio_uses:
            uses = ", ".join(f"{use} x{count}" for use, count in p.le_audio_uses.most_common())
            lines.append(("", f"Streams used for: {uses}", False))
        for start, end in p.le_audio[:8]:
            lines.append(("", f"{_clock(start)} - {_clock(end) + '  ' + _span(start, end) if end else 'still open'}", False))
        if len(p.le_audio) > 8:
            lines.append(("", f"... {len(p.le_audio) - 8} more", False))
    for start, end, codec in p.voice_links:
        length = _span(start, end) if end else "still open at the end of the capture"
        lines.append(("Voice link", f"{_clock(start)}  {codec}, {length}", False))

    for service, transfers in p.syncs.items():
        shown = [t for t in transfers if t.requests]
        for i, transfer in enumerate(shown or transfers[:1]):
            lines.append((service if i == 0 else "", obex.describe_transfer(transfer), bool(transfer.failures)))
        if not transfers:
            lines.append((service, "connected, nothing transferred", False))

    if p.android_auto_start or p.android_auto_wifi:
        text = f"Started {_clock(p.android_auto_start)}" if p.android_auto_start else "Set-up seen"
        if p.android_auto_wifi:
            when, ok = p.android_auto_wifi
            text += (f"; phone joined the device's Wi-Fi at {_clock(when)}" if ok
                     else f"; phone failed to join the device's Wi-Fi at {_clock(when)}")
        lines.append(("Android Auto", text + " (projection then runs over Wi-Fi, not in this log)",
                      bool(p.android_auto_wifi and not p.android_auto_wifi[1])))
    return lines


def print_profiles(trace: ProtocolTrace, color: bool = True) -> None:
    """Print what music, controls, calls and Android Auto did with each device."""
    trace.finish()
    if color:
        BOLD, YELLOW, CYAN, DIM, RESET = "\033[1m", "\033[93m", "\033[96m", "\033[2m", "\033[0m"
    else:
        BOLD = YELLOW = CYAN = DIM = RESET = ""
    devices = {device: p for device, p in trace.profiles.items() if p.active()}
    print(f"\n{BOLD}Profiles:{RESET}")
    if trace.truncated_frames:
        print(f"  {DIM}Filtered capture: some details were cut from the log.{RESET}")
    if not devices:
        print("  No music, call or remote-control activity found.")
    seen = {"music (A2DP or LE Audio)": False, "calls (HFP)": False, "remote control (AVRCP)": False,
            "Android Auto": False}
    for device, profile in devices.items():
        print(f"  {CYAN}{device}{RESET}")
        for label, text, warning in _profile_lines(profile):
            colour = YELLOW if warning else ""
            print(f"    {label:<17} {colour}{'! ' if warning else ''}{text}{RESET if warning else ''}")
        seen["music (A2DP or LE Audio)"] |= bool(profile.streams or profile.codec or profile.le_audio)
        seen["calls (HFP)"] |= bool(profile.hfp_first)
        seen["remote control (AVRCP)"] |= bool(profile.buttons or profile.volume_sets or profile.volume_reports)
        seen["Android Auto"] |= bool(profile.android_auto_start or profile.android_auto_wifi)
    missing = [name for name, found in seen.items() if not found]
    if missing:
        print(f"  {DIM}Not seen in this capture: {', '.join(missing)}{RESET}")
