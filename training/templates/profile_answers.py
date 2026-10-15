"""Answers for the protocol-level training sessions, written from each session's report.

The answer only restates what the report (and so the model's input) contains:
the problem's warning line, when it first happened, and a cause stated in the
same terms. Normal sessions get a short account of what happened.
"""
from __future__ import annotations

import datetime
from typing import Optional

from btsnoop_parser.obex import describe_transfer
from btsnoop_parser.protocols import DeviceProfiles
from btsnoop_parser.report import SessionReport

CAUSES = {
    "volume_override": (
        "the device answered each of the phone's volume changes with its own, unchanged level, so the phone's "
        "volume buttons had no effect on it. That is a compatibility problem with the device's handling of "
        "absolute volume; turning on \"Disable absolute volume\" in the phone's developer options usually works "
        "around it"),
    "player_error": (
        "the music app reported a playback error. Bluetooth delivered the commands and status normally, so the "
        "problem is in the app or the track itself (for example a track that is unavailable), not the "
        "Bluetooth link"),
    "no_service": (
        "the phone reported no cellular service. The hands-free link itself worked, but calls placed or "
        "received through the device would fail; this is a phone or network problem, not Bluetooth"),
    "stall": (
        "the phone stopped sending audio for a few seconds while the stream was running. That is usually radio "
        "interference, distance between the devices, or the phone being too busy to keep up"),
    "a2dp_reject": (
        "the device rejected the phone's audio stream settings, so music could not start; the two sides did "
        "not agree on a codec configuration"),
    "le_audio_fail": (
        "the earbuds refused a step of the LE Audio stream set-up, so that stream never started"),
    "aa_fail": (
        "the phone could not join the car's Wi-Fi network, so wireless Android Auto could not start. "
        "Bluetooth itself worked; the problem is on the Wi-Fi side (for example the phone's Wi-Fi being off, "
        "or the car's network being unreachable)"),
    "lost_pairing": (
        "the device no longer had the pairing key for this phone (it was removed from its paired list or "
        "reset), and it refused to pair again automatically. Removing the device on the phone and pairing both "
        "sides again fixes it"),
    "sync_fail": (
        "the phone refused the device's phonebook request. Contact sharing is probably not allowed for this "
        "device; allowing contact access in the phone's Bluetooth settings for the device fixes it"),
}

WHAT = {
    "volume_override": "the phone's volume changes on {name}",
    "player_error": "playback in the music app while connected to {name}",
    "no_service": "calls through {name}",
    "stall": "the music stream to {name}",
    "a2dp_reject": "the music stream set-up with {name}",
    "le_audio_fail": "an LE Audio stream to {name}",
    "aa_fail": "wireless Android Auto with {name}",
    "lost_pairing": "reconnecting to {name}",
    "sync_fail": "the phonebook sync with {name}",
}

FIRST_SEEN = {"volume_override": "volume", "player_error": "player", "stall": "stall", "a2dp_reject": "a2dp",
              "le_audio_fail": "gatt", "sync_fail": "sync"}


_SYNC_NAMES = {"Phonebook (PBAP)": "phonebook", "Messages (MAP)": "text messages",
               "Message alerts (MAP)": "message alerts"}


def _synced(transfer) -> str:
    """e.g. 'contacts (25 entries, 3 KB)' or 'single message (343 downloaded, 147 KB)'."""
    what = transfer.what
    if what.startswith("phonebook (") and what.endswith(")"):
        what = what[len("phonebook ("):-1]
    amount = describe_transfer(transfer).split(": ", 1)[-1].split(", over")[0].split(", took")[0]
    return f"{what} ({amount})"


def _clock(when: Optional[datetime.datetime]) -> str:
    return when.astimezone().strftime("%H:%M:%S") if when else "an unrecorded time"


def _span(seconds: float) -> str:
    whole = int(seconds)
    return f"{whole // 60}m {whole % 60:02d}s" if whole >= 60 else f"{whole}s"


def _name(report: SessionReport, address: str) -> str:
    device = next((d for d in report.devices if d.address == address), None)
    return f'{address} ("{device.name}")' if device and device.name else address


def _story(report: SessionReport) -> str:
    """What each device did, in a sentence or two each."""
    parts = []
    for device in report.devices:
        profile: Optional[DeviceProfiles] = report.profiles.get(device.address)
        connections = [c for c in report.connections if c.device == device.address]
        facts = []
        if profile is not None:
            if profile.streams:
                total = sum((e - s).total_seconds() for s, e, _, _ in profile.streams)
                facts.append(f"music played {len(profile.streams)} time(s), {_span(total)} in total"
                             + (f" ({profile.codec.split(',')[0]})" if profile.codec else ""))
            if profile.le_audio:
                uses = ", ".join(profile.le_audio_uses) or "audio"
                facts.append(f"{len(profile.le_audio)} LE Audio stream(s) for {uses}")
            if profile.buttons:
                facts.append("buttons pressed: " + ", ".join(f"{b} x{n}" for b, n in profile.buttons.most_common()))
            if profile.hfp_first:
                calls = profile.incoming + profile.outgoing
                facts.append(f"{calls} call(s)" if calls else "the hands-free link was up with no calls")
            for service, transfers in profile.syncs.items():
                done = [_synced(t) for t in transfers if (t.entries or t.requests > 1) and not t.failures]
                if done:
                    facts.append(f"{_SYNC_NAMES.get(service, service)} synced: {', '.join(done)}")
            if profile.android_auto_wifi and profile.android_auto_wifi[1]:
                facts.append(f"wireless Android Auto started at {_clock(profile.android_auto_start)}")
        if connections:
            last = connections[-1]
            who = {"phone": "this phone", "device": "the other device"}.get(last.ended_by or "")
            if last.end:
                facts.append(f"the connection ended at {_clock(last.end)}"
                             + (f" when {who} closed it" if who else ""))
        if facts:
            parts.append(f"{_name(report, device.address)}: " + "; ".join(facts) + ".")
    return " ".join(parts)


def normal_answer(report: SessionReport, routine: list[str]) -> str:
    text = "Nothing failed — the session looks normal. " + _story(report)
    if routine:
        text += (f"\nThe routine failures listed ({', '.join(routine)}) are common on Android and are not a "
                 "problem by themselves.")
    return text.strip()


def _warning_line(report: SessionReport, address: str, kind: str) -> str:
    """The detail the model sees for this problem, restated."""
    profile = report.profiles.get(address)
    if kind == "volume_override" and profile and profile.volume_overrides:
        phone, device = profile.volume_overrides[-1]
        return (f"the device overrode the phone's volume {len(profile.volume_overrides)} time(s) "
                f"(e.g. phone set {phone}%, device answered {device}%)")
    if kind == "player_error" and profile:
        return f"the music app reported a playback error {profile.player_errors} time(s)"
    if kind == "stall" and profile:
        return f"audio stalled {profile.stalls} time(s) while playing"
    if kind == "a2dp_reject" and profile and profile.a2dp_errors:
        return profile.a2dp_errors[0]
    if kind == "le_audio_fail" and profile and profile.gatt_errors:
        return profile.gatt_errors[0]
    if kind == "sync_fail" and profile:
        failed = [t for ts in profile.syncs.values() for t in ts if t.failures]
        if failed:
            return f"the {failed[0].what} request failed ({failed[0].failures[0]})"
    return ""


def problem_answer(report: SessionReport, stats, address: str, kind: str, routine: list[str]) -> tuple[str, list[str]]:
    """Answer for a session with one problem; returns (answer, facts the answer must contain)."""
    profile = report.profiles.get(address)
    name = _name(report, address)
    when_ts = None
    if profile is not None and kind in FIRST_SEEN:
        when_ts = profile.first_seen.get(FIRST_SEEN[kind])
    if kind == "aa_fail" and profile and profile.android_auto_wifi:
        when_ts = profile.android_auto_wifi[0]
    if kind == "lost_pairing":
        when_ts = next((i["timestamp"] for i in stats.issues if i["title"] == "Authentication Failed"), None)
    when = f"at {_clock(when_ts)}" if kind != "no_service" else "throughout the session"
    detail = _warning_line(report, address, kind)
    cause = CAUSES[kind]
    if detail:
        cause = f"{detail[0].upper()}{detail[1:]}. This means {cause}"
    text = (f"Yes, something failed.\n(1) What failed: {WHAT[kind].format(name=name)}.\n(2) When: {when}.\n"
            f"(3) Likely root cause: {cause}.")
    story = _story(report)
    if story:
        text += f"\nOtherwise: {story}"
    if routine:
        text += (f"\nThe routine failures listed ({', '.join(routine)}) are common on Android and are not a "
                 "problem by themselves.")
    facts = {
        "volume_override": ["overrode", "volume"], "player_error": ["playback error"],
        "no_service": ["no cellular service"], "stall": ["stalled"], "aa_fail": ["wi-fi"],
        "lost_pairing": ["pairing key"],
    }.get(kind, [])
    if kind == "a2dp_reject" and detail:
        facts = [detail.rsplit(": ", 1)[-1]]  # e.g. "codec type not supported"
    elif kind == "le_audio_fail" and detail:
        reason = detail.rsplit("-> ", 1)[-1]  # e.g. "stream 1 unsupported setting (frame size)"
        facts = [reason.split(" ", 2)[-1].split(" (")[0]]
    elif kind == "sync_fail" and profile:
        failed = [t for ts in profile.syncs.values() for t in ts if t.failures]
        facts = [failed[0].failures[0]] if failed else []
    return text, facts + [address]


# Which problem to lead with: the ones that stop the device working come first.
PRIORITY = ["lost_pairing", "a2dp_reject", "le_audio_fail", "aa_fail", "sync_fail", "stall", "no_service",
            "player_error", "volume_override"]

SHORT_LABELS = {
    "lost_pairing": "Pairing", "a2dp_reject": "Music set-up", "le_audio_fail": "LE Audio", "aa_fail": "Android Auto",
    "sync_fail": "Phonebook", "stall": "Audio", "no_service": "Calls", "player_error": "Music app",
    "volume_override": "Volume",
}

SHORT_CAUSES = {
    "lost_pairing": "the device lost its pairing with this phone; remove it on the phone and pair again",
    "a2dp_reject": "the device rejected the stream settings, so music could not start",
    "le_audio_fail": "the earbuds refused a stream set-up step",
    "aa_fail": "the phone could not join the car's Wi-Fi, so wireless Android Auto could not start",
    "sync_fail": "contact sharing is probably not allowed for this device in the phone's Bluetooth settings",
    "stall": "usually interference, distance, or the phone being too busy",
    "no_service": "the phone had no cellular service, so calls through the device would fail",
    "player_error": "a problem in the music app or the track, not Bluetooth",
    "volume_override": 'the device ignores the phone\'s volume; "Disable absolute volume" in developer options '
                       "usually helps",
}


def _when(report: SessionReport, stats, address: str, kind: str) -> str:
    profile = report.profiles.get(address)
    when_ts = None
    if profile is not None and kind in FIRST_SEEN:
        when_ts = profile.first_seen.get(FIRST_SEEN[kind])
    if kind == "aa_fail" and profile and profile.android_auto_wifi:
        when_ts = profile.android_auto_wifi[0]
    if kind == "lost_pairing":
        when_ts = next((i["timestamp"] for i in stats.issues if i["title"] == "Authentication Failed"), None)
    return "throughout the session" if kind == "no_service" else f"at {_clock(when_ts)}"


def multi_answer(report: SessionReport, stats, address: str, kinds: list[str], routine: list[str]
                 ) -> tuple[str, list[str]]:
    """Answer for a session with several problems: the main one in full, then each other one briefly."""
    ordered = sorted(kinds, key=PRIORITY.index)
    main, rest = ordered[0], ordered[1:]
    single, facts = problem_answer(report, stats, address, main, [])
    what, when, cause = single.split("\n")[1:4]
    text = ("Yes, several things failed.\n" + what.replace("(1) What failed:", "(1) Main problem:") + "\n"
            + when + "\n" + cause + "\nAlso:")
    for kind in rest:
        detail = _warning_line(report, address, kind) or WHAT[kind].format(name=_name(report, address))
        text += f"\n- {SHORT_LABELS[kind]}: {detail}, {_when(report, stats, address, kind)} — {SHORT_CAUSES[kind]}."
        facts += problem_answer(report, stats, address, kind, [])[1][:-1]
    story = _story(report)
    if story:
        text += f"\nOtherwise: {story}"
    if routine:
        text += (f"\nThe routine failures listed ({', '.join(routine)}) are common on Android and are not a "
                 "problem by themselves.")
    return text, list(dict.fromkeys(facts))


def visible(report: SessionReport, stats, address: str, kind: str) -> bool:
    """True when the problem shows up in what the model is given."""
    profile = report.profiles.get(address)
    if profile is None:
        return kind == "lost_pairing" and any(i["title"] == "Authentication Failed" for i in stats.issues)
    return {
        "volume_override": bool(profile.volume_overrides), "player_error": profile.player_errors > 0,
        "no_service": profile.no_service, "stall": profile.stalls > 0, "a2dp_reject": bool(profile.a2dp_errors),
        "le_audio_fail": bool(profile.gatt_errors),
        "aa_fail": bool(profile.android_auto_wifi and not profile.android_auto_wifi[1]),
        "sync_fail": any(t.failures for ts in profile.syncs.values() for t in ts),
        "lost_pairing": any(i["title"] == "Authentication Failed" for i in stats.issues),
    }.get(kind, False)
