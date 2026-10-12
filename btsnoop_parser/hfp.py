"""Hands-Free Profile (HFP) decoding.

HFP is a text conversation over RFCOMM. The hands-free unit (headset, car kit)
sends ``AT`` commands; the audio gateway (phone) answers with result codes such
as ``+CIEV`` or ``OK``. :class:`HfpSession` turns each line into a plain-English
description of what the two sides are doing.
"""
from __future__ import annotations

import re
from typing import Optional

CODECS = {1: "CVSD", 2: "mSBC", 3: "LC3-SWB"}

HF_FEATURES = [
    "echo cancel/noise reduction", "three-way calling", "caller ID", "voice recognition",
    "remote volume control", "enhanced call status", "enhanced call control", "codec negotiation",
    "HF indicators", "eSCO S4", "enhanced voice recognition", "voice recognition text",
]
AG_FEATURES = [
    "three-way calling", "echo cancel/noise reduction", "voice recognition", "in-band ringtone",
    "voice tag", "reject call", "enhanced call status", "enhanced call control",
    "extended error codes", "codec negotiation", "HF indicators", "eSCO S4",
    "enhanced voice recognition", "voice recognition text",
]

_INDICATOR_VALUES = {
    "call": {0: "no call active", 1: "call active"},
    "callsetup": {0: "no call being set up", 1: "incoming call", 2: "outgoing call dialing",
                  3: "outgoing call, remote party ringing"},
    "callheld": {0: "no calls held", 1: "call held, another active", 2: "call on hold"},
    "service": {0: "no network service", 1: "network service available"},
    "roam": {0: "not roaming", 1: "roaming"},
}
_INDICATOR_LABELS = {"signal": "signal strength", "battchg": "phone battery"}

_HOLD_ACTIONS = {
    "0": "release held calls / reject waiting call",
    "1": "end active call and accept the other",
    "2": "hold active call and accept the other",
    "3": "merge calls into a conference",
    "4": "connect the two calls and leave",
}

_CALL_STATES = {"0": "active", "1": "held", "2": "dialing", "3": "alerting", "4": "incoming", "5": "waiting"}

_FINAL_RESULTS = {
    "OK": "OK",
    "ERROR": "Command rejected",
    "RING": "Incoming call is ringing",
    "NO CARRIER": "Call could not be connected",
    "BUSY": "Remote party is busy",
    "NO ANSWER": "Remote party did not answer",
    "DELAYED": "Call delayed",
    "BLACKLISTED": "Number is blocked",
}

_COMMAND = re.compile(r"^AT([+^][A-Z0-9]+|[A-Z])(.*)$", re.IGNORECASE)
_RESULT = re.compile(r"^([+^][A-Z0-9 ]+?):\s*(.*)$", re.IGNORECASE)


def looks_like_at(text: str) -> bool:
    """True when a line is an AT command or a result code."""
    line = text.strip().upper()
    return line.startswith("AT") or line in _FINAL_RESULTS or bool(_RESULT.match(line))


def _features(value: str, names: list[str]) -> str:
    try:
        bits = int(value)
    except ValueError:
        return value
    found = [name for i, name in enumerate(names) if bits & (1 << i)]
    return ", ".join(found) if found else "none"


def _codec(value: str) -> str:
    value = value.strip()
    return CODECS.get(int(value), f"codec {value}") if value.isdigit() else value


def _volume(value: str) -> str:
    return f"{value.strip()}/15"


class HfpSession:
    """Describes the AT traffic of one HFP connection."""

    def __init__(self) -> None:
        self._indicators: list[str] = []

    def describe(self, line: str) -> tuple[str, bool]:
        """Return (description, is_error) for one AT command or result line."""
        line = line.strip()
        if line.upper() in _FINAL_RESULTS:
            return _FINAL_RESULTS[line.upper()], line.upper() == "ERROR"
        command = _COMMAND.match(line)
        if command:
            return self._describe_command(command.group(1).upper().lstrip("+"), command.group(2)), False
        result = _RESULT.match(line)
        if result:
            name = result.group(1).upper().lstrip("+")
            return self._describe_result(name, result.group(2)), name == "CME ERROR"
        return "Unrecognized line", False

    def _indicator(self, index: str, value: str) -> str:
        position = int(index) - 1 if index.isdigit() else -1
        if not 0 <= position < len(self._indicators):
            return f"indicator {index} = {value}"
        name = self._indicators[position]
        if value.isdigit() and int(value) in _INDICATOR_VALUES.get(name, {}):
            return _INDICATOR_VALUES[name][int(value)]
        return f"{_INDICATOR_LABELS.get(name, name)} {value}/5" if name in _INDICATOR_LABELS else f"{name} = {value}"

    def _describe_command(self, name: str, rest: str) -> str:
        test, read = rest == "=?", rest == "?"
        arg = rest[1:] if rest.startswith("=") and not test else ""

        if name == "BRSF":
            return f"Hands-free reports its features: {_features(arg, HF_FEATURES)}"
        if name == "BAC":
            return "Hands-free supports codecs: " + ", ".join(_codec(c) for c in arg.split(","))
        if name == "CIND":
            return "Asks which status indicators the phone has" if test else "Asks for the current status values"
        if name == "CMER":
            enabled = arg.split(",")[-1].strip() == "1"
            return ("Turns on" if enabled else "Turns off") + " status updates from the phone"
        if name == "CHLD":
            if test:
                return "Asks which call hold/multi-party actions the phone supports"
            return f"Call control: {_HOLD_ACTIONS.get(arg[:1], arg)}"
        if name == "BIND":
            if test:
                return "Asks which hands-free indicators the phone supports"
            if read:
                return "Asks which hands-free indicators are enabled"
            return f"Hands-free lists its indicators: {arg}"
        if name == "BIEV":
            ident, _, value = arg.partition(",")
            if ident.strip() == "2":
                return f"Hands-free battery level: {value.strip()}%"
            return f"Hands-free indicator {ident.strip()} = {value.strip()}"
        if name == "CLIP":
            return ("Turns on" if arg == "1" else "Turns off") + " caller ID notifications"
        if name == "CCWA":
            return ("Turns on" if arg == "1" else "Turns off") + " call waiting notifications"
        if name == "CMEE":
            return ("Turns on" if arg == "1" else "Turns off") + " detailed error codes"
        if name == "NREC":
            return "Asks the phone to turn off its echo cancel/noise reduction"
        if name == "VGS":
            return f"Hands-free speaker volume is {_volume(arg)}"
        if name == "VGM":
            return f"Hands-free microphone gain is {_volume(arg)}"
        if name == "BCC":
            return "Hands-free asks the phone to open the audio link"
        if name == "BCS":
            return f"Hands-free confirms codec {_codec(arg)}"
        if name == "BVRA":
            return ("Starts" if arg[:1] == "1" else "Stops") + " the voice assistant"
        if name == "A":
            return "Answers the incoming call"
        if name == "CHUP":
            return "Hangs up / rejects the call"
        if name == "D":
            return f"Dials {rest.rstrip(';')}"
        if name == "BLDN":
            return "Redials the last number"
        if name == "VTS":
            return f"Sends keypad tone {arg}"
        if name == "CLCC":
            return "Asks for the list of current calls"
        if name == "COPS":
            return "Asks for the network operator name" if read else "Sets the operator name format"
        if name == "CNUM":
            return "Asks for the phone's own number"
        if name == "BIA":
            return "Chooses which status updates to receive"
        if name == "BTRH":
            return "Asks about / controls response-and-hold"
        if name == "CKPD":
            return "Headset button pressed"
        if name == "XAPL":
            return "Apple accessory identifies itself"
        if name == "IPHONEACCEV":
            return _apple_accessory_event(arg)
        if name in ("XEVENT", "ANDROID", "CSRSF", "CSRBATT", "CSR"):
            return "Vendor-specific command"
        return "Command"

    def _describe_result(self, name: str, value: str) -> str:
        if name == "BRSF":
            return f"Phone reports its features: {_features(value, AG_FEATURES)}"
        if name == "CIND":
            names = re.findall(r'\("([^"]+)"', value)
            if names:
                self._indicators = [n.lower() for n in names]
                return "Phone lists its status indicators: " + ", ".join(self._indicators)
            values = [v.strip() for v in value.split(",")]
            parts = [self._indicator(str(i), v) for i, v in enumerate(values, 1)]
            return "Current status: " + "; ".join(parts)
        if name == "CIEV":
            index, _, val = value.partition(",")
            return "Status update: " + self._indicator(index.strip(), val.strip())
        if name == "CHLD":
            return f"Phone supports call control actions {value}"
        if name == "BCS":
            return f"Phone selects codec {_codec(value)}"
        if name == "VGS":
            return f"Phone sets speaker volume to {_volume(value)}"
        if name == "VGM":
            return f"Phone sets microphone gain to {_volume(value)}"
        if name == "BVRA":
            return "Voice assistant " + ("started" if value[:1] == "1" else "stopped")
        if name == "CLIP":
            return f"Caller ID: {value.split(',')[0].strip(chr(34))}"
        if name == "CCWA":
            return f"Call waiting: {value.split(',')[0].strip(chr(34))}"
        if name == "CLCC":
            fields = [f.strip() for f in value.split(",")]
            if len(fields) >= 3:
                way = "incoming" if fields[1] == "1" else "outgoing"
                return f"Call {fields[0]}: {way}, {_CALL_STATES.get(fields[2], fields[2])}"
            return "Call list entry"
        if name == "COPS":
            operator = re.search(r'"([^"]*)"', value)
            return f"Network operator: {operator.group(1)}" if operator else "Network operator not available"
        if name == "CNUM":
            number = re.search(r'"([^"]*)"', value)
            return f"Phone number: {number.group(1)}" if number else "Phone number"
        if name == "BSIR":
            return "Phone will " + ("play its own ringtone over the audio link" if value[:1] == "1"
                                    else "let the hands-free play the ringtone")
        if name == "BIND":
            return f"Hands-free indicators: {value}"
        if name == "CME ERROR":
            return f"Command failed (error {value})"
        if name in ("XAPL", "XEVENT", "ANDROID"):
            return "Vendor-specific response"
        return "Result"


def _apple_accessory_event(arg: str) -> str:
    fields = [f.strip() for f in arg.split(",")]
    pairs = list(zip(fields[1::2], fields[2::2]))
    parts = []
    for key, value in pairs:
        if key == "1" and value.isdigit():
            parts.append(f"battery about {(int(value) + 1) * 10}%")
        elif key == "2":
            parts.append("docked" if value == "1" else "not docked")
    return "Accessory status: " + ", ".join(parts) if parts else "Accessory status report"


def split_lines(buffer: str) -> tuple[list[str], str]:
    """Split buffered AT text into complete lines and the unfinished remainder."""
    if not buffer:
        return [], ""
    pieces = re.split(r"[\r\n]+", buffer)
    remainder = "" if buffer[-1] in "\r\n" else pieces.pop()
    return [p for p in pieces if p.strip()], remainder


def decode_text(payload: bytes) -> Optional[str]:
    """Return the payload as text if it is printable ASCII, else None."""
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError:
        return None
    return text if all(c.isprintable() or c in "\r\n" for c in text) else None
