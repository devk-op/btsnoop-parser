"""Short plain-English notes on common HCI status codes, written for this project.

Used only to write the training answers. Kept to codes whose usual meaning is
well established; codes not listed here get an answer that sticks to the code's
name instead of guessing.
"""
from __future__ import annotations

CODE_NOTES = {
    0x02: "the command referred to a connection that no longer exists, usually because it had already closed",
    0x03: "the Bluetooth controller reported an internal hardware fault",
    0x04: "the other device never answered the connection request — it was most likely out of range, switched off, or not accepting connections",
    0x05: "authentication failed, which usually means the two devices no longer agree on their pairing keys; removing and re-pairing the device typically fixes it",
    0x06: "one side has no stored key for the other, typically because the pairing was deleted on one device; re-pairing is needed",
    0x07: "the controller ran out of memory",
    0x08: "the link supervision timeout expired: the two devices stopped hearing each other, usually because of distance, interference, or the other device stopping responding",
    0x09: "the controller could not accept another connection because it is already at its limit",
    0x0B: "a connection to that device already existed",
    0x0C: "the controller refused the command in its current state",
    0x0D: "the other device rejected the connection because it lacked resources",
    0x0E: "the other device rejected the connection for security reasons",
    0x10: "an incoming connection was not accepted in time",
    0x11: "a requested feature or parameter value is not supported",
    0x12: "the host sent parameters the controller considers invalid",
    0x1A: "the other device does not support a feature that was requested",
    0x1F: "the controller reported a failure without giving a specific reason",
    0x22: "the other device did not answer a link-layer procedure in time",
    0x28: "a timed link-layer change was scheduled for a moment that had already passed, typically caused by timing problems or interference",
    0x2F: "the security level of the link was not high enough for the request",
    0x3A: "the controller was too busy to handle the request",
    0x3B: "the other device rejected the requested connection parameters",
    0x3D: "the encryption integrity check failed, which usually points to mismatched keys or corrupted packets",
    0x3E: "the LE connection request was sent but the link never came up, because the other device was not heard after the request",
}
