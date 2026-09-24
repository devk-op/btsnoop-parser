"""Regression tests for the HCI opcode table."""
from __future__ import annotations

import unittest

from btsnoop_parser import core
from btsnoop_parser.constants import HCI_OPCODE_NAMES
from btsnoop_parser.security import _LINK_KEY_REQUEST_REPLY_OPCODE


class TestOpcodeTable(unittest.TestCase):
    def test_known_opcodes(self):
        expected = {
            0x0401: "Inquiry",
            0x0405: "Create Connection",
            0x040B: "Link Key Request Reply",
            0x040C: "Link Key Request Negative Reply",
            0x040D: "PIN Code Request Reply",
            0x0C03: "Reset",
            0x0C1F: "Read Authentication Enable",
            0x0C52: "Write Extended Inquiry Response",
            0x100D: "Read Local Supported Codecs (V2)",
            0x200C: "LE Set Scan Enable",
            0x2019: "LE Start Encryption",
            0x201A: "LE Long Term Key Request Reply",
        }
        for opcode, name in expected.items():
            self.assertEqual(HCI_OPCODE_NAMES.get(opcode), name, hex(opcode))

    def test_names_are_unique(self):
        names = list(HCI_OPCODE_NAMES.values())
        duplicates = {n for n in names if names.count(n) > 1}
        self.assertFalse(duplicates, f"same name assigned to multiple opcodes: {duplicates}")

    def test_opcode_group_field_is_valid(self):
        valid_ogfs = {0x01, 0x02, 0x03, 0x04, 0x05, 0x08}
        for opcode in HCI_OPCODE_NAMES:
            self.assertIn(opcode >> 10, valid_ogfs, hex(opcode))

    def test_security_opcode_matches_table(self):
        self.assertEqual(HCI_OPCODE_NAMES[_LINK_KEY_REQUEST_REPLY_OPCODE], "Link Key Request Reply")

    def test_core_shares_the_same_table(self):
        self.assertIs(core.CMD_NAMES, HCI_OPCODE_NAMES)


if __name__ == "__main__":
    unittest.main()
