"""Tests for the full session report (btsnoop_parser.report)."""
from __future__ import annotations

import io
import json
import struct
import unittest
from contextlib import redirect_stdout

from btsnoop_parser.report import build_report, class_of_device, print_report
from tests.test_protocols import _ADDR, _HANDLE, _Capture

_CAR = "11:22:33:44:55:66"


def _command(capture: _Capture, opcode: int, params: bytes = b"") -> None:
    capture._add(0x01, "TX", struct.pack("<HB", opcode, len(params)) + params)


def _complete(capture: _Capture, opcode: int, ret: bytes) -> None:
    capture.event(bytes([0x0E, 3 + len(ret), 0x01]) + struct.pack("<H", opcode) + ret)


def _session() -> _Capture:
    capture = _Capture()
    _complete(capture, 0x1009, b"\x00" + bytes.fromhex("A9673AA61CC0"))  # Read BD_ADDR
    _complete(capture, 0x1001, bytes([0x00, 0x0E, 0, 0, 0x0E, 0x0F, 0x00, 0, 0]))  # Bluetooth 6.0, Broadcom
    _command(capture, 0x0C13, b"Pixel\x00")
    # Extended Inquiry Result: name and class of device (car audio)
    eir = bytes([7, 0x09]) + b"MyCar\x00"
    capture.event(bytes([0x2F, 0xFF, 0x01]) + _ADDR + bytes([1, 0]) + bytes([0x20, 0x04, 0x24]) + bytes([0, 0, 0xC5])
                  + eir)
    _command(capture, 0x0405, _ADDR + bytes(7))  # Create Connection
    capture.wait(1.5)
    capture.connected()
    capture.event(bytes([0x36, 0x07, 0x00]) + _ADDR)  # Simple Pairing Complete: success
    capture.event(bytes([0x59, 0x05, 0x00]) + struct.pack("<H", _HANDLE) + bytes([0x01, 0x10]))  # encrypted
    capture.event(bytes([0x14, 0x06, 0x00]) + struct.pack("<H", _HANDLE) + bytes([0x02, 0x20, 0x03]))  # sniff
    capture.wait(10.0)
    capture.event(bytes([0x14, 0x06, 0x00]) + struct.pack("<H", _HANDLE) + bytes([0x00, 0x00, 0x00]))  # active
    capture.wait(10.0)
    capture.event(bytes([0x05, 0x04, 0x00]) + struct.pack("<H", _HANDLE) + bytes([0x13]))
    return capture


class TestReport(unittest.TestCase):
    def test_phone(self):
        phone = build_report(_session().records).phone
        self.assertEqual((phone.address, phone.name, phone.bluetooth_version, phone.chip_maker),
                         ("C0:1C:A6:3A:67:A9", "Pixel", "6.0", "Broadcom"))

    def test_device_identity(self):
        device = build_report(_session().records).devices[0]
        self.assertEqual((device.address, device.name, device.kind), (_CAR, "MyCar", "car audio"))
        self.assertEqual(device.signal_dbm, [-59])

    def test_connection_details(self):
        connection = build_report(_session().records).connections[0]
        self.assertEqual(connection.initiated_by, "phone")
        self.assertAlmostEqual(connection.connect_seconds, 1.5, places=1)
        self.assertEqual(connection.ended_by, "device")
        self.assertEqual(connection.security, ["paired (new pairing)"])
        self.assertTrue(connection.encrypted)
        self.assertAlmostEqual(connection.sniff_seconds, 10.0, places=1)

    def test_lost_pairing_is_explained(self):
        capture = _Capture()
        capture.connected()
        capture.event(bytes([0x06, 0x03, 0x06]) + struct.pack("<H", _HANDLE))  # PIN or Key Missing
        capture.event(bytes([0x36, 0x07, 0x18]) + _ADDR)  # Pairing Not Allowed
        report = build_report(capture.records)
        self.assertEqual(report.connections[0].security,
                         ["the device no longer had the pairing key", "pairing refused: Pairing Not Allowed"])
        self.assertEqual([i["title"] for i in report.issues], ["Authentication Failed", "Pairing Failed"])

    def test_le_link_settings(self):
        capture = _Capture()
        _command(capture, 0x200D)
        capture.wait(0.5)
        # LE Connection Complete: status, handle, role central, addr type, addr, interval 24 (30 ms), latency 0, timeout 400
        capture.event(bytes([0x3E, 0x13, 0x01, 0x00, _HANDLE, 0x00, 0x00, 0x00]) + _ADDR
                      + struct.pack("<HHH", 24, 0, 400) + b"\x00")
        capture.event(bytes([0x3E, 0x06, 0x0C, 0x00, _HANDLE, 0x00, 0x02, 0x02]))  # PHY 2M
        connection = build_report(capture.records).connections[0]
        self.assertEqual((connection.transport, connection.initiated_by, connection.role), ("LE", "phone", "central"))
        self.assertEqual((connection.le_interval_ms, connection.le_timeout_ms, connection.le_phy), (30.0, 4000, "2M"))

    def test_json_and_printing(self):
        report = build_report(_session().records)
        data = json.loads(json.dumps(report.to_dict(), default=str))
        self.assertEqual(data["devices"][0]["name"], "MyCar")
        self.assertAlmostEqual(data["connections"][0]["seconds"], 20.0, places=1)
        out = io.StringIO()
        with redirect_stdout(out):
            print_report(report, color=False)
        text = out.getvalue()
        self.assertIn('"Pixel", C0:1C:A6:3A:67:A9, Bluetooth 6.0, Broadcom chip', text)
        self.assertIn("started by the phone, took 1.5 s; ended by the device", text)

    def test_device_connected_before_the_capture(self):
        capture = _Capture()
        capture.media(0x0061, 1)
        devices = build_report(capture.records).devices
        self.assertEqual([(d.address, d.transports) for d in devices],
                         [("handle 0x00B", ["connected before the capture began"])])

    def test_class_of_device(self):
        self.assertEqual(class_of_device(0x240420), "car audio")
        self.assertEqual(class_of_device(0x240404), "wearable headset")
        self.assertEqual(class_of_device(0x000540), "keyboard")
        self.assertEqual(class_of_device(0x5A020C), "phone")


if __name__ == "__main__":
    unittest.main()
