HCI_PACKET_TYPES = {
    0x01: "COMMAND",
    0x02: "ACL",
    0x03: "SCO",
    0x04: "EVENT",
    0x05: "ISO",
    0xFF: "VENDOR",
}

HCI_OPCODE_NAMES = {
    0x0401: "Inquiry",
    0x0405: "Create Connection",
    0x0406: "Disconnect",
    0x0C01: "Set Event Mask",
    0x0C03: "Reset",
    0x1001: "Read Local Version Information",
    0x1002: "Read Local Supported Commands",
    0x1003: "Read Local Supported Features",
    0x1009: "Read BD_ADDR",
    0x2001: "LE Set Event Mask",
    0x2003: "LE Read Local Supported Features",
    0x201C: "LE Read Supported States",
    # Add more opcodes as needed
}
