CLI Reference
=============

After ``pip install btsnoop-parser`` the ``btsnoop_parser`` command is available.

Usage
-----

.. code-block:: text

   btsnoop_parser <file> [options]

Options
-------

.. option:: --limit N

   Show only the first *N* records.

.. option:: --filter EXPR

   Filter records by a ``key:value`` expression.  May be repeated to combine
   filters (all must match).

   Supported keys:

   * ``type`` — packet type.  Values: ``command`` (or ``cmd``), ``acl``,
     ``event`` (or ``evt``), ``sco``, ``iso``, or a hex literal ``0xNN``.
     Comma-separate for OR logic: ``type:command,event``.
   * ``dir`` — direction: ``tx`` or ``rx``.

.. option:: --pcap OUTPUT.pcap

   Write matching records to a PCAP file (link type 201,
   ``LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR``).  The file can be opened directly
   in Wireshark or piped to ``tshark``.

.. option:: --json

   Emit records as a JSON array.  Payload bytes are hex-encoded.

.. option:: --pretty

   Pretty-print the JSON output (implies ``--json``).

.. option:: --decode

   Print decoded HCI command/event metadata beneath the table.

.. option:: --stats

   Analyse the capture and print connection history, detected devices, and
   potential issues.

.. option:: --no-color

   Disable ANSI colour codes in output.

Examples
--------

.. code-block:: bash

   # Wireshark-style table, first 20 packets
   btsnoop_parser capture.log --limit 20

   # Show only HCI events going host→controller
   btsnoop_parser capture.log --filter type:event --filter dir:tx

   # Export events to PCAP for Wireshark
   btsnoop_parser capture.log --filter type:event --pcap events.pcap

   # Convert entire capture to PCAP
   btsnoop_parser capture.log --pcap full.pcap

   # Pipe to tshark for further analysis
   btsnoop_parser capture.log --pcap - | tshark -r -

   # Capture statistics and issue detection
   btsnoop_parser capture.log --stats

   # Scripting with JSON
   btsnoop_parser capture.log --json | jq '[.[] | select(.direction=="RX")]'
