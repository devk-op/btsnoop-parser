btsnoop-parser
==============

A lightweight Python library and CLI for parsing and analysing Bluetooth
``btsnoop_hci.log`` captures from Android devices — a fast, scriptable
alternative to opening Wireshark.

.. code-block:: bash

   pip install btsnoop-parser

.. toctree::
   :maxdepth: 2
   :caption: Contents

   cli
   api

Quick start
-----------

.. code-block:: python

   from btsnoop_parser import parse_btsnoop_file, filter_records, write_pcap

   records = parse_btsnoop_file("btsnoop_hci.log")

   # Keep only HCI events
   events = filter_records(records, ["type:event"])

   # Export to Wireshark-compatible PCAP
   write_pcap(records, "capture.pcap")
