Python API
==========

Parsing
-------

.. autofunction:: btsnoop_parser.parse_btsnoop_file

.. autofunction:: btsnoop_parser.iter_records

Filtering
---------

.. autofunction:: btsnoop_parser.filter_records

PCAP export
-----------

.. autofunction:: btsnoop_parser.write_pcap

HCI decoding
------------

.. autofunction:: btsnoop_parser.decode_hci_packet

Display
-------

.. autofunction:: btsnoop_parser.print_table

.. autofunction:: btsnoop_parser.slice_records

Analysis
--------

.. autoclass:: btsnoop_parser.analysis.CaptureStats
   :members:
   :undoc-members:

LLM analysis
------------

Requires the ``ai`` extra (``pip install "btsnoop-parser[ai]"``).

.. autofunction:: btsnoop_parser.llm.build_context

.. autofunction:: btsnoop_parser.llm.ask

Security
--------

.. autofunction:: btsnoop_parser.security.extract_link_keys
