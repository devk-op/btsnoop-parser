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

.. option:: --ai

   Ask a local LLM to diagnose capture issues in plain English. Requires the
   ``ai`` extra (``pip install "btsnoop-parser[ai]"``) — pulls in ``torch``
   and ``transformers``. Runs entirely locally; only a summarized version of
   the capture is sent to the model, never raw packets.

.. option:: --question TEXT

   Question to ask the LLM about the capture (used with ``--ai``). Defaults
   to asking why the session failed and what the likely root cause is.

.. option:: --base-model NAME

   Hugging Face model id to use for ``--ai`` (default:
   ``Qwen/Qwen2.5-1.5B-Instruct``).

.. option:: --adapter-path DIR

   Path to a LoRA adapter directory to specialize the ``--ai`` model — see
   ``training/README.md`` for how to fine-tune one.

.. option:: --link-keys

   Extract Classic BT link keys seen in HCI traffic (Link Key Notification
   events and Link Key Request Reply commands) and print device address, key,
   and key type. A link key is credential material — only use this against
   captures you're authorized to analyze. BLE (LTK) isn't covered.

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

   # Ask a local LLM to diagnose issues (requires the 'ai' extra)
   btsnoop_parser capture.log --ai
   btsnoop_parser capture.log --ai --question "Why did the connection drop?"

   # Extract Classic BT link keys (your own authorized captures only)
   btsnoop_parser capture.log --link-keys

   # Scripting with JSON
   btsnoop_parser capture.log --json | jq '[.[] | select(.direction=="RX")]'
