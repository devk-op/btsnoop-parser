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

.. option:: --protocols

   Decode the protocols carried above HCI and print a timeline: L2CAP channels
   opening and closing (labelled SDP, RFCOMM, AVDTP, ATT, ...), RFCOMM serial
   ports, HFP commands with a plain-English meaning, and voice (SCO/eSCO) links.
   Needs a capture that includes ACL data.

.. option:: --ai

   Ask a local model whether anything failed, and why, in plain English.
   Requires the ``ai`` extra (``pip install "btsnoop-parser[ai]"``) — pulls in
   ``torch`` and ``transformers``. Runs entirely locally; the model reads a
   summary of the capture, never raw packets. The default model is
   ``Qwen/Qwen2.5-0.5B-Instruct`` with the
   ``kdonut/btsnoop-hci-qwen2.5-0.5b-lora`` adapter, fine-tuned for this
   summary format.

.. option:: --question TEXT

   Question to ask the LLM about the capture (used with ``--ai``). Defaults
   to asking what happened, whether anything actually failed, and if so the
   likely root cause.

.. option:: --base-model NAME

   Hugging Face model id, or the path of a local model folder, to use for
   ``--ai``. Defaults to the ``BTSNOOP_AI_MODEL`` environment variable if it
   is set, otherwise ``Qwen/Qwen2.5-0.5B-Instruct``.

.. option:: --adapter-path DIR

   LoRA adapter to specialize the ``--ai`` model: a local folder or a Hugging
   Face repo id. Defaults to the btsnoop-hci adapter when the default model is
   used, and to no adapter otherwise. See ``training/README.md`` for how to
   train one.

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

   # What the devices said above HCI: channels, serial ports, HFP commands
   btsnoop_parser capture.log --protocols

   # Ask a local LLM to diagnose issues (requires the 'ai' extra)
   btsnoop_parser capture.log --ai
   btsnoop_parser capture.log --ai --question "Why did the connection drop?"

   # Extract Classic BT link keys (your own authorized captures only)
   btsnoop_parser capture.log --link-keys

   # Scripting with JSON
   btsnoop_parser capture.log --json | jq '[.[] | select(.direction=="RX")]'
