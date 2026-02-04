from __future__ import annotations

import sys
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
from btsnoop_parser.cli import main

@patch("sys.stdout", new_callable=StringIO)
@patch("btsnoop_parser.cli.parse_btsnoop_file")
@patch("btsnoop_parser.cli.print_table")
def test_cli_simple_invocation(mock_print_table, mock_parse, mock_stdout):
    """Test standard CLI invocation without flags."""
    test_args = ["btsnoop_parser", "test.log"]
    mock_parse.return_value = [{"index": 1, "packet_type": 1, "payload": b"\x00"}]
    
    with patch.object(sys, "argv", test_args):
        main()
    
    mock_parse.assert_called_once_with("test.log")
    mock_print_table.assert_called_once()
    assert not mock_stdout.getvalue()  # print_table handles output usually, assumed mocked

@patch("sys.stdout", new_callable=StringIO)
@patch("btsnoop_parser.cli.parse_btsnoop_file")
def test_cli_json_output(mock_parse, mock_stdout):
    """Test --json flag output."""
    test_args = ["btsnoop_parser", "test.log", "--json"]
    # Mock a record causing serialization
    mock_parse.return_value = [
        {"index": 1, "packet_type": 1, "payload": b"\x01", "timestamp": None}
    ]
    
    with patch.object(sys, "argv", test_args):
        main()
    
    output = mock_stdout.getvalue()
    assert '"payload": "01"' in output
    assert '"index": 1' in output

@patch("sys.stdout", new_callable=StringIO)
@patch("btsnoop_parser.cli.parse_btsnoop_file")
def test_cli_json_pretty_output(mock_parse, mock_stdout):
    """Test --json --pretty flag output."""
    test_args = ["btsnoop_parser", "test.log", "--json", "--pretty"]
    mock_parse.return_value = [
        {"index": 1, "packet_type": 1, "payload": b"\x01"}
    ]
    
    with patch.object(sys, "argv", test_args):
        main()
    
    output = mock_stdout.getvalue()
    # Check for indentation (newlines usually present in pretty print)
    assert "\n" in output
    assert '"index": 1' in output

@patch("btsnoop_parser.cli.print_table")
@patch("btsnoop_parser.cli.parse_btsnoop_file")
@patch("btsnoop_parser.cli.decode_hci_packet")
def test_cli_decode_flag(mock_decode, mock_parse, mock_print_table):
    """Test --decode flag invocation."""
    test_args = ["btsnoop_parser", "test.log", "--decode"]
    mock_parse.return_value = [
        {"index": 1, "packet_type": 1, "payload": b"\x00", "packet_data": b""}
    ]
    mock_decode.return_value = "Decoded Packet"
    
    with patch.object(sys, "argv", test_args):
        # We also need to mock print because decode loop prints directly
        with patch("builtins.print") as mock_print:
            main()
            
    # call args list should contain the decoded string
    assert any("Decoded Packet" in str(call) for call in mock_print.call_args_list)

def test_cli_help():
    """Test --help flag exits locally."""
    with patch.object(sys, "argv", ["btsnoop_parser", "--help"]):
        with pytest.raises(SystemExit):
            main()
