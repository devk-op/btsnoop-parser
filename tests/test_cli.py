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

@patch("sys.stdout", new_callable=StringIO)
@patch("btsnoop_parser.llm.ask")
@patch("btsnoop_parser.cli.parse_btsnoop_file")
def test_cli_ai_flag_wires_question_and_model(mock_parse, mock_ask, mock_stdout):
    """--ai should build CaptureStats and pass --question/--base-model/--adapter-path through to ask()."""
    test_args = [
        "btsnoop_parser", "test.log", "--ai",
        "--question", "Why?", "--base-model", "custom/model", "--adapter-path", "/some/adapter",
    ]
    mock_parse.return_value = []
    mock_ask.return_value = "diagnosis text"

    with patch.object(sys, "argv", test_args):
        main()

    mock_ask.assert_called_once()
    _, kwargs = mock_ask.call_args
    assert kwargs["question"] == "Why?"
    assert kwargs["base_model"] == "custom/model"
    assert kwargs["adapter_path"] == "/some/adapter"
    assert "diagnosis text" in mock_stdout.getvalue()

@patch("sys.stdout", new_callable=StringIO)
@patch("btsnoop_parser.llm.ask")
@patch("btsnoop_parser.cli.parse_btsnoop_file")
def test_cli_ai_flag_default_model(mock_parse, mock_ask, mock_stdout):
    """--ai without --question/--base-model should fall back to llm's defaults."""
    from btsnoop_parser.llm import DEFAULT_BASE_MODEL, DEFAULT_QUESTION

    mock_parse.return_value = []
    mock_ask.return_value = "diagnosis text"

    with patch.object(sys, "argv", ["btsnoop_parser", "test.log", "--ai"]):
        main()

    _, kwargs = mock_ask.call_args
    assert kwargs["question"] == DEFAULT_QUESTION
    assert kwargs["base_model"] == DEFAULT_BASE_MODEL
    assert kwargs["adapter_path"] is None

@patch("btsnoop_parser.llm.ask")
@patch("btsnoop_parser.cli.parse_btsnoop_file")
def test_cli_ai_model_unavailable_exits_nonzero(mock_parse, mock_ask):
    """A ModelUnavailableError from ask() should exit non-zero with a friendly stderr message, not the argparse usage banner."""
    from btsnoop_parser.llm import ModelUnavailableError

    mock_parse.return_value = []
    mock_ask.side_effect = ModelUnavailableError('Install them with: pip install "btsnoop-parser[ai]"')

    with patch.object(sys, "argv", ["btsnoop_parser", "test.log", "--ai"]):
        with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
            with pytest.raises(SystemExit) as exc_info:
                main()

    assert exc_info.value.code == 1
    assert "pip install" in mock_stderr.getvalue()
    assert "usage:" not in mock_stderr.getvalue()

@patch("sys.stdout", new_callable=StringIO)
@patch("btsnoop_parser.security.extract_link_keys")
@patch("btsnoop_parser.cli.parse_btsnoop_file")
def test_cli_link_keys_flag_prints_results(mock_parse, mock_extract, mock_stdout):
    """--link-keys should call extract_link_keys() and print each result."""
    mock_parse.return_value = []
    mock_extract.return_value = [{
        "timestamp": "2024-01-01T00:00:00", "addr": "11:22:33:44:55:66",
        "link_key": "AA" * 16, "source": "Link Key Notification",
        "key_type": 0x05, "key_type_name": "Authenticated Combination key (P-192)",
    }]

    with patch.object(sys, "argv", ["btsnoop_parser", "test.log", "--link-keys"]):
        main()

    mock_extract.assert_called_once_with([])
    output = mock_stdout.getvalue()
    assert "11:22:33:44:55:66" in output
    assert "AA" * 16 in output
    assert "Authenticated Combination key (P-192)" in output

@patch("sys.stdout", new_callable=StringIO)
@patch("btsnoop_parser.security.extract_link_keys")
@patch("btsnoop_parser.cli.parse_btsnoop_file")
def test_cli_link_keys_flag_none_found(mock_parse, mock_extract, mock_stdout):
    """--link-keys with no matches should say so rather than print nothing."""
    mock_parse.return_value = []
    mock_extract.return_value = []

    with patch.object(sys, "argv", ["btsnoop_parser", "test.log", "--link-keys"]):
        main()

    assert "No link keys found." in mock_stdout.getvalue()
