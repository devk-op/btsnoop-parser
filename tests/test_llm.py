"""Tests for the local-LLM analysis module (btsnoop_parser.llm)."""
from __future__ import annotations

import datetime
import sys
import unittest
from unittest.mock import MagicMock, patch

from btsnoop_parser.analysis import CaptureStats
from btsnoop_parser.llm import ModelUnavailableError, ask, build_context

_UTC = datetime.timezone.utc
_BASE_TS = datetime.datetime(2024, 1, 1, 12, 0, 0, tzinfo=_UTC)


def _stats(**overrides) -> CaptureStats:
    s = CaptureStats()
    s.start_time = _BASE_TS
    s.end_time = _BASE_TS + datetime.timedelta(seconds=5)
    s.total_packets = 10
    s.total_bytes = 1024
    for key, value in overrides.items():
        setattr(s, key, value)
    return s


def _issue(level="WARN", title="Abnormal Disconnect", detail="detail text", ts=_BASE_TS) -> dict:
    return {"timestamp": ts, "level": level, "title": title, "detail": detail}


def _event(is_error=False, event="Connected (LE)", handle="0x001", details="Device: AA:BB:CC:11:22:33", ts=_BASE_TS) -> dict:
    return {"timestamp": ts, "event": event, "handle": handle, "details": details, "is_error": is_error}


class TestBuildContext(unittest.TestCase):
    def test_includes_summary_stats(self):
        s = _stats()
        ctx = build_context(s)
        self.assertIn("Total Packets: 10", ctx)
        self.assertIn("1.00 KB", ctx)
        self.assertIn("5.000s", ctx)

    def test_includes_issue_fields(self):
        s = _stats(issues=[_issue(detail="Failed to connect to AA:BB:CC:11:22:33: Page Timeout")])
        ctx = build_context(s)
        self.assertIn("Abnormal Disconnect", ctx)
        self.assertIn("Page Timeout", ctx)
        self.assertIn("WARN", ctx)

    def test_includes_lifecycle_event_fields(self):
        s = _stats(lifecycle_events=[_event()])
        ctx = build_context(s)
        self.assertIn("Connected (LE)", ctx)
        self.assertIn("0x001", ctx)
        self.assertIn("AA:BB:CC:11:22:33", ctx)

    def test_no_issues_says_so_explicitly(self):
        s = _stats(issues=[])
        ctx = build_context(s)
        self.assertIn("No issues detected.", ctx)

    def test_truncation_preserves_high_severity_issues(self):
        critical = [_issue(level="CRITICAL", title=f"Crit-{i}") for i in range(5)]
        warnings = [_issue(level="WARN", title=f"Warn-{i}") for i in range(60)]
        s = _stats(issues=critical + warnings)
        ctx = build_context(s, max_issues=10)
        for i in range(5):
            self.assertIn(f"Crit-{i}", ctx)
        self.assertIn("omitted", ctx)

    def test_truncation_preserves_error_lifecycle_events(self):
        errors = [_event(is_error=True, event=f"Failed-{i}") for i in range(5)]
        normals = [_event(is_error=False, event=f"Normal-{i}") for i in range(60)]
        s = _stats(lifecycle_events=errors + normals)
        ctx = build_context(s, max_events=10)
        for i in range(5):
            self.assertIn(f"Failed-{i}", ctx)
        self.assertIn("omitted", ctx)

    def test_no_ansi_escapes(self):
        s = _stats(issues=[_issue()], lifecycle_events=[_event()])
        ctx = build_context(s)
        self.assertNotIn("\033[", ctx)


class TestAsk(unittest.TestCase):
    def _mock_transformers(self):
        torch_mock = MagicMock()
        torch_mock.backends.mps.is_available.return_value = False

        tokenizer_mock = MagicMock()
        tensor_mock = MagicMock()
        tensor_mock.shape = (1, 7)
        tensor_mock.to.return_value = tensor_mock
        tokenizer_mock.apply_chat_template.return_value = tensor_mock
        tokenizer_mock.decode.return_value = "diagnosis text"

        model_mock = MagicMock()
        model_mock.to.return_value = model_mock
        model_mock.generate.return_value = [MagicMock()]

        transformers_mock = MagicMock()
        transformers_mock.AutoTokenizer.from_pretrained.return_value = tokenizer_mock
        transformers_mock.AutoModelForCausalLM.from_pretrained.return_value = model_mock

        return torch_mock, transformers_mock, tokenizer_mock, model_mock

    def test_ask_returns_decoded_text_without_adapter(self):
        torch_mock, transformers_mock, tokenizer_mock, model_mock = self._mock_transformers()
        with patch.dict(sys.modules, {"torch": torch_mock, "transformers": transformers_mock}):
            answer = ask(_stats(issues=[_issue()]), question="Why?", base_model="fake/model")

        self.assertEqual(answer, "diagnosis text")
        transformers_mock.AutoModelForCausalLM.from_pretrained.assert_called_once_with("fake/model")
        model_mock.generate.assert_called_once()

    def test_ask_raises_model_unavailable_when_transformers_missing(self):
        with patch.dict(sys.modules, {"transformers": None}):
            with self.assertRaises(ModelUnavailableError) as ctx:
                ask(_stats())
        self.assertIn("pip install", str(ctx.exception))

    def test_ask_warns_and_falls_back_when_adapter_path_missing(self):
        torch_mock, transformers_mock, tokenizer_mock, model_mock = self._mock_transformers()
        with patch.dict(sys.modules, {"torch": torch_mock, "transformers": transformers_mock}):
            with patch("sys.stderr") as mock_stderr:
                ask(_stats(), adapter_path="/nonexistent/path")

        warned = "".join(call.args[0] for call in mock_stderr.write.call_args_list if call.args)
        self.assertIn("not found", warned)

    def test_ask_loads_adapter_when_path_exists(self):
        torch_mock, transformers_mock, tokenizer_mock, model_mock = self._mock_transformers()
        peft_mock = MagicMock()
        peft_model_mock = MagicMock()
        peft_model_mock.to.return_value = peft_model_mock
        peft_mock.PeftModel.from_pretrained.return_value = peft_model_mock

        with patch.dict(sys.modules, {"torch": torch_mock, "transformers": transformers_mock, "peft": peft_mock}):
            with patch("os.path.isdir", return_value=True):
                ask(_stats(), adapter_path="/fake/adapter")

        peft_mock.PeftModel.from_pretrained.assert_called_once_with(model_mock, "/fake/adapter")


if __name__ == "__main__":
    unittest.main()
