# Training: a local LoRA fine-tune for HCI log analysis

This directory is a **learning path**, not a shipped part of `btsnoop_parser` (the
package's `pyproject.toml` only includes `btsnoop_parser*` in its wheel — nothing
here is installed by `pip install btsnoop-parser`). It walks through applying
Hugging Face `transformers` + `peft` (LoRA) to an existing small open-weight
model, so it can explain Bluetooth HCI capture failures in plain English.

Everything below runs fully locally — no cloud API, no data leaves your machine.
The only network access is the one-time model download from the Hugging Face Hub.

## Setup

```bash
cd btsnoop-parser
python3 -m venv .venv        # if you don't already have one
source .venv/bin/activate
pip install -e ".[train]"    # torch, transformers, peft, datasets, accelerate
```

Verify the Apple Silicon GPU backend (MPS) is available before going further:

```bash
python3 -c "import torch; print('MPS available:', torch.backends.mps.is_available())"
```

If that prints `False`, everything below still works on CPU — just slower.

## Phase 1 — Baseline inference (no training yet)

```bash
python3 training/baseline_check.py
```

Loads `Qwen/Qwen2.5-1.5B-Instruct` (~3GB download, first run only) with plain
`transformers`, and runs one hand-written HCI failure summary through
`tokenizer.apply_chat_template()` + `model.generate()`. This is the "hello
world" — it proves the environment works and shows what the un-tuned base
model's answers look like, before any training complexity is introduced.

This is also exactly the code path `btsnoop_parser --ai` uses when you run it
without `--adapter-path` — so this script doubles as a way to preview what the
CLI feature does.

## Phase 2 — Synthetic dataset generation

There's no existing "Bluetooth HCI root-cause Q&A" dataset anywhere, so we
generate one programmatically. `btsnoop_parser.constants` already has the
canonical HCI error-code (`HCI_ERROR_CODES`) and opcode-name (`HCI_OPCODE_NAMES`)
tables, and `btsnoop_parser.analysis.CaptureStats` already knows which
event/issue shapes a real capture produces (`Connect Failed (LE)`, `Abnormal
Disconnect`, `Command Failure`, etc.). `generate_dataset.py` samples
combinations of those, synthesizes a plausible short capture around each one,
renders it through the **same** `btsnoop_parser.llm.build_context()` used at
inference time (so training and inference text distributions match), and pairs
it with a deterministic, template-based answer (`templates/answer_templates.py`)
— zero hallucination risk in the training data itself.

```bash
python3 training/generate_dataset.py
# writes training/data/train.jsonl, training/data/val.jsonl,
# training/data/eval_holdout.jsonl
```

## Phase 3 — LoRA fine-tuning

```bash
python3 training/train_lora.py
# writes the adapter to training/checkpoints/hci-rootcause-lora/
```

Uses `peft.LoraConfig` (rank 16, targeting the attention + MLP projection
layers) on top of the frozen base model — only a few million parameters are
actually trained, which is why this fits comfortably in 16GB of unified
memory. See the file for the exact hyperparameters and why each one was
chosen for this hardware/task size.

## Phase 4 — Evaluate

```bash
python3 training/evaluate.py
```

Runs both the base model and the LoRA-adapted model over the held-out
`eval_holdout.jsonl` scenarios (built from template combinations that were
never in the training set) and reports a cheap surface-match "did it name the
right error code and device" accuracy for each, so you can see whether the
fine-tune actually helped.

## Phase 5 — Use it from the CLI

```bash
btsnoop_parser capture.log --ai --adapter-path training/checkpoints/hci-rootcause-lora
```

Without `--adapter-path`, `--ai` still works — it just prompts the bare base
model (Phase 1's behavior) instead of the specialized one.

## Known limitations (see llm.py's SYSTEM_PROMPT and CaptureStats)

`CaptureStats` only decodes **HCI-transport-layer** events — connection
setup/teardown, command failures, hardware errors. It does not parse upper-layer
protocol payloads (A2DP audio, RFCOMM data, etc.), so questions about those will
get an "insufficient information" answer rather than a real diagnosis — that's
a capability boundary of the underlying parser, not something fine-tuning can
fix without also extending `analysis.py` to decode those protocols.
