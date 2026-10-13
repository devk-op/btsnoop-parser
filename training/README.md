# Training the `--ai` model

The scripts here produce the LoRA adapter that `btsnoop_parser --ai` uses by default
([`kdonut/btsnoop-hci-qwen2.5-0.5b-lora`](https://huggingface.co/kdonut/btsnoop-hci-qwen2.5-0.5b-lora),
on top of `Qwen/Qwen2.5-0.5B-Instruct`). They are not part of the installed package.

Everything runs locally. The only network access is the one-time download of the base
model from the Hugging Face Hub.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[train]"    # torch, transformers, peft, datasets, accelerate
```

Developed on an Apple M4 with 16 GB of memory (MPS backend). It also runs on CPU, slower.

## Steps

```bash
python3 training/baseline_check.py      # optional: see what the untrained model answers
python3 training/generate_dataset.py    # writes training/data/{train,val,eval_holdout}.jsonl
python3 training/train_lora.py          # about 90 minutes; writes training/checkpoints/<model>-lora/
python3 training/evaluate.py --model Qwen/Qwen2.5-0.5B-Instruct \
        --adapter training/checkpoints/Qwen2.5-0.5B-Instruct-lora

btsnoop_parser capture.log --ai --adapter-path training/checkpoints/Qwen2.5-0.5B-Instruct-lora
```

## How the data is made

There is no public dataset of HCI logs with explanations, so `generate_dataset.py`
synthesizes one:

- Each session is built as raw HCI packets and run through the real
  `btsnoop_parser.analysis.CaptureStats` and `btsnoop_parser.llm.build_context`, so a
  training input has exactly the format the model sees in use.
- Answers come from `templates/answer_templates.py` and only restate facts present in
  that summary, including its status code notes (`btsnoop_parser/code_notes.py`).
- Scenarios: normal sessions, LE and Classic connection failures, unexpected disconnects,
  failed commands, hardware errors and failed LE Audio streams. Sessions range from one
  short link to a dual-mode device cycling several audio streams.
- Routine Android noise (rejected vendor commands, Delete Stored Link Key, Sniff
  Subrating) is mixed into every scenario so the model learns it is not a root cause.

The held-out set uses device addresses, commands and status codes that never appear in
training, so a correct answer shows the model read the summary.

## How training works

`train_lora.py` freezes the base model and trains LoRA matrices (rank 16) on the attention
and MLP projections: 8.8M parameters, 1.75% of the model. The loss covers the answer
tokens only. To fit in 16 GB it uses one example per step with gradients accumulated over
16 steps, gradient checkpointing, and inputs padded to a few fixed lengths.

## Results

`evaluate.py` counts an answer as correct when it contains every key fact for the scenario
(device address, status-code name, command name or hardware code), or clearly says nothing
failed for a normal session.

| Model | Correct on 122 held-out sessions |
|---|---|
| Qwen2.5-0.5B-Instruct + adapter | 118 (97%) |
| Qwen2.5-1.5B-Instruct, no adapter | 27 (22%) |
| Qwen2.5-0.5B-Instruct, no adapter | 1 (1%) |

## Limitations

- The test sessions are synthetic; accuracy on real captures will be lower.
- The check is a surface match on facts, not a judgement of answer quality. Read the
  saved answers in `training/checkpoints/eval/` too.
- The model only knows what the summary contains: connections, command failures, hardware
  errors and LE Audio streams. It does not see profile traffic such as A2DP, HFP or GATT.
