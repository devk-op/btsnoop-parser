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
python3 training/train_lora.py          # about 3 hours; writes training/checkpoints/<model>-lora/
python3 training/evaluate.py --model Qwen/Qwen2.5-0.5B-Instruct \
        --adapter training/checkpoints/Qwen2.5-0.5B-Instruct-lora

btsnoop_parser capture.log --ai --adapter-path training/checkpoints/Qwen2.5-0.5B-Instruct-lora
```

## How the data is made

There is no public dataset of HCI logs with explanations, so `generate_dataset.py`
synthesizes one:

- Each session is built as raw HCI packets and run through the real
  `btsnoop_parser.report.ReportBuilder` and `btsnoop_parser.llm.build_context`, so a
  training input has exactly the format the model sees in use.
- Connection-level sessions (`generate_dataset.py`): normal sessions, LE and Classic
  connection failures, unexpected disconnects, failed commands, hardware errors and failed
  LE Audio links.
- Profile-level sessions (`profile_scenarios.py`) write L2CAP channels, AVDTP, AVRCP, HFP,
  OBEX, ATT, LE Audio stream control and Android Auto start-up: normal car, headset and LE
  Audio sessions, and problems such as volume override, music-app errors, no cellular
  service, audio stalls, rejected codecs, refused LE Audio set-up, Android Auto Wi-Fi
  failure, lost pairing and refused phonebook access. Some sessions carry two to four
  problems at once, or a second, unrelated device.
- Answers come from `templates/` and are written from each session's decoded report, so
  they only restate what the model's input shows; a session is rejected if an answer
  would mention a problem the input doesn't show.
- A fifth of the connection-level examples keep the older input and system prompt
  (`templates/legacy_prompt.py`), so the model still serves btsnoop-parser 0.6 and 0.7.
- Routine Android noise (rejected vendor commands, Delete Stored Link Key, Sniff
  Subrating) is mixed into every scenario so the model learns it is not a root cause.

The held-out set uses device addresses, commands, status codes and failure reasons that
never appear in training, so a correct answer shows the model read the summary.

## How training works

`train_lora.py` freezes the base model and trains LoRA matrices (rank 16) on the attention
and MLP projections: 8.8M parameters, 1.75% of the model. The loss covers the answer
tokens only. To fit in 16 GB it uses one example per step with gradients accumulated over
16 steps, gradient checkpointing, and inputs padded to a few fixed lengths.

## Results

`evaluate.py` counts an answer as correct only when it contains every key fact for the
scenario (device, error or reason, every problem in multi-problem sessions, the main
device's own end time when two devices are present), or clearly says nothing failed for a
normal session.

| Model | Correct on 254 held-out sessions |
|---|---|
| Qwen2.5-0.5B-Instruct + adapter | 244 (96%) |
| Qwen2.5-0.5B-Instruct, no adapter | 15 (6%) |

Every single-problem and normal kind scores 100%. Sessions with two to four problems score
30/40: the misses list every problem but the last, least serious one.

## Limitations

- The test sessions are synthetic; accuracy on real captures will be lower.
- The check is a surface match on facts, not a judgement of answer quality. Read the
  saved answers in `training/checkpoints/eval/` too.
- The model only knows what the summary contains. With three or four problems it can leave
  out the last, least serious one.
