#!/usr/bin/env python3
"""Phase 3: LoRA fine-tune the base model on the synthetic HCI dataset.

LoRA (Low-Rank Adaptation) freezes the base model's weights and trains a
small pair of low-rank matrices bolted onto a subset of layers instead —
here, the attention (q/k/v/o) and MLP (gate/up/down) projections. That's why
this fits in 16GB of unified memory even though the base model itself is
~3GB in bf16: the vast majority of parameters never move during training,
only the tiny LoRA deltas do.

Usage:
    python3 training/generate_dataset.py   # if you haven't already
    python3 training/train_lora.py
    # -> training/checkpoints/hci-rootcause-lora/
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from btsnoop_parser.llm import DEFAULT_BASE_MODEL

DATA_DIR = ROOT / "training" / "data"
OUTPUT_DIR = ROOT / "training" / "checkpoints" / "hci-rootcause-lora"


def _load_jsonl(path: Path) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def main() -> None:
    import torch
    from datasets import Dataset
    from peft import LoraConfig, get_peft_model
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
    )

    train_examples = _load_jsonl(DATA_DIR / "train.jsonl")
    val_examples = _load_jsonl(DATA_DIR / "val.jsonl")
    if not train_examples:
        raise SystemExit("No training data found — run training/generate_dataset.py first.")

    print(f"Loaded {len(train_examples)} train / {len(val_examples)} val examples")

    tokenizer = AutoTokenizer.from_pretrained(DEFAULT_BASE_MODEL)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    def _to_chat_text(example: dict) -> str:
        messages = [
            {"role": "system", "content": "You are a Bluetooth protocol expert analyzing HCI logs."},
            {"role": "user", "content": example["input"]},
            {"role": "assistant", "content": example["output"]},
        ]
        return tokenizer.apply_chat_template(messages, tokenize=False)

    def _tokenize(batch):
        texts = [_to_chat_text({"input": i, "output": o}) for i, o in zip(batch["input"], batch["output"])]
        tokenized = tokenizer(texts, truncation=True, max_length=512, padding="max_length")
        tokenized["labels"] = list(tokenized["input_ids"])
        return tokenized

    train_ds = Dataset.from_list(train_examples).map(_tokenize, batched=True, remove_columns=["input", "output"])
    val_ds = Dataset.from_list(val_examples).map(_tokenize, batched=True, remove_columns=["input", "output"]) if val_examples else None

    base_model = AutoModelForCausalLM.from_pretrained(DEFAULT_BASE_MODEL)

    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(base_model, lora_config)
    model.print_trainable_parameters()

    device = "mps" if torch.backends.mps.is_available() else "cpu"
    model = model.to(device)

    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        per_device_train_batch_size=2,
        gradient_accumulation_steps=8,
        num_train_epochs=3,
        learning_rate=2e-4,
        warmup_ratio=0.03,
        lr_scheduler_type="cosine",
        max_grad_norm=1.0,
        logging_steps=10,
        save_strategy="epoch",
        eval_strategy="epoch" if val_ds is not None else "no",
        bf16=(device != "cpu"),  # fall back to fp32 on CPU or if bf16 shows NaN loss on MPS
        optim="adamw_torch",
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
    )
    trainer.train()

    model.save_pretrained(str(OUTPUT_DIR))
    tokenizer.save_pretrained(str(OUTPUT_DIR))
    print(f"\nSaved LoRA adapter to {OUTPUT_DIR.relative_to(ROOT)}")
    print(f"Try it: btsnoop_parser capture.log --ai --adapter-path {OUTPUT_DIR.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
