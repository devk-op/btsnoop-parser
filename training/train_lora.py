#!/usr/bin/env python3
"""Phase 3: LoRA fine-tune a small model on the synthetic HCI dataset.

LoRA freezes the base model and trains small low-rank matrices added to the
attention and MLP projections, so only a few million parameters change.

Each example is formatted with the same system prompt `btsnoop_parser --ai`
uses at inference time, and the loss is computed only on the answer tokens —
the model learns to answer, not to reproduce the prompt.

Usage:
    python3 training/generate_dataset.py
    python3 training/train_lora.py --model Qwen/Qwen2.5-0.5B-Instruct
    # -> training/checkpoints/Qwen2.5-0.5B-Instruct-lora/
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from btsnoop_parser.llm import SYSTEM_PROMPT

DATA_DIR = ROOT / "training" / "data"


def _load_jsonl(path: Path) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", default="Qwen/Qwen2.5-0.5B-Instruct", help="Base model id or local folder")
    parser.add_argument("--output", help="Adapter output folder (default: training/checkpoints/<model>-lora)")
    parser.add_argument("--epochs", type=float, default=2)
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--max-len", type=int, default=1536)
    parser.add_argument("--bf16", action="store_true", help="Train in bfloat16 (faster; fall back to fp32 if loss is NaN)")
    args = parser.parse_args()

    import torch
    from datasets import Dataset
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForCausalLM, AutoTokenizer, Trainer, TrainingArguments

    output = Path(args.output) if args.output else ROOT / "training" / "checkpoints" / f"{Path(args.model).name}-lora"
    train_examples = _load_jsonl(DATA_DIR / "train.jsonl")
    val_examples = _load_jsonl(DATA_DIR / "val.jsonl")
    print(f"Loaded {len(train_examples)} train / {len(val_examples)} val examples")

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    def encode(example: dict) -> dict:
        prompt = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": example["input"]},
        ]
        prompt_text = tokenizer.apply_chat_template(prompt, tokenize=False, add_generation_prompt=True)
        full_text = tokenizer.apply_chat_template(
            prompt + [{"role": "assistant", "content": example["output"]}], tokenize=False
        )
        assert full_text.startswith(prompt_text), "chat template does not extend the prompt"
        prompt_ids = tokenizer(prompt_text, add_special_tokens=False)["input_ids"]
        ids = tokenizer(full_text, add_special_tokens=False)["input_ids"][: args.max_len]
        labels = [-100] * len(prompt_ids) + ids[len(prompt_ids):]
        return {"input_ids": ids, "attention_mask": [1] * len(ids), "labels": labels[: len(ids)]}

    def collate(batch: list[dict]) -> dict:
        # Round up to a multiple of 128 so only a handful of tensor shapes ever occur,
        # which lets the MPS allocator reuse buffers instead of growing.
        width = math.ceil(max(len(b["input_ids"]) for b in batch) / 128) * 128
        pad = tokenizer.pad_token_id

        def padded(key, value):
            return torch.tensor([b[key] + [value] * (width - len(b[key])) for b in batch])

        return {"input_ids": padded("input_ids", pad), "attention_mask": padded("attention_mask", 0),
                "labels": padded("labels", -100)}

    columns = ["input", "output", "facts", "kind"]
    train_ds = Dataset.from_list(train_examples).map(encode, remove_columns=columns)
    val_ds = Dataset.from_list(val_examples).map(encode, remove_columns=columns)
    lengths = [len(x) for x in train_ds["input_ids"]]
    print(f"Tokens per example: min {min(lengths)}, max {max(lengths)}, mean {sum(lengths) / len(lengths):.0f}")
    truncated = sum(n >= args.max_len for n in lengths)
    if truncated:
        print(f"Warning: {truncated} examples hit --max-len {args.max_len}; their answers are cut off")

    # One example per step keeps the (tokens x 150k-vocab) logits small enough for 16GB of
    # unified memory; accumulating 16 steps gives the same effective batch size.
    batch, accumulation = 1, 16
    total_steps = math.ceil(len(train_ds) / (batch * accumulation) * args.epochs)
    warmup_steps = max(1, round(total_steps * 0.05))

    dtype = torch.bfloat16 if args.bf16 else torch.float32
    model = AutoModelForCausalLM.from_pretrained(args.model, dtype=dtype)
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()
    model = get_peft_model(model, LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
    ))
    model.print_trainable_parameters()

    from transformers import TrainerCallback

    class FreeMpsCache(TrainerCallback):
        # Every example has a different length, so the MPS allocator keeps caching buffers of new
        # sizes until it runs out of memory; releasing the cache each step keeps usage flat.
        def on_step_end(self, *_, **__):
            if torch.backends.mps.is_available():
                torch.mps.empty_cache()

        on_substep_end = on_step_end

    trainer = Trainer(
        model=model,
        callbacks=[FreeMpsCache()],
        args=TrainingArguments(
            output_dir=str(output / "trainer"),
            per_device_train_batch_size=batch,
            per_device_eval_batch_size=batch,
            gradient_accumulation_steps=accumulation,
            num_train_epochs=args.epochs,
            learning_rate=args.lr,
            warmup_steps=warmup_steps,
            lr_scheduler_type="cosine",
            logging_steps=10,
            eval_strategy="epoch",
            save_strategy="no",
            bf16=args.bf16,
            remove_unused_columns=False,
            report_to="none",
        ),
        train_dataset=train_ds,
        eval_dataset=val_ds,
        data_collator=collate,
    )
    started = time.time()
    trainer.train()
    print(f"Training took {(time.time() - started) / 60:.1f} min")

    model.save_pretrained(str(output))
    tokenizer.save_pretrained(str(output))
    shown = output.relative_to(ROOT) if output.is_relative_to(ROOT) else output
    print(f"\nSaved LoRA adapter to {shown}")
    print(f"Use it: btsnoop_parser capture.log --ai --base-model {args.model} --adapter-path {shown}")


if __name__ == "__main__":
    main()
