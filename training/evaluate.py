#!/usr/bin/env python3
"""Phase 4: sanity-check the LoRA fine-tune against the base model.

Not a full eval harness — a cheap, honest surface-match check: for each
held-out scenario (built from device/scenario combinations the model never
saw during training), does the generated answer mention the correct HCI
error code and device/handle? Run both the base model and the LoRA-adapted
model over the same held-out set and compare.

Usage:
    python3 training/evaluate.py
    python3 training/evaluate.py --sample 15   # print a few full answers too
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from btsnoop_parser.llm import DEFAULT_BASE_MODEL, SYSTEM_PROMPT

DATA_PATH = ROOT / "training" / "data" / "eval_holdout.jsonl"
ADAPTER_PATH = ROOT / "training" / "checkpoints" / "hci-rootcause-lora"

_HEX_RE = re.compile(r"0x[0-9A-Fa-f]{2}\b")
_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")


def _expected_facts(answer: str) -> set[str]:
    facts = {m.upper() for m in _HEX_RE.findall(answer)}
    facts |= {m.upper() for m in _MAC_RE.findall(answer)}
    return facts


def _load_holdout() -> list[dict]:
    if not DATA_PATH.exists():
        raise SystemExit(f"No holdout data at {DATA_PATH} — run training/generate_dataset.py first.")
    with open(DATA_PATH) as f:
        return [json.loads(line) for line in f if line.strip()]


def _load_model(adapter_path: str | None):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(DEFAULT_BASE_MODEL)
    model = AutoModelForCausalLM.from_pretrained(DEFAULT_BASE_MODEL)

    if adapter_path:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, adapter_path)

    device = "mps" if torch.backends.mps.is_available() else "cpu"
    model = model.to(device).eval()
    return tokenizer, model, device


def _generate(tokenizer, model, device, user_content: str) -> str:
    import torch

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]
    inputs = tokenizer.apply_chat_template(
        messages, add_generation_prompt=True, return_dict=True, return_tensors="pt"
    ).to(device)
    with torch.no_grad():
        output = model.generate(**inputs, max_new_tokens=400, do_sample=False, pad_token_id=tokenizer.eos_token_id)
    return tokenizer.decode(output[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True).strip()


def _score(tag: str, tokenizer, model, device, examples: list[dict], sample: int) -> None:
    hits, total = 0, 0
    printed = 0
    for ex in examples:
        expected = _expected_facts(ex["output"])
        if not expected:
            continue
        generated = _generate(tokenizer, model, device, ex["input"])
        found = {fact for fact in expected if fact in generated.upper()}
        total += 1
        if found == expected:
            hits += 1
        if printed < sample:
            print(f"\n[{tag}] expected facts: {sorted(expected)} | matched: {sorted(found)}")
            print(f"  -> {generated[:200]}")
            printed += 1
    accuracy = hits / total if total else 0.0
    print(f"\n{tag}: {hits}/{total} held-out scenarios fully matched ({accuracy:.0%})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=int, default=0, help="Print this many full answers per model")
    args = parser.parse_args()

    examples = _load_holdout()
    print(f"Evaluating on {len(examples)} held-out scenarios\n")

    print("=== Base model (no LoRA) ===")
    tokenizer, model, device = _load_model(adapter_path=None)
    _score("base", tokenizer, model, device, examples, args.sample)
    del model

    if ADAPTER_PATH.exists():
        print("\n=== LoRA-adapted model ===")
        tokenizer, model, device = _load_model(adapter_path=str(ADAPTER_PATH))
        _score("lora", tokenizer, model, device, examples, args.sample)
    else:
        print(f"\nNo adapter found at {ADAPTER_PATH.relative_to(ROOT)} — run training/train_lora.py to compare.")


if __name__ == "__main__":
    main()
