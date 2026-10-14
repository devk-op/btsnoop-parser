#!/usr/bin/env python3
"""Score a model (with or without a LoRA adapter) on the holdout set.

The holdout set uses devices and status codes that never appear in training.
A failure answer counts as correct when it contains every key fact for that
scenario (device address, status-code name, command name, or hardware code).
A normal-session answer counts as correct when it clearly says nothing failed.
This is a cheap surface check, not a full judgement of answer quality — read
the saved answers too.

Usage:
    python3 training/evaluate.py --model Qwen/Qwen2.5-0.5B-Instruct
    python3 training/evaluate.py --model Qwen/Qwen2.5-0.5B-Instruct \
        --adapter training/checkpoints/Qwen2.5-0.5B-Instruct-lora
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from btsnoop_parser.llm import SYSTEM_PROMPT
from training.templates.legacy_prompt import LEGACY_SYSTEM_PROMPT

DATA_PATH = ROOT / "training" / "data" / "eval_holdout.jsonl"
RESULTS_DIR = ROOT / "training" / "checkpoints" / "eval"

NORMAL_PHRASES = ("looks normal", "nothing failed", "no issues", "no detected issues", "no problems",
                  "did not fail", "no failure", "no significant")


def _correct(answer: str, facts: list[str]) -> bool:
    text = answer.lower()
    if facts == ["NORMAL"]:
        return any(p in text for p in NORMAL_PHRASES)
    return all(f.lower() in text for f in facts)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", required=True, help="Base model id or local folder")
    parser.add_argument("--adapter", help="LoRA adapter folder")
    parser.add_argument("--limit", type=int, help="Only score the first N holdout examples")
    parser.add_argument("--max-new-tokens", type=int, default=400)
    args = parser.parse_args()

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    with open(DATA_PATH) as f:
        examples = [json.loads(line) for line in f if line.strip()][: args.limit]

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForCausalLM.from_pretrained(args.model)
    if args.adapter:
        from peft import PeftModel
        # Merging folds the LoRA weights into the base layers, so generation runs at base-model speed.
        model = PeftModel.from_pretrained(model, args.adapter).merge_and_unload()
    device = "mps" if torch.backends.mps.is_available() else "cpu"
    model = model.to(device).eval()

    label = Path(args.model).name + ("+lora" if args.adapter else "")
    print(f"Scoring {label} on {len(examples)} holdout examples ({device})")
    by_kind: dict[str, list[bool]] = collections.defaultdict(list)
    rows = []
    started = time.time()
    for i, ex in enumerate(examples, 1):
        system = LEGACY_SYSTEM_PROMPT if ex.get("system") == "legacy" else SYSTEM_PROMPT
        messages = [{"role": "system", "content": system}, {"role": "user", "content": ex["input"]}]
        inputs = tokenizer.apply_chat_template(
            messages, add_generation_prompt=True, return_dict=True, return_tensors="pt"
        ).to(device)
        with torch.no_grad():
            out = model.generate(**inputs, max_new_tokens=args.max_new_tokens, do_sample=False,
                                 pad_token_id=tokenizer.eos_token_id)
        answer = tokenizer.decode(out[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True).strip()
        ok = _correct(answer, ex["facts"])
        by_kind[ex["kind"] + (" (older input)" if ex.get("system") == "legacy" else "")].append(ok)
        rows.append({"kind": ex["kind"], "facts": ex["facts"], "correct": ok, "answer": answer, "expected": ex["output"]})
        if i % 10 == 0:
            print(f"  {i}/{len(examples)} done ({time.time() - started:.0f}s)")

    print(f"\n{label}")
    total = [ok for oks in by_kind.values() for ok in oks]
    for kind, oks in sorted(by_kind.items()):
        print(f"  {kind:22} {sum(oks):3d}/{len(oks):<3d} {sum(oks) / len(oks):6.0%}")
    print(f"  {'OVERALL':22} {sum(total):3d}/{len(total):<3d} {sum(total) / len(total):6.0%}")
    print(f"  ({(time.time() - started) / len(examples):.1f}s per answer)")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / f"{label}.jsonl"
    with open(path, "w") as f:
        f.writelines(json.dumps(r) + "\n" for r in rows)
    print(f"Answers saved to {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
