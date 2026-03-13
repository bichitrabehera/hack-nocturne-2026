"""
Fine-tune a scam detector text classifier and export it for the API.

Supported dataset formats:
- JSONL with {"text": "...", "label": 0|1}
- CSV with columns: text,label

Example:
python scripts/fine_tune_model.py --dataset data/scam_train.jsonl
"""

import argparse
import csv
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import List


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fine-tune the scam detector model")
    parser.add_argument("--dataset", required=True, help="Path to a CSV or JSONL file with text,label")
    parser.add_argument(
        "--output-dir",
        default=str(Path("models") / "scam-detector"),
        help="Directory where the fine-tuned model checkpoint will be saved",
    )
    parser.add_argument("--base-model", default="distilbert-base-uncased", help="Hugging Face base model")
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=8, help="Per-device batch size")
    parser.add_argument("--learning-rate", type=float, default=2e-5, help="Learning rate")
    parser.add_argument("--max-length", type=int, default=256, help="Tokenizer max sequence length")
    parser.add_argument("--eval-ratio", type=float, default=0.2, help="Validation split ratio")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    return parser.parse_args()


@dataclass
class Example:
    text: str
    label: int


def load_examples(path: Path) -> List[Example]:
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    if path.suffix.lower() == ".jsonl":
        records = []
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                raw = line.strip()
                if not raw:
                    continue
                item = json.loads(raw)
                records.append(_validate_record(item, f"{path}:{line_number}"))
        return records

    if path.suffix.lower() == ".csv":
        records = []
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for index, row in enumerate(reader, start=2):
                records.append(_validate_record(row, f"{path}:{index}"))
        return records

    raise ValueError("Dataset must be .csv or .jsonl")


def _validate_record(record: dict, location: str) -> Example:
    text = str(record.get("text", "")).strip()
    label_raw = record.get("label")
    if not text:
        raise ValueError(f"Missing text at {location}")
    if label_raw not in (0, 1, "0", "1"):
        raise ValueError(f"Label must be 0 or 1 at {location}")
    return Example(text=text, label=int(label_raw))


def split_examples(examples: List[Example], eval_ratio: float, seed: int) -> tuple[List[Example], List[Example]]:
    if len(examples) < 5:
        raise ValueError("Need at least 5 labeled examples to fine-tune the model")

    rng = random.Random(seed)
    shuffled = examples[:]
    rng.shuffle(shuffled)

    eval_count = max(1, int(len(shuffled) * eval_ratio))
    eval_examples = shuffled[:eval_count]
    train_examples = shuffled[eval_count:]
    if not train_examples or not eval_examples:
        raise ValueError("Dataset split produced an empty train or validation set")
    return train_examples, eval_examples


def main() -> None:
    args = parse_args()

    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        DataCollatorWithPadding,
        Trainer,
        TrainingArguments,
    )
    import evaluate
    import numpy as np
    from datasets import Dataset

    dataset_path = Path(args.dataset)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    examples = load_examples(dataset_path)
    train_examples, eval_examples = split_examples(examples, args.eval_ratio, args.seed)

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model,
        num_labels=2,
        id2label={0: "legitimate", 1: "scam"},
        label2id={"legitimate": 0, "scam": 1},
    )

    def tokenize(batch):
        return tokenizer(
            batch["text"],
            truncation=True,
            max_length=args.max_length,
        )

    train_dataset = Dataset.from_list([example.__dict__ for example in train_examples]).map(tokenize, batched=True)
    eval_dataset = Dataset.from_list([example.__dict__ for example in eval_examples]).map(tokenize, batched=True)

    accuracy = evaluate.load("accuracy")
    precision = evaluate.load("precision")
    recall = evaluate.load("recall")
    f1 = evaluate.load("f1")

    def compute_metrics(eval_prediction):
        logits, labels = eval_prediction
        predictions = np.argmax(logits, axis=-1)
        return {
            "accuracy": accuracy.compute(predictions=predictions, references=labels)["accuracy"],
            "precision": precision.compute(predictions=predictions, references=labels)["precision"],
            "recall": recall.compute(predictions=predictions, references=labels)["recall"],
            "f1": f1.compute(predictions=predictions, references=labels)["f1"],
        }

    training_args = TrainingArguments(
        output_dir=str(output_dir / "checkpoints"),
        learning_rate=args.learning_rate,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        num_train_epochs=args.epochs,
        weight_decay=0.01,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        logging_steps=10,
        seed=args.seed,
        report_to=[],
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        tokenizer=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer=tokenizer),
        compute_metrics=compute_metrics,
    )

    trainer.train()
    metrics = trainer.evaluate()
    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))

    summary = {
        "saved_model_dir": str(output_dir.resolve()),
        "base_model": args.base_model,
        "train_examples": len(train_examples),
        "eval_examples": len(eval_examples),
        "metrics": metrics,
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
