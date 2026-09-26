"""Runner di valutazione: esegue i casi di un task contro un backend System One.

Usage:
  python3 run_eval.py --task harness/tasks/scanner_triage.json \
      --data data/smoke/scanner_triage.jsonl --base-url http://127.0.0.1:8008 \
      --backend reflex --out results [--verbose]
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from jevsec.client import SystemOneError, answer_probability, answer_value, ask

ECE_BINS = 10


def load_cases(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def expected_calibration_error(pairs: list[tuple[float, bool]]) -> float:
    """ECE su 10 bin: |accuratezza bin - confidenza media bin| pesata."""
    if not pairs:
        return float("nan")
    buckets: list[list[tuple[float, bool]]] = [[] for _ in range(ECE_BINS)]
    for probability, is_correct in pairs:
        index = min(int(probability * ECE_BINS), ECE_BINS - 1)
        buckets[index].append((probability, is_correct))
    total = len(pairs)
    error = 0.0
    for bucket in buckets:
        if not bucket:
            continue
        mean_confidence = sum(p for p, _ in bucket) / len(bucket)
        accuracy = sum(1 for _, correct in bucket if correct) / len(bucket)
        error += (len(bucket) / total) * abs(accuracy - mean_confidence)
    return error


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(int(math.ceil(fraction * len(ordered))) - 1, len(ordered) - 1)
    return ordered[max(index, 0)]


def choice_metrics(records: list[dict[str, Any]]) -> dict[str, float]:
    pairs = [(r["probability"], r["predicted"] == r["label"]) for r in records]
    correct = sum(1 for _, is_correct in pairs if is_correct)
    return {
        "accuracy": correct / len(records),
        "ece": expected_calibration_error(pairs),
    }


def score_metrics(records: list[dict[str, Any]]) -> dict[str, float]:
    exact = sum(1 for r in records if round(r["predicted"]) == r["label"])
    within1 = sum(1 for r in records if abs(r["predicted"] - r["label"]) <= 1.0)
    mae = sum(abs(r["predicted"] - r["label"]) for r in records) / len(records)
    pairs = [(r["probability"], round(r["predicted"]) == r["label"]) for r in records]
    return {
        "accuracy_exact": exact / len(records),
        "accuracy_within1": within1 / len(records),
        "mae": mae,
        "ece": expected_calibration_error(pairs),
    }


def noul_metrics(records: list[dict[str, Any]]) -> dict[str, float]:
    binary = [(r["predicted"], r["label"] == 1) for r in records]
    accuracy = sum(1 for probability, label in binary if (probability >= 0.5) == label)
    brier = sum((probability - float(label)) ** 2 for probability, label in binary) / len(records)
    pairs = binary
    return {
        "accuracy_at_0.5": accuracy / len(records),
        "brier": brier,
        "ece": expected_calibration_error(pairs),
    }


METRIC_FUNCTIONS = {"choice": choice_metrics, "score": score_metrics, "noul": noul_metrics}
PRIMARY_METRIC = {
    "choice": "accuracy",
    "score": "accuracy_within1",
    "noul": "accuracy_at_0.5",
}


def run(task: dict[str, Any], cases: list[dict[str, Any]], base_url: str) -> dict[str, Any]:
    questions = task["questions"]
    collected: dict[str, dict[str, list[dict[str, Any]]]] = {}
    latencies: list[float] = []
    errors: list[dict[str, str]] = []
    for case in cases:
        try:
            response, latency = ask(base_url, case["state"], questions)
        except SystemOneError as error:
            errors.append({"id": case["id"], "error": str(error)})
            continue
        latencies.append(latency)
        for question_name, answer in response["answers"].items():
            record = {
                "predicted": answer_value(answer),
                "probability": answer_probability(answer),
                "label": case["labels"][question_name],
            }
            collected.setdefault(question_name, {"records": [], "errors": []})["records"].append(record)
    return {
        "task": task["name"],
        "n_cases": len(cases),
        "n_errors": len(errors),
        "errors": errors,
        "latency_p50_s": percentile(latencies, 0.50) if latencies else float("nan"),
        "latency_p95_s": percentile(latencies, 0.95) if latencies else float("nan"),
        "questions": {
            name: {
                "primitive": details["primitive"],
                "metrics": METRIC_FUNCTIONS[details["primitive"]](details["records"]),
            }
            for name, details in (
                (name, {"primitive": task["labels"][name], "records": data["records"]})
                for name, data in collected.items()
            )
        },
    }


def print_report(result: dict[str, Any]) -> None:
    print(f"\n## {result['task']} — {result['n_cases']} casi, {result['n_errors']} errori")
    print(f"latency p50 {result['latency_p50_s']:.3f}s · p95 {result['latency_p95_s']:.3f}s")
    for name, question in result["questions"].items():
        metrics = ", ".join(f"{key}={value:.3f}" for key, value in question["metrics"].items())
        print(f"- {name} ({question['primitive']}): {metrics}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", required=True, type=Path, help="task JSON in harness/tasks/")
    parser.add_argument("--data", required=True, type=Path, help="casi JSONL etichettati")
    parser.add_argument("--base-url", required=True, help="es. http://127.0.0.1:8008")
    parser.add_argument("--backend", required=True, help="nome backend per l'output (reflex, decider)")
    parser.add_argument("--out", required=True, type=Path, help="directory risultati")
    parser.add_argument("--verbose", action="store_true", help="stampa ogni caso: predetto vs etichetta")
    args = parser.parse_args()

    task = json.loads(args.task.read_text(encoding="utf-8"))
    cases = load_cases(args.data)
    result = run(task, cases, args.base_url)

    if args.verbose:
        print(f"\n# Dettaglio {task['name']}")
        for case in cases:
            try:
                response, _ = ask(args.base_url, case["state"], task["questions"])
            except SystemOneError as error:
                print(f"{case['id']}: ERRORE {error}")
                continue
            for question_name, answer in response["answers"].items():
                print(f"{case['id']} {question_name}: {answer_value(answer)!r} (p={answer_probability(answer):.2f}) label={case['labels'][question_name]!r}")

    print_report(result)
    args.out.mkdir(parents=True, exist_ok=True)
    suffix = args.data.stem
    output_path = args.out / f"{args.backend}_{task['name']}_{suffix}.json"
    output_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"salvato in {output_path}")
    return 1 if result["n_errors"] == result["n_cases"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
