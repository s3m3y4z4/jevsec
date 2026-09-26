"""Verifica prioritization-v2 sul bench dello spike (SC-001, FR-009).

Per ognuno dei 25 casi di data/bench/prioritization.jsonl: mappa la frase-obiettivo
al nome rubrica via [objective_names], esegue l'osservazione attraverso la pipeline,
confronta l'impatto ricomposto con l'etichetta. Report in results/ con accanto le
metriche dei modelli compositi dello spike e i criteri SC-001 (> 0,32 exact, > 0,60
within-1). Run non valida se un caso va in errore.

Usage:
  PYTHONPATH=src python3 harness/run_prioritization_eval.py [--base-url URL] \
      [--out results/prioritization_v2_decider2b.json]
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from jevsec.client import ask  # noqa: E402
from jevsec.prioritize import prioritize_observation  # noqa: E402
from jevsec.rubric import load_rubric  # noqa: E402

SPIKE_REFERENCE = {
    "reflex_4b_composite": {"accuracy_exact": 0.320, "accuracy_within1": 0.600, "mae": 0.960},
    "decider_2b_composite": {"accuracy_exact": 0.240, "accuracy_within1": 0.520, "mae": 1.000},
}
SC_EXACT = 0.32
SC_WITHIN1 = 0.60

DEFAULT_BENCH = REPO_ROOT / "data" / "bench" / "prioritization.jsonl"
DEFAULT_CONFIG = REPO_ROOT / "config" / "prioritization.toml"
DEFAULT_OUT = REPO_ROOT / "results" / "prioritization_v2_decider2b.json"


def load_cases(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="es. http://127.0.0.1:8000")
    parser.add_argument("--bench", type=Path, default=DEFAULT_BENCH)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    config = load_rubric(args.config)
    config = dataclasses.replace(config, base_url=args.base_url)
    sentence_to_name = {sentence: name for name, sentence in config.objective_names.items()}
    cases = load_cases(args.bench)

    results = []
    errors = 0
    unmatched = 0
    for case in cases:
        objective_sentence = case["state"]["objective"]
        objective_name = sentence_to_name.get(objective_sentence)
        if objective_name is None:
            unmatched += 1
            continue
        observation = {"id": case["id"], "text": case["state"]["observation"]}
        record = prioritize_observation(observation, case["id"], config, config.objectives[objective_name], ask)
        if record["error"] or record["impact"] is None:
            errors += 1
            results.append({"id": case["id"], "error": record["error"], "label": case["labels"]["impact"]})
            continue
        results.append({
            "id": case["id"],
            "objective": objective_name,
            "predicted": record["impact"],
            "label": case["labels"]["impact"],
            "winning_rule": record["winning_rule"],
        })

    measured = [r for r in results if "predicted" in r]
    exact = sum(1 for r in measured if r["predicted"] == r["label"]) / len(measured) if measured else 0.0
    within1 = sum(1 for r in measured if abs(r["predicted"] - r["label"]) <= 1) / len(measured) if measured else 0.0
    mae = sum(abs(r["predicted"] - r["label"]) for r in measured) / len(measured) if measured else 0.0
    report = {
        "base_url": args.base_url,
        "n_cases": len(cases),
        "n_measured": len(measured),
        "n_errors": errors,
        "n_unmatched_objectives": unmatched,
        "valid": errors == 0 and unmatched == 0,
        "metrics": {
            "accuracy_exact": round(exact, 4),
            "accuracy_within1": round(within1, 4),
            "mae": round(mae, 4),
        },
        "sc001": {
            "required": {"exact_gt": SC_EXACT, "within1_gt": SC_WITHIN1},
            "exact_pass": exact > SC_EXACT,
            "within1_pass": within1 > SC_WITHIN1,
        },
        "spike_reference": SPIKE_REFERENCE,
        "results": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    verdict = "SUPERATA" if (report["sc001"]["exact_pass"] and report["sc001"]["within1_pass"]) else "NON SUPERATA"
    print(
        f"misurati {len(measured)}/{len(cases)} | exact {exact:.3f} (>{SC_EXACT}) | within1 {within1:.3f} (>{SC_WITHIN1}) "
        f"| MAE {mae:.3f} | SC-001 {verdict} | salvato in {args.out}"
    )
    if errors or unmatched:
        print(f"NON VALIDA: {errors} errori, {unmatched} obiettivi non mappati")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
