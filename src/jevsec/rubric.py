"""Carica, valida e applica le rubriche di prioritizzazione (config/prioritization.toml).

La rubrica è la conoscenza operativa: domande atomiche per obiettivo e regole che
il codice ricombina in impatto 0-4. Semantica (data-model): una regola è attiva se
ogni condizione dichiarata è ≥ soglia; vince il punteggio più alto, a parità la
prima dichiarata; nessuna attiva → default_rule.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jevsec.config import channel_violation

MIN_IMPACT = 0
MAX_IMPACT = 4


class RubricError(RuntimeError):
    """Rubrica assente, malformata o obiettivo sconosciuto: fatale, exit 2."""


@dataclass(frozen=True)
class Rule:
    """Una regola: nome, punteggio 0-4, condizioni domanda → probabilità minima."""

    name: str
    score: int
    conditions: dict[str, float]


@dataclass(frozen=True)
class ObjectiveRubric:
    """Domande atomiche e regole di un obiettivo, già validate."""

    name: str
    questions: dict[str, dict[str, Any]]
    rules: tuple[Rule, ...]
    default_rule: Rule


@dataclass(frozen=True)
class PrioritizationConfig:
    """Config validata: backend, soglie, mappa frasi-obiettivo, rubriche."""

    base_url: str
    timeout_s: float
    max_state_chars: int
    default_condition: float
    objective_names: dict[str, str]
    objectives: dict[str, ObjectiveRubric]
    api_token: str | None = None
    model: str = "jev-latest"


def _validate_question(objective: str, name: str, question: Any) -> dict[str, Any]:
    if not isinstance(question, dict):
        raise RubricError(f"[objectives.{objective}.questions.{name}] expected a table")
    if set(question) - {"type", "instructions"}:
        raise RubricError(f"[objectives.{objective}.questions.{name}] no fields allowed beyond type/instructions")
    if question.get("type") != "noul":
        raise RubricError(f"[objectives.{objective}.questions.{name}] only noul questions are allowed")
    if not isinstance(question.get("instructions"), str) or not question["instructions"].strip():
        raise RubricError(f"[objectives.{objective}.questions.{name}] instructions is required and must not be empty")
    return dict(question)


def _validate_rule(objective: str, rule: Any, question_names: set[str]) -> Rule:
    if not isinstance(rule, dict):
        raise RubricError(f"[objectives.{objective}] rule must be a table")
    name = rule.get("name")
    if not isinstance(name, str) or not name.strip():
        raise RubricError(f"[objectives.{objective}] rule without name")
    score = rule.get("score")
    if not isinstance(score, int) or not MIN_IMPACT <= score <= MAX_IMPACT:
        raise RubricError(f"[objectives.{objective}] rule {name!r}: score {score!r} out of range 0-4")
    conditions_raw = rule.get("conditions", {})
    if not isinstance(conditions_raw, dict) or not conditions_raw:
        raise RubricError(f"[objectives.{objective}] rule {name!r}: conditions required and non-empty")
    conditions: dict[str, float] = {}
    for question_name, threshold in conditions_raw.items():
        if question_name not in question_names:
            raise RubricError(
                f"[objectives.{objective}] rule {name!r}: condition on unknown question {question_name!r}"
            )
        if not isinstance(threshold, (int, float)) or not 0.0 <= float(threshold) <= 1.0:
            raise RubricError(f"[objectives.{objective}] rule {name!r}: threshold {threshold!r} out of range [0,1]")
        conditions[question_name] = float(threshold)
    return Rule(name=name, score=score, conditions=conditions)


def _validate_objective(name: str, raw: Any, default_condition: float) -> ObjectiveRubric:
    if not isinstance(raw, dict):
        raise RubricError(f"[objectives.{name}] expected a table")
    questions_raw = raw.get("questions")
    if not isinstance(questions_raw, dict) or not questions_raw:
        raise RubricError(f"[objectives.{name}] questions required and non-empty")
    questions = {qname: _validate_question(name, qname, question) for qname, question in questions_raw.items()}
    rules_raw = raw.get("rules")
    if not isinstance(rules_raw, list) or not rules_raw:
        raise RubricError(f"[objectives.{name}] rules required and non-empty")
    rules = tuple(
        _validate_rule(name, rule, set(questions)) for rule in rules_raw
    )
    default_raw = raw.get("default_rule")
    if not isinstance(default_raw, dict) or "name" not in default_raw:
        raise RubricError(f"[objectives.{name}] default_rule required (name and score)")
    default_score = default_raw.get("score")
    if not isinstance(default_score, int) or not MIN_IMPACT <= default_score <= MAX_IMPACT:
        raise RubricError(f"[objectives.{name}] default_rule score out of range 0-4")
    default_rule = Rule(name=str(default_raw["name"]), score=default_score, conditions={})
    return ObjectiveRubric(name=name, questions=questions, rules=rules, default_rule=default_rule)


def load_rubric(path: Path) -> PrioritizationConfig:
    """Legge e valida il file rubriche; RubricError alla prima violazione."""
    try:
        with Path(path).open("rb") as handle:
            raw = tomllib.load(handle)
    except FileNotFoundError as error:
        raise RubricError(f"config not found: {path}") from error
    except tomllib.TOMLDecodeError as error:
        raise RubricError(f"invalid TOML config: {path}: {error}") from error

    backend = raw.get("backend")
    if not isinstance(backend, dict) or not str(backend.get("base_url", "")).startswith(("http://", "https://")):
        raise RubricError("[backend] base_url http(s) required")
    timeout_s = float(backend.get("timeout_s", 30.0))
    api_token = backend.get("api_token")
    if api_token is not None and not isinstance(api_token, str):
        raise RubricError("[backend] api_token expected as a string")
    model = backend.get("model", "jev-latest")
    if not isinstance(model, str) or not model.strip():
        raise RubricError(f"[backend] model={model!r}: expected a non-empty string")
    violation = channel_violation(str(backend["base_url"]), api_token)
    if violation is not None:
        raise RubricError(violation)

    thresholds = raw.get("thresholds", {})
    max_state_chars = thresholds.get("max_state_chars", 2000)
    if not isinstance(max_state_chars, int) or max_state_chars <= 0:
        raise RubricError("[thresholds] max_state_chars must be a positive integer")
    default_condition = thresholds.get("default_condition", 0.5)
    if not isinstance(default_condition, (int, float)) or not 0.0 <= float(default_condition) <= 1.0:
        raise RubricError("[thresholds] default_condition out of range [0,1]")

    objective_names = raw.get("objective_names", {})
    if not isinstance(objective_names, dict):
        raise RubricError("[objective_names] expected a table name → sentence")

    objectives_raw = raw.get("objectives")
    if not isinstance(objectives_raw, dict) or not objectives_raw:
        raise RubricError("[objectives] at least one objective with a rubric is required")
    objectives = {
        name: _validate_objective(name, raw_objective, float(default_condition))
        for name, raw_objective in objectives_raw.items()
    }
    return PrioritizationConfig(
        base_url=str(backend["base_url"]),
        timeout_s=timeout_s,
        max_state_chars=max_state_chars,
        default_condition=float(default_condition),
        objective_names=dict(objective_names),
        objectives=objectives,
        api_token=api_token,
        model=model,
    )


def apply_rules(judgments: dict[str, float], rubric: ObjectiveRubric) -> tuple[list[Rule], Rule]:
    """Ritorna (regole attive ordinate per punteggio descrescente, regola vincitrice).

    Una regola è attiva se ogni condizione ha probabilità ≥ soglia; a parità di
    punteggio vince la prima dichiarata. Nessuna attiva → default_rule.
    """
    active = [
        rule
        for rule in rubric.rules
        if all(judgments.get(question, 0.0) >= threshold for question, threshold in rule.conditions.items())
    ]
    if not active:
        return [], rubric.default_rule
    ordered = sorted(active, key=lambda rule: -rule.score)
    return ordered, ordered[0]
