"""Per-osservazione: redige, chiede le domande atomiche della rubrica, ricombina.

Il modello non vede mai l'obiettivo né parole-scenario (FR-003, FR-010): giudica
fatti. L'impatto lo calcola apply_rules nel codice. Ogni fallimento degrada in
record con errore e impatto nullo (FR-007).
"""

from __future__ import annotations

import hashlib
from typing import Any, Callable

from jevsec.client import SystemOneError, answer_value, ask
from jevsec.redact import redact_text
from jevsec.rubric import ObjectiveRubric, PrioritizationConfig, apply_rules

AskFunction = Callable[..., tuple[dict[str, Any], float]]

# FR-010: il payload (state + domande) non deve contenere parole che rivelano il
# tipo di attività. Verificato da test; se una istruzione di rubrica ne contiene
# una, il test fallisce prima che il codice veda un modello.
SCENARIO_WORDS = ("ctf", "flag", "pentest", "pen test", "engagement", "red team", "company", "azienda")

QUICK_WIN_QUESTION = "quick_win"
QUICK_WIN_THRESHOLD = 0.5


def _base_record(obs_ref: str, objective: str) -> dict[str, Any]:
    return {
        "obs_ref": obs_ref,
        "objective": objective,
        "impact": None,
        "winning_rule": None,
        "active_rules": [],
        "judgments": {},
        "quick_win": None,
        "quick_win_probability": None,
        "truncated": False,
        "error": None,
        "observation": None,
        "obs_hash": None,
    }


def observation_hash(state: dict[str, Any]) -> str:
    """Identità di contenuto dello state redatto: dedupe e replay senza testo grezzo (004 D4)."""
    return hashlib.sha256(
        (state.get("text", "") + "\x00" + state.get("context", "")).encode("utf-8")
    ).hexdigest()


def build_state(observation: dict[str, Any], max_state_chars: int) -> tuple[dict[str, Any], bool]:
    """State neutro: solo text e context redatti. L'obiettivo non entra mai (FR-003)."""
    state: dict[str, Any] = {}
    any_truncated = False
    text, was_truncated = redact_text(str(observation["text"]), max_state_chars)
    state["text"] = text
    any_truncated = any_truncated or was_truncated
    if observation.get("context"):
        context, was_truncated = redact_text(str(observation["context"]), max_state_chars)
        state["context"] = context
        any_truncated = any_truncated or was_truncated
    return state, any_truncated


def prioritize_observation(
    observation: dict[str, Any],
    obs_ref: str,
    config: PrioritizationConfig,
    rubric: ObjectiveRubric,
    ask_fn: AskFunction = ask,
) -> dict[str, Any]:
    """Un'osservazione → un ImpactRecord (o record d'errore con impatto nullo)."""
    record = _base_record(obs_ref, rubric.name)

    if not isinstance(observation.get("text"), str) or not observation["text"].strip():
        record["error"] = "text missing or empty: nothing to judge"
        return record

    state, was_truncated = build_state(observation, config.max_state_chars)
    record["truncated"] = was_truncated
    record["observation"] = state
    record["obs_hash"] = observation_hash(state)

    try:
        response, _latency = ask_fn(config.base_url, state, rubric.questions, config.timeout_s, api_token=config.api_token, model=config.model)
    except SystemOneError as error:
        record["error"] = f"engine: {error}"
        return record

    judgments: dict[str, float] = {}
    try:
        answers = response.get("answers", {})
        for question_name in rubric.questions:
            judgments[question_name] = float(answer_value(answers[question_name]))
    except (KeyError, TypeError, ValueError, SystemOneError) as error:
        record["error"] = f"unexpected engine response: {error}"
        return record

    record["judgments"] = judgments
    active_rules, winner = apply_rules(judgments, rubric)
    record["impact"] = winner.score
    record["winning_rule"] = winner.name
    record["active_rules"] = [rule.name for rule in active_rules]
    if QUICK_WIN_QUESTION in judgments:
        record["quick_win_probability"] = judgments[QUICK_WIN_QUESTION]
        record["quick_win"] = judgments[QUICK_WIN_QUESTION] >= QUICK_WIN_THRESHOLD
    return record


def sort_impact_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ordina la coda: impatto decrescente, poi quick_win, poi obs_ref (contratto CLI)."""
    return sorted(records, key=lambda record: (
        -(record.get("impact") if record.get("impact") is not None else -1),
        0 if record.get("quick_win") else 1,
        str(record.get("obs_ref", "")),
    ))
