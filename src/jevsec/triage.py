"""Per-finding: redige, chiede al motore, estrae i giudizi, applica il gate.

Ogni fallimento degrada nel record come errore + gate review: mai un'eccezione
verso l'alto, mai un finding scartato (FR-007).
"""

from __future__ import annotations

from typing import Any, Callable

from jevsec.actions import target_from_url
from jevsec.client import SystemOneError, answer_probability, answer_value, ask
from jevsec.config import Config
from jevsec.queue import GATE_AUTO, VERDICT_NEEDS_REVIEW
from jevsec.redact import build_state

AskFunction = Callable[..., tuple[dict[str, Any], float]]


def _base_record(finding_ref: str) -> dict[str, Any]:
    return {
        "finding_ref": finding_ref,
        "verdict": None,
        "verdict_probability": None,
        "no_auth": None,
        "no_auth_probability": None,
        "severity": None,
        "gate": "review",
        "truncated": False,
        "error": None,
        "target": None,
        "state": None,
    }


def _error_record(
    finding_ref: str, error: str, truncated: bool = False, severity: str | None = None,
    target: dict[str, str] | None = None, state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = _base_record(finding_ref)
    record["error"] = error
    record["truncated"] = truncated
    record["severity"] = severity
    record["target"] = target
    record["state"] = state
    return record


def triage_finding(finding: dict[str, Any], finding_ref: str, config: Config, ask_fn: AskFunction = ask) -> dict[str, Any]:
    """Un finding → un TriageRecord completo o in errore (sempre gate=review se in errore)."""
    severity = finding.get("info", {}).get("severity") if isinstance(finding.get("info"), dict) else None
    target = target_from_url(finding.get("matched_at", ""))

    if not finding.get("template_id"):
        return _error_record(finding_ref, "template_id missing: finding cannot be identified", severity=severity, target=target)

    state, was_truncated = build_state(finding, config.max_state_chars)

    if not state.get("response_snippet") and not state.get("extracted_results"):
        return _error_record(
            finding_ref,
            "textual evidence missing (response_snippet and extracted_results absent or empty): nothing to judge",
            truncated=was_truncated,
            severity=severity,
            target=target,
            state=state,
        )

    try:
        response, _latency = ask_fn(config.base_url, state, config.questions, config.timeout_s, api_token=config.api_token, model=config.model)
    except SystemOneError as error:
        return _error_record(finding_ref, f"engine: {error}", truncated=was_truncated, severity=severity, target=target)

    record = _base_record(finding_ref)
    record["truncated"] = was_truncated
    record["severity"] = severity
    record["target"] = target
    record["state"] = state

    try:
        answers = response.get("answers", {})
        verdict_answer = answers["verdict"]
        no_auth_answer = answers["no_auth"]
        verdict = answer_value(verdict_answer)
        probabilities = verdict_answer.get("probabilities")
        if not isinstance(probabilities, dict) or str(verdict) not in probabilities:
            raise ValueError(f"verdict probabilities missing for the chosen option {verdict!r}")
        verdict_probability = answer_probability(verdict_answer)
        no_auth_probability = float(answer_value(no_auth_answer))
    except (KeyError, TypeError, ValueError, SystemOneError) as error:
        record["error"] = f"unexpected engine response: {error}"
        return record

    record["verdict"] = verdict
    record["verdict_probability"] = verdict_probability
    record["no_auth_probability"] = no_auth_probability
    record["no_auth"] = no_auth_probability >= config.pre_auth
    if verdict == VERDICT_NEEDS_REVIEW:
        record["gate"] = "review"
    else:
        is_above_threshold = verdict_probability >= config.auto_verdict
        record["gate"] = GATE_AUTO if (config.auto_gate_enabled and is_above_threshold) else "review"
    return record
