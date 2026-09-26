"""Ordinamento della coda di triage secondo i bucket configurati.

I nomi dei bucket sono fissi, l'ordine vive nella config ([queue] order):
il primo nome è la cima della coda (data-model, FR-003).
"""

from __future__ import annotations

from typing import Any

GATE_AUTO = "auto"
VERDICT_TRUE_POSITIVE = "true_positive"
VERDICT_FALSE_POSITIVE = "false_positive"
VERDICT_NEEDS_REVIEW = "needs_review"


def bucket_of(record: dict[str, Any]) -> str:
    """Bucket di appartenenza di un TriageRecord secondo le regole del data-model."""
    if record.get("verdict") == VERDICT_FALSE_POSITIVE:
        return "false_positive"
    if record.get("error") or record.get("verdict") in (None, VERDICT_NEEDS_REVIEW):
        return "review_uncertain"
    if record.get("verdict") == VERDICT_TRUE_POSITIVE:
        if record.get("gate") == GATE_AUTO:
            return "auto_tp_preauth" if record.get("no_auth") else "auto_tp_no_preauth"
        return "review_tp"
    return "review_uncertain"


def sort_records(records: list[dict[str, Any]], order: tuple[str, ...]) -> list[dict[str, Any]]:
    """Ordina la coda: bucket secondo order, poi probabilità descrescente, poi finding_ref."""
    bucket_index = {name: position for position, name in enumerate(order)}

    def sort_key(record: dict[str, Any]) -> tuple[int, float, str]:
        probability = record.get("verdict_probability")
        return (
            bucket_index[bucket_of(record)],
            -(probability if probability is not None else 0.0),
            str(record.get("finding_ref", "")),
        )

    return sorted(records, key=sort_key)
