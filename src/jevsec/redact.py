"""Redazione a monte: dal finding allo state che vede il motore.

Funzione pura (constitution V): stesso finding e stesso limite → stesso state,
ricostruibile in audit senza registrare il payload inviato.
"""

from __future__ import annotations

import re
from typing import Any

HEX_MIN_CHARS = 16
BASE64_MIN_CHARS = 24
HEX_PLACEHOLDER = "[hex-redacted]"
BLOB_PLACEHOLDER = "[blob-redacted]"
TRUNCATION_MARKER = "[truncated]"

_HEX_RUN = re.compile(r"[0-9a-fA-F]{16,}")
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

_PASSTHROUGH_FIELDS = ("template_id", "matched_at")
_TEXT_FIELDS = ("response_snippet", "extracted_results")


def redact_text(text: str, max_chars: int) -> tuple[str, bool]:
    """Tronca a max_chars con marcatore, poi sostituisce hex e blob. Ritorna (testo, troncato)."""
    was_truncated = False
    if len(text) > max_chars:
        text = text[:max_chars] + TRUNCATION_MARKER
        was_truncated = True
    text = _HEX_RUN.sub(HEX_PLACEHOLDER, text)
    text = _BASE64_RUN.sub(BLOB_PLACEHOLDER, text)
    return text, was_truncated


def build_state(finding: dict[str, Any], max_state_chars: int) -> tuple[dict[str, Any], bool]:
    """Costruisce lo StateForModel: solo i campi giudicabili, redatti e troncati.

    Ritorna (state, truncated). I campi assenti o vuoti non compaiono nello state.
    """
    state: dict[str, Any] = {}
    any_truncated = False
    for field in _PASSTHROUGH_FIELDS:
        value = finding.get(field)
        if value:
            state[field] = value
    if finding.get("response_snippet"):
        text, was_truncated = redact_text(str(finding["response_snippet"]), max_state_chars)
        state["response_snippet"] = text
        any_truncated = any_truncated or was_truncated
    extracted = finding.get("extracted_results")
    if extracted:
        redacted_items = []
        for item in extracted:
            text, was_truncated = redact_text(str(item), max_state_chars)
            redacted_items.append(text)
            any_truncated = any_truncated or was_truncated
        state["extracted_results"] = redacted_items
    return state, any_truncated
