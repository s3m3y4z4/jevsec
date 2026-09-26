"""Client HTTP minimale per endpoint System One (/v1/systemone).

Compatibile con reflex, decider e l'API hosted di TypeSafe: stesso formato wire.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

DEFAULT_TIMEOUT_S = 180.0
DEFAULT_MODEL = "jev-latest"


class SystemOneError(RuntimeError):
    """Errore di comunicazione o risposta malformata dall'endpoint System One."""


def ask(
    base_url: str,
    state: Any,
    questions: dict[str, Any],
    timeout_s: float = DEFAULT_TIMEOUT_S,
    api_token: str | None = None,
    model: str = DEFAULT_MODEL,
) -> tuple[dict[str, Any], float]:
    """Invia state e domande tipizzate a un endpoint /v1/systemone.

    Ritorna (risposta completa, latenza in secondi). La latenza misura
    l'intero round trip HTTP, coerente con come si userebbe in produzione.
    Con api_token impostato la richiesta porta Authorization: Bearer;
    i certificati vengono verificati con le CA di sistema, sempre.
    """
    payload = {"model": model, "state": state, "questions": questions}
    headers = {"Content-Type": "application/json"}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
    request = urllib.request.Request(
        base_url.rstrip("/") + "/v1/systemone",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[:500]
        raise SystemOneError(f"HTTP {error.code}: {detail}") from error
    except urllib.error.URLError as error:
        raise SystemOneError(f"connection failed: {error.reason}") from error
    except json.JSONDecodeError as error:
        raise SystemOneError(f"non-JSON response: {error}") from error
    if not isinstance(body.get("answers"), dict):
        raise SystemOneError(f"response without 'answers': {json.dumps(body)[:300]}")
    return body, time.perf_counter() - started


def answer_value(answer: dict[str, Any]) -> Any:
    """Estrae il valore tipizzato da una singola risposta (choice/score/noul)."""
    for key in ("choice", "score", "noul"):
        if key in answer:
            return answer[key]
    raise SystemOneError(f"answer without a known value: {json.dumps(answer)[:300]}")


def answer_probability(answer: dict[str, Any]) -> float:
    """Probabilità associata alla risposta data, per la calibrazione.

    Per choice è la probabilità dell'opzione scelta, per score quella del
    livello più vicino al punteggio pesato, per noul il valore stesso.
    """
    if "noul" in answer:
        return float(answer["noul"])
    value = answer_value(answer)
    probabilities = answer.get("probabilities", {})
    lookup_key = str(int(round(value))) if "score" in answer else str(value)
    for key, probability in probabilities.items():
        if lookup_key == str(key):
            return float(probability)
    return max((float(p) for p in probabilities.values()), default=0.0)
