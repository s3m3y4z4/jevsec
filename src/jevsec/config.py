"""Carica e valida la configurazione live-triage (TOML).

Ogni violazione diventa ConfigError con diagnosi precisa: la CLI la traduce
in exit 2 prima di leggere qualunque riga di input (FR-004, FR-005).
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

QUESTION_NAMES = frozenset({"verdict", "no_auth"})
ALLOWED_QUESTION_TYPES = frozenset({"choice", "noul"})
ALLOWED_QUESTION_FIELDS = frozenset({"type", "instructions", "criteria"})
BUCKET_NAMES = frozenset(
    {"auto_tp_preauth", "review_tp", "review_uncertain", "auto_tp_no_preauth", "false_positive"}
)
MIN_AUTO_VERDICT = 0.5
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class ConfigError(RuntimeError):
    """Configurazione assente, malformata o fuori vincolo: fatale, exit 2."""


def is_loopback_url(base_url: str) -> bool:
    host = urlsplit(base_url).hostname or ""
    return host.lower() in LOOPBACK_HOSTS


def channel_violation(base_url: str, api_token: str | None) -> str | None:
    """Prima violazione del canale decisionale (messaggio EN), None se ammessa.

    Regola (spec 005 FR-008): loopback sempre ammesso; qualunque altro host
    richiede https e token, altrimenti la configurazione viene rifiutata
    prima che una sola riga di testo di engagement parta.
    """
    if is_loopback_url(base_url):
        return None
    if not base_url.startswith("https://"):
        host = urlsplit(base_url).hostname or base_url
        return f"remote backend requires https: {host}; refused to send engagement text in clear"
    if not (isinstance(api_token, str) and api_token.strip()):
        return "remote backend requires api_token in [backend]; refused unauthenticated remote channel"
    return None


@dataclass(frozen=True)
class Config:
    """Configurazione validata: soglie, ordine coda, domande wire."""

    base_url: str
    timeout_s: float
    health_ttl_s: float
    auto_gate_enabled: bool
    auto_verdict: float
    pre_auth: float
    max_state_chars: int
    queue_order: tuple[str, ...]
    questions: dict[str, dict[str, Any]]
    api_token: str | None = None
    model: str = "jev-latest"


def _require_probability(section: str, key: str, value: Any) -> float:
    if not isinstance(value, (int, float)) or not 0.0 <= float(value) <= 1.0:
        raise ConfigError(f"[{section}] {key}={value!r}: expected a probability in [0, 1]")
    return float(value)


def _validate_question(name: str, question: Any) -> dict[str, Any]:
    if not isinstance(question, dict):
        raise ConfigError(f"[questions.{name}] expected a table, found {type(question).__name__}")
    unknown = set(question) - ALLOWED_QUESTION_FIELDS
    if unknown:
        raise ConfigError(f"[questions.{name}] unknown fields: {sorted(unknown)}")
    question_type = question.get("type")
    if question_type not in ALLOWED_QUESTION_TYPES:
        raise ConfigError(f"[questions.{name}] type={question_type!r}: allowed {sorted(ALLOWED_QUESTION_TYPES)}")
    if not isinstance(question.get("instructions"), str) or not question["instructions"].strip():
        raise ConfigError(f"[questions.{name}] instructions is required and must not be empty")
    criteria = question.get("criteria")
    if question_type == "noul":
        if criteria is not None:
            raise ConfigError(f"[questions.{name}] criteria not allowed for noul (TypeSafe schema)")
    elif not isinstance(criteria, dict) or not criteria:
        raise ConfigError(f"[questions.{name}] criteria is required and non-empty for choice")
    return dict(question)


def _validate_queue(order: Any) -> tuple[str, ...]:
    if not isinstance(order, list) or not order:
        raise ConfigError("[queue] order expected as a non-empty list of buckets")
    names = tuple(order)
    unknown = set(names) - BUCKET_NAMES
    if unknown:
        raise ConfigError(f"[queue] order contains unknown buckets: {sorted(unknown)}")
    if len(set(names)) != len(names):
        raise ConfigError("[queue] order contains duplicate buckets")
    missing = BUCKET_NAMES - set(names)
    if missing:
        raise ConfigError(f"[queue] order must be a permutation of all buckets, missing: {sorted(missing)}")
    return names


def load_config(path: Path) -> Config:
    """Legge e valida il file TOML; solleva ConfigError alla prima violazione."""
    try:
        with Path(path).open("rb") as handle:
            raw = tomllib.load(handle)
    except FileNotFoundError as error:
        raise ConfigError(f"config not found: {path}") from error
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"invalid TOML config: {path}: {error}") from error

    backend = raw.get("backend")
    if not isinstance(backend, dict):
        raise ConfigError("[backend] section is required")
    base_url = backend.get("base_url")
    if not isinstance(base_url, str) or not base_url.startswith(("http://", "https://")):
        raise ConfigError(f"[backend] base_url={base_url!r}: expected an http(s) URL")
    timeout_s = backend.get("timeout_s", 30.0)
    if not isinstance(timeout_s, (int, float)) or float(timeout_s) <= 0:
        raise ConfigError(f"[backend] timeout_s={timeout_s!r}: expected a positive number")
    health_ttl_s = backend.get("health_ttl_s", 300.0)
    if not isinstance(health_ttl_s, (int, float)) or float(health_ttl_s) <= 0:
        raise ConfigError(f"[backend] health_ttl_s={health_ttl_s!r}: expected a positive number")
    api_token = backend.get("api_token")
    if api_token is not None and not isinstance(api_token, str):
        raise ConfigError("[backend] api_token expected as a string")
    model = backend.get("model", "jev-latest")
    if not isinstance(model, str) or not model.strip():
        raise ConfigError(f"[backend] model={model!r}: expected a non-empty string")
    violation = channel_violation(base_url, api_token)
    if violation is not None:
        raise ConfigError(violation)

    thresholds = raw.get("thresholds")
    if not isinstance(thresholds, dict):
        raise ConfigError("[thresholds] section is required")
    auto_gate_enabled = thresholds.get("auto_gate_enabled", False)
    if not isinstance(auto_gate_enabled, bool):
        raise ConfigError(f"[thresholds] auto_gate_enabled={auto_gate_enabled!r}: expected a boolean")
    auto_verdict = _require_probability("thresholds", "auto_verdict", thresholds.get("auto_verdict"))
    if auto_verdict < MIN_AUTO_VERDICT:
        raise ConfigError(
            f"[thresholds] auto_verdict={auto_verdict}: minimum {MIN_AUTO_VERDICT} "
            "(lower values would auto-approve worse-than-chance verdicts)"
        )
    pre_auth = _require_probability("thresholds", "pre_auth", thresholds.get("pre_auth"))
    max_state_chars = thresholds.get("max_state_chars")
    if not isinstance(max_state_chars, int) or max_state_chars <= 0:
        raise ConfigError(f"[thresholds] max_state_chars={max_state_chars!r}: expected a positive integer")

    queue = raw.get("queue")
    if not isinstance(queue, dict):
        raise ConfigError("[queue] section is required")
    queue_order = _validate_queue(queue.get("order"))

    questions_raw = raw.get("questions")
    if not isinstance(questions_raw, dict):
        raise ConfigError("[questions] section is required")
    if set(questions_raw) != QUESTION_NAMES:
        raise ConfigError(
            f"[questions] the tool sends exactly {sorted(QUESTION_NAMES)}, found: {sorted(questions_raw)}"
        )
    questions = {name: _validate_question(name, question) for name, question in questions_raw.items()}

    return Config(
        base_url=base_url,
        timeout_s=float(timeout_s),
        health_ttl_s=float(health_ttl_s),
        auto_gate_enabled=auto_gate_enabled,
        auto_verdict=auto_verdict,
        pre_auth=pre_auth,
        max_state_chars=max_state_chars,
        queue_order=queue_order,
        questions=questions,
        api_token=api_token,
        model=model,
    )
