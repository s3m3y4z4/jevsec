"""Azione assistita: playbook suggeriti ed esecuzione con conferma umana (spec 006).

Il comando ha una sola sorgente: template dichiarato in config + campi del record.
Il campo `confirm` del client può solo coincidere con l'argv ricostruito o fallire:
nessun testo arrivato dalla rete viene mai eseguito (research R2).
Allowlist assente ⇒ esecuzione disabilitata; le proposte testuali restano.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

TRIAGE_BUCKETS = frozenset(
    {"auto_tp_preauth", "review_tp", "review_uncertain", "auto_tp_no_preauth", "false_positive"}
)
PLACEHOLDERS = frozenset({"host", "port", "scheme", "path"})
DEFAULT_TIMEOUT_S = 120.0
MAX_OUTPUT_BYTES = 64 * 1024
REDUCED_ENV_KEYS = ("PATH", "HOME", "LANG")


class ActionError(RuntimeError):
    """Config o richiesta d'azione invalida: fatale (config) o 400 (richiesta)."""


class ActionConfigError(ActionError):
    """config/actions.toml malformata: avvio rifiutato con template/chiave nominati."""


@dataclass(frozen=True)
class PlaybookTemplate:
    """Un template per bucket di triage (command) o regola di prioritizzazione (suggestion)."""

    name: str
    description: str
    command: tuple[str, ...] | None = None
    suggestion: str | None = None

    @property
    def is_executable(self) -> bool:
        return self.command is not None


@dataclass(frozen=True)
class ActionsConfig:
    """Config validata: playbook, allowlist, scope, esecuzione."""

    triage: dict[str, PlaybookTemplate] = field(default_factory=dict)
    prioritize: dict[str, PlaybookTemplate] = field(default_factory=dict)
    tools: tuple[str, ...] = ()
    scope: tuple[str, ...] = ()
    timeout_s: float = DEFAULT_TIMEOUT_S
    enabled: bool = False  # True solo con allowlist tools non vuota

    def template(self, name: str) -> PlaybookTemplate | None:
        if name.startswith("triage."):
            return self.triage.get(name.removeprefix("triage."))
        if name.startswith("prioritize."):
            return self.prioritize.get(name.removeprefix("prioritize."))
        return None


class ActionRefused(ActionError):
    """Richiesta d'azione rifiutata: 400 con diagnosi, nessun processo avviato, nessun audit."""


def resolve_argv(record: dict[str, Any], template: PlaybookTemplate) -> list[str] | None:
    """L'argv ricostruito dal template e dal record: la sola sorgente legittima (research R2)."""
    if template.command is None:
        return None
    target = record.get("target")
    if not isinstance(target, dict):
        return None
    argv: list[str] = []
    for part in template.command:
        filled = part
        for token in _placeholder_tokens(part):
            if token not in target or target[token] in (None, ""):
                return None
            filled = filled.replace("{" + token + "}", str(target[token]))
        argv.append(filled)
    return argv


def execute_action(
    *,
    session_name: str,
    session_dir: Path,
    record: dict[str, Any],
    template_name: str,
    confirm: list[str],
    config: ActionsConfig,
) -> dict[str, Any]:
    """Esegue l'azione assistita: conferma per-azione, allowlist, scope, audit pre-risposta.

    Ritorna il payload di risposta (audit inclusa) o solleva ActionRefused (nessun
    processo, nessun audit). L'audit di un'azione partita viene scritta SEMPRE, anche
    a timeout o errore del processo (exit_code None in caso di timeout).
    """
    if not config.enabled:
        raise ActionRefused("execution disabled: declare [allowlist] tools in config/actions.toml")
    template = config.template(template_name)
    if template is None:
        raise ActionRefused(f"unknown template: {template_name}")
    argv = resolve_argv(record, template)
    if argv is None:
        raise ActionRefused(f"no executable proposal for this record (template {template_name})")
    if list(confirm) != argv:
        raise ActionRefused("confirm does not match the proposed command")
    tool = argv[0]
    if tool not in config.tools:
        raise ActionRefused(f"tool not in allowlist: {tool}")
    hosts = [record["target"][key] for key in ("host",) if key in record.get("target", {})]
    for host in hosts:
        if not target_in_scope(host, config.scope):
            raise ActionRefused(f"target out of scope: {host} (scope: {', '.join(config.scope)})")

    reduced_env = {key: os.environ[key] for key in REDUCED_ENV_KEYS if key in os.environ}
    started = time.perf_counter()
    timed_out = False
    try:
        completed = subprocess.run(
            argv, shell=False, cwd=str(session_dir), env=reduced_env,
            capture_output=True, timeout=config.timeout_s, check=False,
        )
        exit_code: int | None = completed.returncode
        stdout = completed.stdout.decode("utf-8", errors="replace")[:MAX_OUTPUT_BYTES]
        stderr = completed.stderr.decode("utf-8", errors="replace")[:MAX_OUTPUT_BYTES]
    except subprocess.TimeoutExpired as error:
        timed_out = True
        exit_code = None
        stdout = (error.stdout or b"").decode("utf-8", errors="replace")[:MAX_OUTPUT_BYTES]
        stderr = f"timed out after {config.timeout_s}s"
    duration_ms = int((time.perf_counter() - started) * 1000)

    audit = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "session": session_name,
        "ref": record.get("finding_ref") or record.get("obs_ref"),
        "template": template_name,
        "argv": argv,
        "target": hosts,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": duration_ms,
    }
    session_dir.mkdir(parents=True, exist_ok=True)
    with (session_dir / "actions.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(audit, ensure_ascii=False) + "\n")

    result = dict(audit)
    if timed_out:
        result["stderr"] = stderr
    return result


def _validate_template(name: str, raw: Any) -> PlaybookTemplate:
    where = name if "." in name else name
    if not isinstance(raw, dict):
        raise ActionConfigError(f"[{where}] expected a table")
    description = raw.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ActionConfigError(f"[{where}] description is required and must not be empty")
    command = raw.get("command")
    suggestion = raw.get("suggestion")
    if command is not None and suggestion is not None:
        raise ActionConfigError(f"[{where}] command and suggestion are mutually exclusive")
    if suggestion is not None:
        if not isinstance(suggestion, str) or not suggestion.strip():
            raise ActionConfigError(f"[{where}] suggestion must be a non-empty string")
        return PlaybookTemplate(name=name, description=description, suggestion=suggestion)
    if not isinstance(command, list) or not command or not all(isinstance(p, str) and p for p in command):
        raise ActionConfigError(f"[{where}] command expected as a non-empty list of strings")
    for part in command:
        for token in _placeholder_tokens(part):
            if token not in PLACEHOLDERS:
                raise ActionConfigError(f"[{where}] unknown placeholder {{{token}}} (allowed: {sorted(PLACEHOLDERS)})")
    return PlaybookTemplate(name=name, description=description, command=tuple(command))


def _placeholder_tokens(part: str) -> list[str]:
    # %{…} appartiene allo strumento (es. curl -w), non a noi: solo {…} non preceduto da %.
    return re.findall(r"(?<!%)\{([^{}]*)\}", part)


def load_actions_config(path: Path) -> ActionsConfig:
    """Legge e valida config/actions.toml; assente ⇒ config vuota (proposte off, esecuzione off)."""
    try:
        with Path(path).open("rb") as handle:
            raw = tomllib.load(handle)
    except FileNotFoundError:
        return ActionsConfig()
    except tomllib.TOMLDecodeError as error:
        raise ActionConfigError(f"invalid TOML actions config: {path}: {error}") from error

    triage_raw = raw.get("triage", {})
    if not isinstance(triage_raw, dict):
        raise ActionConfigError("[triage] expected a table")
    triage: dict[str, PlaybookTemplate] = {}
    for bucket, template in triage_raw.items():
        if bucket not in TRIAGE_BUCKETS:
            raise ActionConfigError(f"[triage.{bucket}] unknown bucket (allowed: {sorted(TRIAGE_BUCKETS)})")
        triage[bucket] = _validate_template(f"triage.{bucket}", template)

    prioritize_raw = raw.get("prioritize", {})
    if not isinstance(prioritize_raw, dict):
        raise ActionConfigError("[prioritize] expected a table")
    prioritize = {
        rule: _validate_template(f"prioritize.{rule}", template)
        for rule, template in prioritize_raw.items()
    }

    allowlist = raw.get("allowlist", {})
    if not isinstance(allowlist, dict):
        raise ActionConfigError("[allowlist] expected a table")
    tools = allowlist.get("tools", [])
    if not isinstance(tools, list) or not all(isinstance(t, str) and t.strip() for t in tools):
        raise ActionConfigError("[allowlist] tools expected as a list of non-empty strings")

    scope_raw = raw.get("scope", {})
    if not isinstance(scope_raw, dict):
        raise ActionConfigError("[scope] expected a table")
    targets = scope_raw.get("targets", [])
    if not isinstance(targets, list) or not all(isinstance(t, str) and t.strip() for t in targets):
        raise ActionConfigError("[scope] targets expected as a list of non-empty strings")
    for target in targets:
        _validate_scope_target(target)

    execution = raw.get("execution", {})
    if not isinstance(execution, dict):
        raise ActionConfigError("[execution] expected a table")
    timeout_s = execution.get("timeout_s", DEFAULT_TIMEOUT_S)
    if not isinstance(timeout_s, (int, float)) or float(timeout_s) <= 0:
        raise ActionConfigError(f"[execution] timeout_s={timeout_s!r}: expected a positive number")

    return ActionsConfig(
        triage=triage,
        prioritize=prioritize,
        tools=tuple(tools),
        scope=tuple(targets),
        timeout_s=float(timeout_s),
        enabled=bool(tools),
    )


def _validate_scope_target(target: str) -> None:
    try:
        ipaddress.ip_network(target, strict=False)
        return
    except ValueError:
        pass
    if not target.startswith(".") or len(target) < 2 or " " in target:
        raise ActionConfigError(
            f"[scope] target {target!r}: expected a CIDR network or a domain suffix starting with '.'"
        )


def target_in_scope(host: str, scope: tuple[str, ...]) -> bool:
    """Host in scope se IP dentro un CIDR o hostname con uno dei suffissi dichiarati."""
    if not scope:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for target in scope:
        if address is not None:
            try:
                if address in ipaddress.ip_network(target, strict=False):
                    return True
            except ValueError:
                continue
        elif target.startswith(".") and host.lower().endswith(target.lower()):
            return True
    return False


DEFAULT_PORTS = {"https": 443, "http": 80}


def target_from_url(url: str) -> dict[str, str] | None:
    """Campi {host, port, scheme, path} dall'URL del finding; None se non risolvibile (codice, non modello)."""
    parts = urlsplit(str(url))
    host = parts.hostname
    if not host:
        return None
    scheme = parts.scheme or "http"
    port = parts.port or DEFAULT_PORTS.get(scheme)
    if port is None:
        return None
    return {"host": host, "port": str(port), "scheme": scheme, "path": parts.path.lstrip("/")}


def proposal_for(record: dict[str, Any], config: ActionsConfig, bucket: str | None = None) -> dict[str, Any] | None:
    """La proposta per un record: template del bucket (triage) o della regola vincitrice (prioritize).

    Ritorna {template, description, argv} per template command con tutti i campi risolvibili,
    {template, description, suggestion} per template testuali, None altrimenti (assenza dichiarata).
    """
    template: PlaybookTemplate | None = None
    if bucket is not None:
        template = config.triage.get(bucket)
    elif record.get("winning_rule"):
        template = config.prioritize.get(record["winning_rule"])
    if template is None:
        return None
    if template.suggestion is not None:
        return {"template": template.name, "description": template.description, "suggestion": template.suggestion}
    target = record.get("target")
    if not isinstance(target, dict):
        return None
    argv: list[str] = []
    for part in template.command or ():
        filled = part
        for token in _placeholder_tokens(part):
            if token not in target or target[token] in (None, ""):
                return None  # campo non risolvibile: nessuna proposta, mai argv con segnaposto
            filled = filled.replace("{" + token + "}", str(target[token]))
        argv.append(filled)
    return {"template": template.name, "description": template.description, "argv": argv}
