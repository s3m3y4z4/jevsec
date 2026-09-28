"""Drop-zone di consegna per le sessioni (spec 007): routing, stabilità, registro, valutazione.

L'inbox valuta soltanto: ogni riga consegnata passa dai percorsi di ingest
esistenti (Session.add_finding / add_observation). Nessuna azione assistita,
nessun traffico oltre il backend già configurato (FR-010).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from jevsec.config import InboxConfig

ACTION_DELIVER_FINDINGS = "deliver-findings"
ACTION_DELIVER_OBSERVATIONS = "deliver-observations"
ACTION_REJECT = "reject"
ACTION_IGNORE = "ignore"
END_EVENTS = ("end",)


@dataclass(frozen=True)
class Routing:
    """Esito dell'instradamento di un nome file (FR-013)."""

    action: str
    objective: str | None = None
    reason: str | None = None


def finding_hash(finding: dict[str, Any]) -> str:
    """Impronta del finding grezzo, pre-redazione (spec 007 FR-008).

    Il JSON canonico (chiavi ordinate) rende lo stesso dict sempre identico:
    serve alla dedup dell'inbox senza esporre il testo che la redazione rimuove.
    """
    canonical = json.dumps(finding, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def route_name(filename: str) -> Routing:
    """Instrada dal solo nome: findings / observations-<objective> / scarto / ignorato.

    L'estensione è case-sensitive e solo `.jsonl` è una consegna; i file nascosti
    e le estensioni provvisorie non sono consegne e non producono registro.
    L'objective arriva grezzo: la validità contro la rubrica spetta al processore.
    """
    if filename.startswith("."):
        return Routing(ACTION_IGNORE)
    stem, dot, extension = filename.rpartition(".")
    if not dot or extension != "jsonl":
        return Routing(ACTION_IGNORE)
    if stem == "findings" or stem.startswith("findings-"):
        return Routing(ACTION_DELIVER_FINDINGS)
    if stem.startswith("observations-"):
        return Routing(ACTION_DELIVER_OBSERVATIONS, objective=stem.split("-")[1])
    return Routing(ACTION_REJECT, reason=f"unknown prefix: {stem!r}")


class StabilityTracker:
    """Candidato solo quando le ultime `reads` letture di dimensione coincidono (FR-006)."""

    def __init__(self, reads: int):
        self._reads = reads
        self._sizes: dict[str, deque[int]] = {}

    def observe(self, path: str, size: int) -> bool:
        sizes = self._sizes.setdefault(path, deque(maxlen=self._reads))
        sizes.append(size)
        return len(sizes) == self._reads and all(value == sizes[0] for value in sizes)

    def forget(self, path: str) -> None:
        self._sizes.pop(path, None)


class DeliveryLog:
    """Registro delle consegne: append-only in inbox-log.jsonl, una riga per fase (FR-003)."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def append(self, entry: dict[str, Any]) -> None:
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **entry}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def known_outcomes(self) -> dict[str, str]:
        """sha256 → stato finale: l'ultima riga di chiusura vince."""
        outcomes: dict[str, str] = {}
        for entry in self.entries():
            sha = entry.get("sha256")
            if sha and entry.get("event") in END_EVENTS:
                outcomes[sha] = str(entry.get("status"))
        return outcomes

    def open_starts(self) -> list[dict[str, Any]]:
        """start rimasti senza end: consegne interrotte da chiudere alla ripartenza (FR-005)."""
        closed: set[str] = set()
        opened: list[dict[str, Any]] = []
        for entry in self.entries():
            sha = entry.get("sha256")
            if not sha:
                continue
            if entry.get("event") in END_EVENTS:
                closed.add(sha)
            elif entry.get("event") == "start":
                opened.append(entry)
        return [entry for entry in opened if entry["sha256"] not in closed]


class InboxProcessor:
    """Una scansione della inbox di una sessione: stabilità → routing → valutazione → registro.

    Il contenuto si legge una volta sola in buffer: sha256, righe valutate e
    righe residue dopo un crash si riferiscono tutte allo stesso contenuto.
    """

    def __init__(self, session: Any, config: InboxConfig, note_backend_outcome: Callable[[bool], None]):
        self.session = session
        self.config = config
        self.note_backend_outcome = note_backend_outcome
        self.inbox_dir = session.directory / "inbox"
        self.archive_dir = self.inbox_dir / "archive"
        self.rejected_dir = self.inbox_dir / "rejected"
        self.log = DeliveryLog(session.directory / "inbox-log.jsonl")
        self.tracker = StabilityTracker(config.stability_reads)
        self._outcomes = self.log.known_outcomes()

    def scan(self) -> None:
        self._close_interrupted()
        if not self.inbox_dir.exists():
            return
        candidates: list[tuple[int, str, Path, Routing]] = []
        for entry in sorted(self.inbox_dir.iterdir()):
            if not entry.is_file():
                continue
            routing = route_name(entry.name)
            if routing.action == ACTION_IGNORE:
                continue
            stat = entry.stat()
            if not self.tracker.observe(entry.name, stat.st_size):
                continue
            candidates.append((stat.st_ctime_ns, entry.name, entry, routing))
        for _, _, entry, routing in sorted(candidates, key=lambda item: (item[0], item[1])):
            try:
                self._deliver(entry, routing)
            except OSError as error:
                print(f"inbox: delivery of {entry.name} failed: {error}", file=sys.stderr)
            self.tracker.forget(entry.name)

    def _close_interrupted(self) -> None:
        """FR-005/SC-003: ogni start senza end si chiude interrupted, mai rivalutata."""
        for entry in self.log.open_starts():
            delivered = self.inbox_dir / str(entry["file"])
            archived_as: str | None = None
            note = "daemon stopped mid-delivery; residual lines inspectable in the archive"
            if delivered.exists():
                archived_as = self._move(delivered, self.archive_dir)
            else:
                already_archived = next(self.archive_dir.glob(f"*-{entry['file']}"), None)
                if already_archived is not None:
                    archived_as = str(already_archived.relative_to(self.session.directory))
                else:
                    note = "daemon stopped mid-delivery; delivered file not found on disk"
            counts = {"lines": entry["lines"]} if entry.get("lines") is not None else {}
            self._end(entry["file"], entry.get("sha256"), entry.get("kind"), entry.get("objective"),
                      "interrupted", archived_as, note=note, **counts)

    def _deliver(self, path: Path, routing: Routing) -> None:
        if routing.action == ACTION_REJECT:
            self._reject(path, routing.reason)
            return
        if routing.action == ACTION_DELIVER_OBSERVATIONS and \
                routing.objective not in self.session.prioritization_config.objectives:
            self._reject(path, f"unknown objective {routing.objective!r}: no rubric for it")
            return
        stat = path.stat()
        if stat.st_size > self.config.max_file_bytes:
            self._reject(path, f"file over max_file_bytes ({stat.st_size} bytes): not read")
            return
        try:
            raw = path.read_bytes()
        except OSError:
            return
        sha = hashlib.sha256(raw).hexdigest()
        kind = "findings" if routing.action == ACTION_DELIVER_FINDINGS else "observations"
        if sha in self._outcomes:
            archived = self._move(path, self.archive_dir)
            self._end(path.name, sha, kind, routing.objective, "already-processed", archived,
                      note="same content already delivered")
            return
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            self._reject(path, "non interpretable content: not valid UTF-8", sha=sha, kind=kind,
                         objective=routing.objective)
            return
        non_empty = [(index, line) for index, line in enumerate(text.splitlines(), start=1) if line.strip()]
        started = time.monotonic()
        self.log.append({"event": "start", "file": path.name, "sha256": sha, "kind": kind,
                         "objective": routing.objective, "lines": len(non_empty)})
        archived_as = self._move(path, self.archive_dir)
        errors: list[dict[str, Any]] = []
        evaluated = duplicates = degraded = 0
        for index, line in non_empty:
            outcome = self._evaluate_line(kind, routing.objective, line)
            if outcome == "duplicate":
                duplicates += 1
            elif isinstance(outcome, dict):
                self.note_backend_outcome(outcome.get("error") is None)
                evaluated += 1
                if outcome.get("error"):
                    degraded += 1
            else:
                errors.append({"line": index, "error": str(outcome)})
        # SC-005: righe valutate ma degradate (backend giù) dichiarano l'esito parziale
        status = "partial" if errors or degraded else "processed"
        if errors and evaluated + duplicates == 0:
            status = "rejected"
            archived_as = self._move(self.session.directory / archived_as, self.rejected_dir)
        self._end(path.name, sha, kind, routing.objective, status, archived_as,
                  lines=len(non_empty), evaluated=evaluated, duplicates=duplicates, errors=errors,
                  duration_s=round(time.monotonic() - started, 3),
                  note="no parsable JSON lines" if status == "rejected" else None)

    def _evaluate_line(self, kind: str, objective: str | None, line: str) -> Any:
        """Una riga → record valutato, 'duplicate', o diagnosi d'errore di riga."""
        try:
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError("line is not a JSON object")
            if kind == "findings":
                digest = finding_hash(item)
                if digest in self.session.finding_hashes:
                    return "duplicate"
                return self.session.add_finding(item)
            envelope = self.session.add_observation(str(objective), item)
            if "duplicate_of" in envelope:
                return "duplicate"
            return envelope
        except (json.JSONDecodeError, ValueError, RuntimeError) as error:
            # RuntimeError copre SessionError senza importarla (objective senza rubrica ecc.)
            return f"{type(error).__name__}: {error}"

    def _reject(self, path: Path, reason: str, sha: str | None = None,
                kind: str | None = None, objective: str | None = None) -> None:
        archived = self._move(path, self.rejected_dir)
        self._end(path.name, sha, kind, objective, "rejected", archived, note=reason)

    def _move(self, path: Path, destination_dir: Path) -> str:
        destination_dir.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y%m%dT%H%M%S")
        destination = destination_dir / f"{timestamp}-{path.name}"
        counter = 2
        while destination.exists():
            destination = destination_dir / f"{timestamp}-{counter}-{path.name}"
            counter += 1
        os.replace(path, destination)
        return str(destination.relative_to(self.session.directory))

    def _end(self, file: str, sha: str | None, kind: str | None, objective: str | None,
             status: str, archived_as: str | None = None, note: str | None = None, **counts: Any) -> None:
        entry: dict[str, Any] = {"event": "end", "file": file, "status": status}
        if archived_as is not None:
            entry["archived_as"] = archived_as
        if sha is not None:
            entry["sha256"] = sha
        if kind is not None:
            entry["kind"] = kind
        if objective is not None:
            entry["objective"] = objective
        if counts:
            entry.update(counts)
        if note is not None:
            entry["note"] = note
        self.log.append(entry)
        if sha is not None:
            self._outcomes[sha] = status
