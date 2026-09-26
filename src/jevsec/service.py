"""Demone locale jevsecd: sessioni d'engagement, API HTTP su 127.0.0.1, console.

Riusa i core esistenti (triage, prioritize, rubriche) senza logica propria di
giudizio (FR-006). Ogni record è scritto su disco quando nasce (write-through);
una sessione riaperta si ricostruisce dai file (SC-003). Nessun subprocess,
nessun traffico oltre il backend dichiarato (FR-007, FR-010).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from jevsec import __version__
from jevsec.client import SystemOneError, ask
from jevsec.config import Config, channel_violation, is_loopback_url, load_config
from jevsec.prioritize import build_state, observation_hash, prioritize_observation, sort_impact_records
from jevsec.queue import sort_records
from jevsec.rubric import PrioritizationConfig, load_rubric
from jevsec.triage import triage_finding

SERVICE_VERSION = __version__
SESSION_NAME_PATTERN = re.compile(r"^[a-z0-9_-]+$")
BACKEND_PROBE_TIMEOUT_S = 5.0
PREVIEW_CHARS = 120
UI_PAGE_PATH = Path(__file__).parent.parent.parent / "ui" / "console.html"
LOCALHOST = "127.0.0.1"


def _text_preview(text: str, limit: int = PREVIEW_CHARS) -> str:
    if len(text) <= limit:
        return text
    cut = text[:limit]
    boundary = cut.rfind(" ")
    if boundary > limit // 2:
        cut = cut[:boundary]
    return cut.rstrip() + "…"


def _light_copy(record: dict[str, Any]) -> dict[str, Any]:
    """Coda leggera: il testo integro sta nei record e nel consiglio, non nel polling (004 D6)."""
    light = dict(record)
    light.pop("observation", None)
    light["text_preview"] = _text_preview((record.get("observation") or {}).get("text", ""))
    return light


class SessionError(RuntimeError):
    """Errore di sessione: diventa 400/404 con diagnosi."""


class Session:
    """Una sessione d'engagement: stato in memoria + write-through su disco."""

    def __init__(self, directory: Path, triage_config: Config, prioritization_config: PrioritizationConfig):
        self.name = directory.name
        self.directory = directory
        self.triage_config = triage_config
        self.prioritization_config = prioritization_config
        self.lock = threading.Lock()
        self.triage_records: list[dict[str, Any]] = []
        self.impact_records: dict[str, list[dict[str, Any]]] = {}
        self.obs_hashes: dict[str, dict[str, str]] = {}
        directory.mkdir(parents=True, exist_ok=True)
        self._reload()

    def _reload(self) -> None:
        for line in self._read_jsonl(self.directory / "triage.jsonl"):
            self.triage_records.append(line)
        for path in sorted(self.directory.glob("prioritize-*.jsonl")):
            objective = path.stem.removeprefix("prioritize-")
            records = list(self._read_jsonl(path))
            hashes: dict[str, str] = {}
            for position, record in enumerate(records, start=1):
                record.setdefault("seq", position)
                if record.get("obs_hash") and not record.get("duplicate_of") and record.get("error") is None:
                    hashes.setdefault(record["obs_hash"], str(record.get("obs_ref")))
            self.impact_records[objective] = records
            self.obs_hashes[objective] = hashes

    @staticmethod
    def _read_jsonl(path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        with path.open(encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def _append(self, filename: str, record: dict[str, Any]) -> None:
        with (self.directory / filename).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def add_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        number = len(self.triage_records) + 1
        record = triage_finding(finding, f"r{number}:{finding.get('template_id', 'unknown')}", self.triage_config)
        with self.lock:
            self.triage_records.append(record)
            self._append("triage.jsonl", record)
        return record

    def add_observation(self, objective: str, observation: dict[str, Any]) -> dict[str, Any]:
        """Un'osservazione → un record, o un puntatore se lo stesso fatto è già stato valutato (004 D4).

        Ritorna il record nuovo/errore, oppure l'involucro {"duplicate_of", "record"} per i duplicati.
        """
        if objective not in self.prioritization_config.objectives:
            raise SessionError(f"unknown objective {objective!r}")
        records = self.impact_records.setdefault(objective, [])
        hashes = self.obs_hashes.setdefault(objective, {})
        obs_ref = observation.get("id") or f"r{len(records) + 1}"
        seq = len(records) + 1
        text = observation.get("text")
        obs_hash = None
        duplicate_of = None
        if isinstance(text, str) and text.strip():
            state, _ = build_state(observation, self.prioritization_config.max_state_chars)
            obs_hash = observation_hash(state)
            duplicate_of = hashes.get(obs_hash)
        if duplicate_of is not None:
            original = next(record for record in records if record.get("obs_ref") == duplicate_of)
            record = {
                "obs_ref": obs_ref, "objective": objective, "seq": seq, "obs_hash": obs_hash,
                "duplicate_of": duplicate_of, "impact": None, "winning_rule": None, "active_rules": [],
                "judgments": {}, "quick_win": None, "quick_win_probability": None,
                "truncated": False, "error": None, "observation": None,
            }
            envelope: dict[str, Any] = {"duplicate_of": duplicate_of, "record": original}
        else:
            record = prioritize_observation(
                observation, obs_ref, self.prioritization_config, self.prioritization_config.objectives[objective]
            )
            record["seq"] = seq
            envelope = record
        with self.lock:
            records.append(record)
            if envelope is record and record.get("error") is None and record.get("obs_hash"):
                hashes.setdefault(str(record["obs_hash"]), str(obs_ref))
            self._append(f"prioritize-{objective}.jsonl", record)
        return envelope

    def next_advice(self, objective: str, since_seq: int | None, top_k: int) -> dict[str, Any]:
        """Il consiglio corrente: top della coda e, col cursore, solo ciò che è nato dopo (004 D7)."""
        if objective not in self.prioritization_config.objectives:
            raise SessionError(f"unknown objective {objective!r}")
        records = self.impact_records.get(objective, [])
        cursor = max((int(record.get("seq") or 0) for record in records), default=0)
        top = sort_impact_records(list(records))[:top_k]
        fresh = ([record for record in records if int(record.get("seq") or 0) > since_seq]
                 if since_seq is not None else [])
        fresh.sort(key=lambda record: int(record.get("seq") or 0))
        return {"objective": objective, "cursor": cursor, "top": top, "fresh": fresh}

    def queues(self) -> dict[str, Any]:
        return {
            "triage": sort_records(list(self.triage_records), self.triage_config.queue_order),
            "prioritize": {
                objective: [_light_copy(record) for record in sort_impact_records(list(records))]
                for objective, records in self.impact_records.items()
            },
        }

    def records(self) -> dict[str, Any]:
        return {"triage": list(self.triage_records), "prioritize": {k: list(v) for k, v in self.impact_records.items()}}

    def add_feedback(self, entry: dict[str, Any]) -> dict[str, Any]:
        record_id = entry.get("id")
        referenced = None
        for records in self.impact_records.values():
            for record in records:
                if record.get("obs_ref") == record_id:
                    referenced = record
                    break
            if referenced:
                break
        if referenced is None:
            raise SessionError(f"prioritization record {record_id!r} not found in this session")
        feedback = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "id": record_id,
            "ranking_ok": bool(entry.get("ranking_ok")),
            "impact_dato": referenced.get("impact"),
            "impact_giusto": entry.get("impact_giusto"),
            "giudizi_sbagliati": entry.get("giudizi_sbagliati", []),
            "note": entry.get("note", ""),
        }
        with self.lock:
            self._append("feedback.jsonl", feedback)
        return feedback


class SessionStore:
    """Apre e ricorda le sessioni; tutto sotto la stessa directory."""

    def __init__(self, sessions_dir: Path, triage_config: Config, prioritization_config: PrioritizationConfig):
        self.sessions_dir = Path(sessions_dir)
        self.triage_config = triage_config
        self.prioritization_config = prioritization_config
        self.sessions: dict[str, Session] = {}
        self.lock = threading.Lock()

    def open(self, name: str) -> Session:
        if not SESSION_NAME_PATTERN.match(name):
            raise SessionError(f"invalid session name {name!r}: allowed a-z 0-9 _ -")
        with self.lock:
            if name not in self.sessions:
                self.sessions[name] = Session(self.sessions_dir / name, self.triage_config, self.prioritization_config)
            return self.sessions[name]

    def known_names(self) -> list[str]:
        return sorted(path.name for path in self.sessions_dir.iterdir() if path.is_dir()) if self.sessions_dir.exists() else []


def build_service(
    sessions_dir: Path,
    triage_config: Config,
    prioritization_config: PrioritizationConfig,
    port: int = 0,
) -> tuple[ThreadingHTTPServer, SessionStore, dict[str, Any]]:
    """Costruisce demone + store + stato condiviso (salute backend a piggyback, 004 D1)."""
    store = SessionStore(sessions_dir, triage_config, prioritization_config)
    shared: dict[str, Any] = {
        "backend_health": {"last_success": None, "last_failure": None, "last_success_wall": None}
    }

    def note_backend_outcome(success: bool) -> None:
        health = shared["backend_health"]
        if success:
            health["last_success"] = time.monotonic()
            health["last_success_wall"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        else:
            health["last_failure"] = time.monotonic()

    def backend_reachable() -> bool:
        """Il traffico reale dichiara la salute; la domanda di verifica esiste solo
        quando nella finestra non c'è stata nessuna notizia (004 FR-001/FR-002)."""
        health = shared["backend_health"]
        now = time.monotonic()
        ttl = triage_config.health_ttl_s
        success, failure = health["last_success"], health["last_failure"]
        if failure is None or (success is not None and success > failure):
            if success is not None and now - success < ttl:
                return True
        elif now - failure < ttl:
            return False
        probe_question = {"probe": {"type": "noul", "instructions": "readiness probe"}}
        try:
            ask(triage_config.base_url, "readiness", probe_question, BACKEND_PROBE_TIMEOUT_S, api_token=triage_config.api_token, model=triage_config.model)
        except SystemOneError:
            note_backend_outcome(False)
            return False
        note_backend_outcome(True)
        return True

    service_log_path = Path(sessions_dir) / "service.log"
    service_log_path.parent.mkdir(parents=True, exist_ok=True)
    service_log = service_log_path.open("a", encoding="utf-8")
    service_log_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # silenzia il log default su stderr
            pass

        def _reply(self, status: int, payload: Any) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            with service_log_lock:
                service_log.write(json.dumps({
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "method": self.command,
                    "path": self.path,
                    "status": status,
                }) + "\n")
                service_log.flush()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body_objects(self) -> list[Any]:
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode("utf-8")
            if not raw.strip():
                raise SessionError("empty body")
            stripped = raw.strip()
            if stripped.startswith("["):
                parsed = json.loads(stripped)
                if not isinstance(parsed, list):
                    raise SessionError("expected a list")
                return parsed
            objects = [json.loads(line) for line in stripped.splitlines() if line.strip()]
            return objects if len(objects) != 1 else objects[0]

        def do_GET(self) -> None:
            parts = [part for part in self.path.split("?")[0].split("/") if part]
            try:
                if not parts:
                    page = UI_PAGE_PATH.read_text(encoding="utf-8") if UI_PAGE_PATH.exists() else "console page missing"
                    body = page.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if parts == ["api", "status"]:
                    self._reply(200, {
                        "service": "jevsecd",
                        "version": SERVICE_VERSION,
                        "sessions": store.known_names(),
                        "backend": {
                            "mode": "loopback" if is_loopback_url(triage_config.base_url) else "remote-secure",
                            "reachable": backend_reachable(),
                            "last_success_ts": shared["backend_health"]["last_success_wall"],
                        },
                    })
                    return
                if len(parts) == 4 and parts[:2] == ["api", "sessions"] and parts[3] in ("queue", "records"):
                    session = self._session(parts[2])
                    self._reply(200, session.queues() if parts[3] == "queue" else session.records())
                    return
                if len(parts) == 4 and parts[:2] == ["api", "sessions"] and parts[3] == "next":
                    session = self._session(parts[2])
                    query = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
                    objective = query.get("objective", [None])[0]
                    if not objective:
                        raise SessionError("objective expected in query (e.g. ?objective=user_flag)")
                    since_seq = self._query_int(query, "since_seq", 0) if "since_seq" in query else None
                    top_k = self._query_int(query, "top_k", 1) if "top_k" in query else 5
                    self._reply(200, session.next_advice(str(objective), since_seq, top_k))
                    return
            except SessionError as error:
                self._reply(404 if "not found" in str(error) else 400, {"error": str(error)})
                return
            self._reply(404, {"error": f"unknown path: {self.path}"})

        @staticmethod
        def _query_int(query: dict[str, list[str]], name: str, minimum: int) -> int:
            raw = query.get(name, [""])[0]
            try:
                value = int(raw)
            except ValueError:
                raise SessionError(f"{name} expected as an integer (got {raw!r})")
            if value < minimum:
                raise SessionError(f"{name} expected >= {minimum} (got {value})")
            return value

        def do_POST(self) -> None:
            parts = [part for part in self.path.split("?")[0].split("/") if part]
            try:
                if parts == ["api", "sessions"]:
                    payload = self._body_objects()
                    if not isinstance(payload, dict) or not payload.get("name"):
                        raise SessionError("expected {\"name\": ...}")
                    store.open(str(payload["name"]))
                    self._reply(200, {"name": payload["name"], "opened": True})
                    return
                if len(parts) == 4 and parts[:2] == ["api", "sessions"]:
                    session = self._session(parts[2])
                    if parts[3] == "findings":
                        items = self._body_objects()
                        findings = items if isinstance(items, list) else [items]
                        for item in findings:
                            if not isinstance(item, dict):
                                raise SessionError("finding must be a JSON object")
                        records = [session.add_finding(item) for item in findings]
                        for record in records:
                            note_backend_outcome(record.get("error") is None)
                        self._reply(200, records if len(records) != 1 else records[0])
                        return
                    if parts[3] == "observations":
                        payload = self._body_objects()
                        if not isinstance(payload, dict) or "objective" not in payload:
                            raise SessionError("expected {\"objective\": ..., \"observation\": ...}")
                        objective = str(payload["objective"])
                        observations = payload.get("observations") or [payload.get("observation")]
                        if not observations or not all(isinstance(o, dict) for o in observations):
                            raise SessionError("observation(s) must be JSON objects")
                        records = [session.add_observation(objective, observation) for observation in observations]
                        for record in records:
                            if "duplicate_of" not in record:
                                note_backend_outcome(record.get("error") is None)
                        self._reply(200, records if len(records) != 1 else records[0])
                        return
                    if parts[3] == "feedback":
                        payload = self._body_objects()
                        if not isinstance(payload, dict):
                            raise SessionError("feedback must be a JSON object")
                        self._reply(200, session.add_feedback(payload))
                        return
            except SessionError as error:
                self._reply(404 if "not found" in str(error) else 400, {"error": str(error)})
                return
            except json.JSONDecodeError as error:
                self._reply(400, {"error": f"malformed JSON: {error}"})
                return
            self._reply(404, {"error": f"unknown path: {self.path}"})

        def _session(self, name: str) -> Session:
            try:
                return store.open(name)
            except SessionError as error:
                raise error

    server = ThreadingHTTPServer((LOCALHOST, port), Handler)
    return server, store, shared


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m jevsec.service", description="Local jevsecd daemon.")
    parser.add_argument("--port", type=int, default=7860)
    parser.add_argument("--sessions-dir", type=Path, default=Path("results/sessions"))
    parser.add_argument("--triage-config", type=Path, default=Path("config/live-triage.toml"))
    parser.add_argument("--prioritization-config", type=Path, default=Path("config/prioritization.toml"))
    parser.add_argument("--base-url", default=None, help="override the backend for both configs")
    args = parser.parse_args()

    triage_config = load_config(args.triage_config)
    prioritization_config = load_rubric(args.prioritization_config)
    if args.base_url:
        violation = channel_violation(args.base_url, triage_config.api_token or prioritization_config.api_token)
        if violation is not None:
            print(f"config: {violation}", file=sys.stderr)
            return 2
        triage_config = dataclasses.replace(triage_config, base_url=args.base_url)
        prioritization_config = dataclasses.replace(prioritization_config, base_url=args.base_url)

    server, _, _ = build_service(args.sessions_dir, triage_config, prioritization_config, port=args.port)
    print(f"jevsecd {SERVICE_VERSION} on http://{LOCALHOST}:{server.server_address[1]} (sessions: {args.sessions_dir})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("jevsecd stopped", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
