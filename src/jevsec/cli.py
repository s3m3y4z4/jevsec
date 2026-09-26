"""CLI live-triage: stream di finding → coda di TriageRecord ordinata.

JSONL sempre su stdout (per pipe), coda leggibile su stderr senza --json,
exit 0 anche con errori per-finding, exit 2 solo per input/config fatali.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

from jevsec import __version__
from jevsec.config import Config, ConfigError, channel_violation, load_config
from jevsec.queue import bucket_of, sort_records
from jevsec.rubric import RubricError, load_rubric
from jevsec.prioritize import prioritize_observation, sort_impact_records
from jevsec.triage import triage_finding

EXIT_OK = 0
EXIT_FATAL = 2
DEFAULT_CONFIG_PATH = Path("config/live-triage.toml")
DEFAULT_PRIORITIZATION_CONFIG_PATH = Path("config/prioritization.toml")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m jevsec",
        description="Active decision-support tooling for authorized pentesting on local System One models.",
    )
    parser.add_argument("--version", action="version", version=f"jevsec {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    triage = commands.add_parser("triage", help="triage queue for a stream of findings")
    triage.add_argument("--input", default="-", help="JSONL file of findings, one object per line (default: stdin)")
    triage.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help=f"TOML config (default: {DEFAULT_CONFIG_PATH})")
    triage.add_argument("--base-url", default=None, help="override the backend for this run")
    triage.add_argument("--json", action="store_true", help="JSONL on stdout only, no readable queue on stderr")
    prioritize = commands.add_parser("prioritize", help="observation queue per objective (declared rubric)")
    prioritize.add_argument("--objective", required=True, help="rubric name, e.g. domain_admin")
    prioritize.add_argument("--input", default="-", help="JSONL observations, one object per line (default: stdin)")
    prioritize.add_argument("--config", type=Path, default=DEFAULT_PRIORITIZATION_CONFIG_PATH,
                            help=f"rubric TOML config (default: {DEFAULT_PRIORITIZATION_CONFIG_PATH})")
    prioritize.add_argument("--base-url", default=None, help="override the backend for this run")
    prioritize.add_argument("--json", action="store_true", help="JSONL on stdout only, no readable queue on stderr")
    session = commands.add_parser("session", help="live session commands (no AI agent needed)")
    session_commands = session.add_subparsers(dest="session_command", required=True)
    new = session_commands.add_parser("new", help="open a session")
    new.add_argument("--name", required=True, help="session name (a-z 0-9 _ -)")
    add_finding = session_commands.add_parser("add-finding", help="send scanner findings to the session (JSONL)")
    add_finding.add_argument("--session", default=None, help="target session (default: the only open one)")
    add_finding.add_argument("input_path", nargs="?", default=None, help="JSONL file of findings (default: stdin)")
    add_finding.add_argument("--file", default=None, help="same as the positional argument")
    add_observation = session_commands.add_parser("add-observation", help="send observations for an objective (JSONL)")
    add_observation.add_argument("--session", default=None, help="target session (default: the only open one)")
    add_observation.add_argument("--objective", required=True, help="objective with a rubric, e.g. user_flag")
    add_observation.add_argument("input_path", nargs="?", default=None, help="JSONL file of observations (default: stdin)")
    add_observation.add_argument("--file", default=None, help="same as the positional argument")
    add_observation.add_argument("--context", default=None, help="context attached to observations that lack one")
    queue = session_commands.add_parser("queue", help="read the session queues")
    queue.add_argument("--session", required=True, help="target session")
    nxt = session_commands.add_parser("next", help="current advice for an objective (top of the queue + delta)")
    nxt.add_argument("--session", required=True, help="target session")
    nxt.add_argument("--objective", required=True, help="objective with a rubric")
    nxt.add_argument("--since-seq", type=int, default=None, help="cursor of the previous read: only newer records")
    nxt.add_argument("--top-k", type=int, default=None, help="how many records at the top (service default: 5)")
    feedback = session_commands.add_parser("feedback", help="record your judgment on a record")
    feedback.add_argument("--session", required=True, help="target session")
    feedback.add_argument("--ref", required=True, help="obs_ref of the record")
    feedback.add_argument("--ranking-ok", required=True, choices=("true", "false"), help="was the ranking right?")
    feedback.add_argument("--impact", type=int, default=None, help="the impact you consider correct (0-4)")
    feedback.add_argument("--notes", default=None, help="free-text notes")
    for command in (new, add_finding, add_observation, queue, nxt, feedback):
        command.add_argument("--url", default=DEFAULT_SERVICE_URL, help=f"jevsecd base URL (default: {DEFAULT_SERVICE_URL})")
        command.add_argument("--json", action="store_true", help="raw JSON output")
    return parser


def read_findings(input_path: str) -> list[tuple[int, dict[str, Any]]]:
    """Legge lo stream: (numero di riga, finding). Exit-fatale su riga malformata."""
    if input_path == "-":
        lines = sys.stdin.read().splitlines()
        source = "stdin"
    else:
        try:
            lines = Path(input_path).read_text(encoding="utf-8").splitlines()
        except OSError as error:
            raise ValueError(f"unreadable input {input_path}: {error}") from error
        source = input_path
    findings: list[tuple[int, dict[str, Any]]] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{source}: line {number} is not JSON: {error.msg}") from error
        if not isinstance(finding, dict):
            raise ValueError(f"{source}: line {number}: expected one JSON object per line")
        findings.append((number, finding))
    return findings


def render_queue(records: list[dict[str, Any]]) -> str:
    header = f"{'gate':<6} {'verdict':<14} {'p':<5} {'pre':<4} {'sev':<9} finding"
    lines = [header, "-" * len(header)]
    for record in records:
        probability = record["verdict_probability"]
        lines.append(
            f"{record['gate']:<6} {str(record['verdict'] or '-'):<14} "
            f"{(f'{probability:.2f}' if probability is not None else '-'):<5} "
            f"{('yes' if record['no_auth'] else 'no') if record['no_auth'] is not None else '-':<4} "
            f"{str(record['severity'] or '-'):<9} {record['finding_ref']}"
            + (f"  ERROR: {record['error']}" if record["error"] else "")
        )
    return "\n".join(lines)


def _apply_base_url_override(config: Config, base_url: str, error_label: str) -> Config:
    """Override del backend: il canale si rivalida qui, l'override non bypassa FR-008."""
    overridden = dataclasses.replace(config, base_url=base_url)
    violation = channel_violation(overridden.base_url, overridden.api_token)
    if violation is not None:
        raise ConfigError(f"{error_label}: {violation}")
    return overridden


def run_triage(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
        if args.base_url:
            config = _apply_base_url_override(config, args.base_url, "config")
    except ConfigError as error:
        print(f"config: {error}", file=sys.stderr)
        return EXIT_FATAL

    try:
        findings = read_findings(args.input)
    except ValueError as error:
        print(f"input: {error}", file=sys.stderr)
        return EXIT_FATAL

    records = [
        triage_finding(finding, f"r{number}:{finding.get('template_id', 'unknown')}", config)
        for number, finding in findings
    ]
    ordered = sort_records(records, config.queue_order)
    bucket_rank = {name: rank for rank, name in enumerate(config.queue_order)}
    for record in ordered:
        record["priority"] = bucket_rank[bucket_of(record)]

    for record in ordered:
        print(json.dumps(record, ensure_ascii=False))

    n_auto = sum(1 for record in ordered if record["gate"] == "auto")
    n_error = sum(1 for record in ordered if record["error"])
    print(
        f"triage: {len(ordered)} findings, {n_auto} auto, {len(ordered) - n_auto} review, {n_error} with errors",
        file=sys.stderr,
    )
    if not args.json:
        print(file=sys.stderr)
        print(render_queue(ordered), file=sys.stderr)
    return EXIT_OK


def render_impact_queue(records: list[dict[str, Any]]) -> str:
    header = f"{'imp':<4} {'rule':<24} {'qw':<3} observation"
    lines = [header, "-" * len(header)]
    for record in records:
        quick_win = ("yes" if record["quick_win"] else "no") if record["quick_win"] is not None else "-"
        lines.append(
            f"{str(record['impact'] if record['impact'] is not None else '-'):<4} "
            f"{str(record['winning_rule'] or '-'):<24} {quick_win:<3} {record['obs_ref']}"
            + (f"  ERROR: {record['error']}" if record["error"] else "")
        )
    return "\n".join(lines)


def run_prioritize(args: argparse.Namespace) -> int:
    try:
        config = load_rubric(args.config)
        if args.base_url:
            config = _apply_base_url_override(config, args.base_url, "config")  # type: ignore[arg-type]
    except (ConfigError, RubricError) as error:
        print(f"config: {error}", file=sys.stderr)
        return EXIT_FATAL

    if args.objective not in config.objectives:
        known = ", ".join(sorted(config.objectives))
        print(f"objective {args.objective!r} has no rubric; known objectives: {known}", file=sys.stderr)
        return EXIT_FATAL
    rubric = config.objectives[args.objective]

    try:
        observations = read_findings(args.input)
    except ValueError as error:
        print(f"input: {error}", file=sys.stderr)
        return EXIT_FATAL

    records = [
        prioritize_observation(observation, observation.get("id") or f"r{number}", config, rubric)
        for number, observation in observations
    ]
    ordered = sort_impact_records(records)

    for record in ordered:
        print(json.dumps(record, ensure_ascii=False))

    n_error = sum(1 for record in ordered if record["error"])
    n_with_impact = sum(1 for record in ordered if record["impact"] is not None)
    print(
        f"prioritize [{args.objective}]: {len(ordered)} observations, {n_with_impact} with impact, {n_error} with errors",
        file=sys.stderr,
    )
    if not args.json:
        print(file=sys.stderr)
        print(render_impact_queue(ordered), file=sys.stderr)
    return EXIT_OK


DEFAULT_SERVICE_URL = "http://127.0.0.1:7860"
SERVICE_TIMEOUT_S = 60.0


def _service_call(service_url: str, method: str, path: str, body: Any = None) -> Any:
    """Client HTTP minimale del demone (contratto cli-session.md): nessun giudizio qui."""
    import urllib.error
    import urllib.request

    request = urllib.request.Request(
        service_url.rstrip("/") + path,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=SERVICE_TIMEOUT_S) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[:300]
        raise ValueError(f"HTTP {error.code}: {detail}") from error
    except urllib.error.URLError as error:
        raise ValueError(
            f"service not reachable at {service_url} ({error.reason}); "
            "start it with: python3 -m jevsec.service --port 7860"
        ) from error


def _input_path(args: argparse.Namespace) -> str:
    """Contratto cli-session.md: `--file PATH` oppure un `-`/percorso posizionale; stdin di default."""
    positional = args.input_path
    explicit = args.file
    if positional and explicit:
        raise ValueError("pass either the positional file or --file, not both")
    return positional or explicit or "-"


def _resolve_session(session_arg: str | None, service_url: str) -> str:
    if session_arg:
        return session_arg
    sessions = _service_call(service_url, "GET", "/api/status").get("sessions", [])
    if len(sessions) == 1:
        return sessions[0]
    known = ", ".join(sessions) if sessions else "none"
    raise ValueError(f"--session is required (known sessions: {known})")


def _print_session_record(record: dict[str, Any]) -> None:
    if "duplicate_of" in record:
        print(f"{record['record'].get('obs_ref')}: duplicate of {record['duplicate_of']}")
        return
    error = f"  ERROR: {record['error']}" if record.get("error") else ""
    print(f"{record.get('obs_ref')}: impact {record.get('impact')} rule {record.get('winning_rule')}{error}")


def _print_next(payload: dict[str, Any]) -> None:
    print(f"objective {payload['objective']}, cursor {payload['cursor']}")
    for record in payload["top"]:
        observation = record.get("observation") or {}
        preview = (observation.get("text") or "")[:120]
        error = f"  ERROR: {record['error']}" if record.get("error") else ""
        print(f"  [{record.get('impact')}] {record.get('winning_rule')} {record.get('obs_ref')}{error}")
        if preview:
            print(f"      {preview}")


def run_session_new(args: argparse.Namespace) -> int:
    try:
        result = _service_call(args.url, "POST", "/api/sessions", {"name": args.name})
    except ValueError as error:
        print(f"session: {error}", file=sys.stderr)
        return EXIT_FATAL
    print(json.dumps(result, ensure_ascii=False) if args.json else f"session {result['name']!r} opened")
    return EXIT_OK


def run_session_add_finding(args: argparse.Namespace) -> int:
    try:
        findings = read_findings(_input_path(args))
    except ValueError as error:
        print(f"input: {error}", file=sys.stderr)
        return EXIT_FATAL
    try:
        session = _resolve_session(args.session, args.url)
        for _, finding in findings:
            record = _service_call(args.url, "POST", f"/api/sessions/{session}/findings", finding)
            if args.json:
                print(json.dumps(record, ensure_ascii=False))
            else:
                probability = record.get("verdict_probability")
                probability_text = f"{probability:.2f}" if probability is not None else "-"
                error = f"  ERROR: {record['error']}" if record.get("error") else ""
                print(
                    f"{record['finding_ref']}: {record.get('verdict') or '-'} "
                    f"p={probability_text} gate={record['gate']}{error}"
                )
    except ValueError as error:
        print(f"session: {error}", file=sys.stderr)
        return EXIT_FATAL
    return EXIT_OK


def run_session_add_observation(args: argparse.Namespace) -> int:
    try:
        observations = read_findings(_input_path(args))
    except ValueError as error:
        print(f"input: {error}", file=sys.stderr)
        return EXIT_FATAL
    payload_observations = []
    for _, observation in observations:
        item = dict(observation)
        if args.context and "context" not in item:
            item["context"] = args.context
        payload_observations.append(item)
    body: dict[str, Any] = {"objective": args.objective, "observations": payload_observations}
    try:
        session = _resolve_session(args.session, args.url)
        results = _service_call(args.url, "POST", f"/api/sessions/{session}/observations", body)
    except ValueError as error:
        print(f"session: {error}", file=sys.stderr)
        return EXIT_FATAL
    if not isinstance(results, list):
        results = [results]
    for record in results:
        if args.json:
            print(json.dumps(record, ensure_ascii=False))
        else:
            _print_session_record(record)
    return EXIT_OK


def run_session_queue(args: argparse.Namespace) -> int:
    try:
        session = _resolve_session(args.session, args.url)
        queues = _service_call(args.url, "GET", f"/api/sessions/{session}/queue")
    except ValueError as error:
        print(f"session: {error}", file=sys.stderr)
        return EXIT_FATAL
    if args.json:
        print(json.dumps(queues, ensure_ascii=False))
        return EXIT_OK
    triage = queues.get("triage", [])
    print(f"triage: {len(triage)} records")
    if triage:
        print(render_queue(triage))
    for objective, records in queues.get("prioritize", {}).items():
        print(f"\nprioritize [{objective}]: {len(records)} records")
        if records:
            print(render_impact_queue(records))
    return EXIT_OK


def run_session_next(args: argparse.Namespace) -> int:
    query = f"objective={args.objective}"
    if args.since_seq is not None:
        query += f"&since_seq={args.since_seq}"
    if args.top_k is not None:
        query += f"&top_k={args.top_k}"
    try:
        session = _resolve_session(args.session, args.url)
        payload = _service_call(args.url, "GET", f"/api/sessions/{session}/next?{query}")
    except ValueError as error:
        print(f"session: {error}", file=sys.stderr)
        return EXIT_FATAL
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        _print_next(payload)
    return EXIT_OK


def run_session_feedback(args: argparse.Namespace) -> int:
    body: dict[str, Any] = {"id": args.ref, "ranking_ok": args.ranking_ok == "true"}
    if args.impact is not None:
        body["impact_giusto"] = args.impact
    if args.notes:
        body["note"] = args.notes
    try:
        session = _resolve_session(args.session, args.url)
        result = _service_call(args.url, "POST", f"/api/sessions/{session}/feedback", body)
    except ValueError as error:
        print(f"session: {error}", file=sys.stderr)
        return EXIT_FATAL
    print(json.dumps(result, ensure_ascii=False) if args.json else f"feedback recorded for {result['id']}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "triage":
        return run_triage(args)
    if args.command == "prioritize":
        return run_prioritize(args)
    if args.command == "session":
        handlers = {
            "new": run_session_new,
            "add-finding": run_session_add_finding,
            "add-observation": run_session_add_observation,
            "queue": run_session_queue,
            "next": run_session_next,
            "feedback": run_session_feedback,
        }
        return handlers[args.session_command](args)
    return EXIT_FATAL


if __name__ == "__main__":
    raise SystemExit(main())
