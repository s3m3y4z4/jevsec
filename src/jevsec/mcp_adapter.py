"""Adattatore MCP su stdio: espone jevsecd come tool tipizzati per gli agenti.

JSON-RPC 2.0 newline-delimited: le risposte su stdout, i log su stderr (mai
mescolati). Client HTTP sottile del demone: nessuna logica di giudizio qui.
Registrazione: claude mcp add jevsec -- <python> -m jevsec.mcp_adapter --url http://127.0.0.1:7860
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote

PROTOCOL_VERSION = "2025-06-18"
ADAPTER_VERSION = "1.0.0"

TOOLS: list[dict[str, Any]] = [
    {
        "name": "jevsec_status",
        "description": "jevsecd service status: version, known sessions, backend reachability (verified with a real question).",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "jevsec_add_finding",
        "description": "Sends a scanner finding to the session and returns the TriageRecord (verdict, probability, gate, severity from the source).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session": {"type": "string", "description": "session name"},
                "finding": {"type": "object", "description": "nuclei-style finding: template_id, matched_at, response_snippet, info.severity, ..."},
            },
            "required": ["session", "finding"],
        },
    },
    {
        "name": "jevsec_add_observation",
        "description": "Sends an engagement observation with its objective and returns the ImpactRecord (impact 0-4, winning rule, atomic judgments). Accepts a single observation or an observations list; the same fact already evaluated returns {duplicate_of, record} with no new evaluations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session": {"type": "string"},
                "objective": {"type": "string", "description": "domain_admin | user_flag | rce_app (or any other name with a rubric)"},
                "observation": {"type": "object", "description": "observation: {text, context?, id?}"},
                "observations": {"type": "array", "items": {"type": "object"},
                                 "description": "batch: several observations of the same objective, as an alternative to observation"},
            },
            "required": ["session", "objective"],
        },
    },
    {
        "name": "jevsec_next",
        "description": "The current advice for an objective: top of the queue (full records, text and active rules) and, with since_seq, only the records born since the last read. Local read: no model call.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session": {"type": "string"},
                "objective": {"type": "string"},
                "since_seq": {"type": "integer", "minimum": 0,
                              "description": "cursor from the previous read: returns only newer records"},
                "top_k": {"type": "integer", "minimum": 1, "description": "how many records at the top (default 5)"},
            },
            "required": ["session", "objective"],
        },
    },
    {
        "name": "jevsec_queue",
        "description": "Reads the session queues: triage (buckets and gates) and prioritize per objective, ordered.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session": {"type": "string"},
                "queue": {"type": "string", "enum": ["triage", "prioritize"], "description": "which queue"},
                "objective": {"type": "string", "description": "prioritize only: objective"},
            },
            "required": ["session", "queue"],
        },
    },
    {
        "name": "jevsec_feedback",
        "description": "Records the operator's judgment on a record (ranking_ok, impact_giusto, giudizi_sbagliati, note): the rubric improvement loop.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session": {"type": "string"},
                "id": {"type": "string", "description": "obs_ref of the record"},
                "ranking_ok": {"type": "boolean"},
                "impact_giusto": {"type": "integer", "minimum": 0, "maximum": 4},
                "giudizi_sbagliati": {"type": "array", "items": {"type": "string"}},
                "note": {"type": "string"},
            },
            "required": ["session", "id", "ranking_ok"],
        },
    },
]


def http_call(base_url: str, method: str, path: str, body: Any = None) -> Any:
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"HTTP {error.code}: {detail}") from error


def call_tool(base_url: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "jevsec_status":
        return http_call(base_url, "GET", "/api/status")
    if name == "jevsec_add_finding":
        return http_call(base_url, "POST", f"/api/sessions/{arguments['session']}/findings", arguments["finding"])
    if name == "jevsec_add_observation":
        has_single = "observation" in arguments
        has_batch = "observations" in arguments
        if has_single == has_batch:
            raise RuntimeError("exactly one of observation (single) or observations (list) is required")
        body: dict[str, Any] = {"objective": arguments["objective"]}
        if has_single:
            body["observation"] = arguments["observation"]
        else:
            batch = arguments["observations"]
            if not isinstance(batch, list) or not batch:
                raise RuntimeError("observations expected as a non-empty list")
            body["observations"] = batch
        return http_call(base_url, "POST", f"/api/sessions/{arguments['session']}/observations", body)
    if name == "jevsec_next":
        query = [f"objective={quote(str(arguments['objective']))}"]
        if "since_seq" in arguments:
            query.append(f"since_seq={int(arguments['since_seq'])}")
        if "top_k" in arguments:
            query.append(f"top_k={int(arguments['top_k'])}")
        return http_call(base_url, "GET", f"/api/sessions/{arguments['session']}/next?" + "&".join(query))
    if name == "jevsec_queue":
        queues = http_call(base_url, "GET", f"/api/sessions/{arguments['session']}/queue")
        if arguments["queue"] == "triage":
            return {"triage": queues["triage"]}
        if "objective" in arguments:
            return {"prioritize": queues["prioritize"].get(arguments["objective"], [])}
        return {"prioritize": queues["prioritize"]}
    if name == "jevsec_feedback":
        return http_call(base_url, "POST", f"/api/sessions/{arguments['session']}/feedback", arguments)
    raise RuntimeError(f"unknown tool: {name}")


def handle(message: dict[str, Any], base_url: str, out) -> None:
    method = message.get("method", "")
    message_id = message.get("id")
    is_notification = message_id is None

    if method == "initialize":
        reply = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                 "serverInfo": {"name": "jevsec", "version": ADAPTER_VERSION}}
    elif method == "notifications/initialized":
        return
    elif method == "ping":
        reply = {}
    elif method == "tools/list":
        reply = {"tools": TOOLS}
    elif method == "tools/call":
        try:
            result = call_tool(base_url, message["params"]["name"], message["params"].get("arguments", {}))
            reply = {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}
        except Exception as error:  # noqa: BLE001 - il canale MCP vuole errori come contenuto, non crash
            print(f"tools/call {message['params'].get('name')}: {error}", file=sys.stderr)
            reply = {"content": [{"type": "text", "text": f"errore: {error}"}], "isError": True}
    elif is_notification:
        return
    else:
        reply = None

    if reply is not None:
        response = {"jsonrpc": "2.0", "id": message_id, "result": reply}
    else:
        response = {"jsonrpc": "2.0", "id": message_id,
                    "error": {"code": -32601, "message": f"unknown method: {method}"}}
    out.write(json.dumps(response, ensure_ascii=False) + "\n")
    out.flush()


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m jevsec.mcp_adapter", description="Adattatore MCP per jevsecd.")
    parser.add_argument("--url", default="http://127.0.0.1:7860")
    args = parser.parse_args()
    print(f"mcp_adapter jevsec {ADAPTER_VERSION} -> {args.url}", file=sys.stderr)
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            print(f"non-JSON request: {error}", file=sys.stderr)
            continue
        handle(message, args.url, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
