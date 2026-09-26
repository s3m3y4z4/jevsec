"""Client MCP di prova: parla con l'adattatore via stdio e verifica il ciclo completo.

Usage (quickstart sc. 6):
  PYTHONPATH=src python3 tests/integration/mcp_probe.py --url http://127.0.0.1:7860
Atende: 6 tool elencati; jevsec_status, jevsec_queue, un batch via jevsec_add_observation
e il consiglio jevsec_next (top + delta) eseguiti end-to-end.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ADAPTER_PATH = Path(__file__).parent.parent.parent / "src" / "jevsec" / "mcp_adapter.py"


def send(process: subprocess.Popen, message: dict) -> None:
    process.stdin.write(json.dumps(message) + "\n")
    process.stdin.flush()


def receive(process: subprocess.Popen) -> dict | None:
    line = process.stdout.readline()
    return json.loads(line) if line.strip() else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:7860")
    args = parser.parse_args()

    process = subprocess.Popen(
        [sys.executable, str(ADAPTER_PATH), "--url", args.url],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1,
    )
    try:
        send(process, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        init = receive(process)
        tools_info = init["result"]["serverInfo"]
        send(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        send(process, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        listed = receive(process)
        tool_names = sorted(tool["name"] for tool in listed["result"]["tools"])
        print(f"adattatore: {tools_info['name']} {tools_info['version']} ({args.url})")
        print(f"tool ({len(tool_names)}): {', '.join(tool_names)}")

        send(process, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "jevsec_status", "arguments": {}}})
        status = json.loads(receive(process)["result"]["content"][0]["text"])
        print(f"jevsec_status: servizio {status['service']} v{status['version']}, "
              f"backend {'ok' if status['backend']['reachable'] else 'giù'}")

        if status["sessions"]:
            session = status["sessions"][0]
            send(process, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                           "params": {"name": "jevsec_queue",
                                      "arguments": {"session": session, "queue": "triage"}}})
            queue = json.loads(receive(process)["result"]["content"][0]["text"])
            print(f"jevsec_queue[{session}]: {len(queue['triage'])} record di triage")
        else:
            print("jevsec_queue: saltato (nessuna sessione)")
        send(process, {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                       "params": {"name": "jevsec_add_observation",
                                  "arguments": {"session": "probe", "objective": "user_flag",
                                                "observations": [
                                                    {"id": "b1",
                                                     "text": "A Group Policy file exposes a recoverable local-admin password."},
                                                    {"id": "b2",
                                                     "text": "The host runs an outdated remote-access service."}]}}})
        records = json.loads(receive(process)["result"]["content"][0]["text"])
        print(f"jevsec_add_observation[probe]: batch di {len(records)} osservazioni")
        send(process, {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                       "params": {"name": "jevsec_next",
                                  "arguments": {"session": "probe", "objective": "user_flag"}}})
        advice = json.loads(receive(process)["result"]["content"][0]["text"])
        best = advice["top"][0]
        print(f"jevsec_next[probe]: cursore {advice['cursor']}, top {len(advice['top'])}, "
              f"migliore {best['obs_ref']} impatto {best['impact']}")
        send(process, {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                       "params": {"name": "jevsec_next",
                                  "arguments": {"session": "probe", "objective": "user_flag",
                                                "since_seq": advice["cursor"] - 1}}})
        delta = json.loads(receive(process)["result"]["content"][0]["text"])
        print(f"jevsec_next[probe] delta dal cursore {advice['cursor'] - 1}: {len(delta['fresh'])} record nuovi")
        expected = ["jevsec_add_finding", "jevsec_add_observation", "jevsec_feedback",
                    "jevsec_queue", "jevsec_status", "jevsec_next"]
        missing = [name for name in expected if name not in tool_names]
        if missing:
            print(f"MANCANO: {missing}")
            return 1
        print("probe completo: tutto end-to-end")
        return 0
    finally:
        process.terminate()
        process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
