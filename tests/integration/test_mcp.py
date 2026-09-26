"""Test MCP end-to-end (SC-005): adattatore stdio -> demone -> mock."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import unittest
from http.server import HTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "harness"))

import mock_systemone  # noqa: E402

from tests.integration.test_service import start_daemon  # noqa: E402

ADAPTER = [sys.executable, str(REPO_ROOT / "src" / "jevsec" / "mcp_adapter.py")]


class TestMcpAdapter(unittest.TestCase):

    def setUp(self) -> None:
        mock_server = HTTPServer(("127.0.0.1", 0), mock_systemone.Handler)
        threading.Thread(target=mock_server.serve_forever, daemon=True).start()
        import tempfile
        sessions_dir = Path(tempfile.mkdtemp())
        self.server, self.base = start_daemon(sessions_dir, mock_server.server_address[1])
        self.addCleanup(self.server.shutdown)
        self.addCleanup(mock_server.shutdown)
        self.process = subprocess.Popen(
            ADAPTER + ["--url", self.base], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
        )
        self.addCleanup(self.process.terminate)
        self.next_id = 0

    def rpc(self, method: str, params: dict | None = None, notify: bool = False) -> dict:
        self.next_id += 1
        message = {"jsonrpc": "2.0", "method": method}
        if not notify:
            message["id"] = self.next_id
        if params is not None:
            message["params"] = params
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        if notify:
            return {}
        return json.loads(self.process.stdout.readline())

    def test_mcp_initialize_e_tools_list(self) -> None:
        init = self.rpc("initialize", {})
        self.assertEqual(init["result"]["serverInfo"]["name"], "jevsec")
        self.rpc("notifications/initialized", notify=True)
        listed = self.rpc("tools/list")
        names = {tool["name"] for tool in listed["result"]["tools"]}
        self.assertEqual(names, {"jevsec_status", "jevsec_add_finding", "jevsec_add_observation",
                                 "jevsec_queue", "jevsec_feedback", "jevsec_next"})

    def test_mcp_tools_call_end_to_end(self) -> None:
        self.rpc("initialize", {})
        self.rpc("notifications/initialized", notify=True)
        status = json.loads(self.rpc("tools/call", {"name": "jevsec_status", "arguments": {}})
                            ["result"]["content"][0]["text"])
        self.assertEqual(status["service"], "jevsecd")
        finding = {"template_id": "doc-t", "response_snippet": "vulnerable banner reflected"}
        record = json.loads(self.rpc("tools/call", {
            "name": "jevsec_add_finding",
            "arguments": {"session": "mcp", "finding": finding},
        })["result"]["content"][0]["text"])
        self.assertIn("verdict", record)
        queue = json.loads(self.rpc("tools/call", {
            "name": "jevsec_queue",
            "arguments": {"session": "mcp", "queue": "triage"},
        })["result"]["content"][0]["text"])
        self.assertEqual(len(queue["triage"]), 1)

    def test_mcp_jevsec_next_e_batch_end_to_end(self) -> None:
        self.rpc("initialize", {})
        self.rpc("notifications/initialized", notify=True)
        records = json.loads(self.rpc("tools/call", {
            "name": "jevsec_add_observation",
            "arguments": {"session": "nx", "objective": "user_flag", "observations": [
                {"id": "q1", "text": "A Group Policy file exposes a recoverable local-admin password."},
                {"id": "q2", "text": "The host runs an outdated remote-access service."}]},
        })["result"]["content"][0]["text"])
        self.assertEqual([record["obs_ref"] for record in records], ["q1", "q2"])
        advice = json.loads(self.rpc("tools/call", {
            "name": "jevsec_next", "arguments": {"session": "nx", "objective": "user_flag"},
        })["result"]["content"][0]["text"])
        self.assertEqual(advice["cursor"], 2)
        self.assertEqual(len(advice["top"]), 2)
        self.assertIn("observation", advice["top"][0])
        delta = json.loads(self.rpc("tools/call", {
            "name": "jevsec_next", "arguments": {"session": "nx", "objective": "user_flag", "since_seq": 1},
        })["result"]["content"][0]["text"])
        self.assertEqual([record["obs_ref"] for record in delta["fresh"]], ["q2"])

    def test_mcp_batch_e_singola_insieme_errore_pulito(self) -> None:
        self.rpc("initialize", {})
        self.rpc("notifications/initialized", notify=True)
        response = self.rpc("tools/call", {
            "name": "jevsec_add_observation",
            "arguments": {"session": "x", "objective": "user_flag",
                          "observation": {"text": "un fatto"},
                          "observations": [{"text": "un altro fatto"}]},
        })
        self.assertTrue(response["result"]["isError"])

    def test_mcp_errore_pulito_con_demone_giu(self) -> None:
        import tempfile
        import urllib.request
        dead = subprocess.Popen(
            ADAPTER + ["--url", "http://127.0.0.1:1"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
        )
        self.addCleanup(dead.terminate)
        dead.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
        dead.stdin.flush()
        json.loads(dead.stdout.readline())
        dead.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                     "params": {"name": "jevsec_status", "arguments": {}}}) + "\n")
        dead.stdin.flush()
        response = json.loads(dead.stdout.readline())
        self.assertTrue(response["result"]["isError"])


if __name__ == "__main__":
    unittest.main()
