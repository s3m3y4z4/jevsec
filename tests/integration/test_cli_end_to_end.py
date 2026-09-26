"""Test d'integrazione CLI end-to-end contro il mock deterministico.

Quickstart scenari 1 e 2: una riga di output per riga di input, gate coerenti
con il mock (probabilità fissa 0,62 < 0,80 → review), errore backend senza perdite.
"""

from __future__ import annotations

import contextlib
import io
import json
import socket
import threading
import unittest
from unittest import mock
from http.server import HTTPServer
from pathlib import Path

import sys

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "harness"))

import mock_systemone  # noqa: E402

from jevsec.cli import main  # noqa: E402

SAMPLE = REPO_ROOT / "data" / "samples" / "live_triage_findings.jsonl"
CONFIG = REPO_ROOT / "config" / "live-triage.toml"
PRIORITIZATION_CONFIG = REPO_ROOT / "config" / "prioritization.toml"

OBSERVATIONS = [
    {"id": "obs-1", "text": "A Group Policy file contains a recoverable password for a local administrator account."},
    {"id": "obs-2", "text": "A network printer responds on port 9100."},
]


def write_observations() -> str:
    import json as json_module
    import tempfile
    handle = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8")
    for observation in OBSERVATIONS:
        handle.write(json_module.dumps(observation) + "\n")
    handle.close()
    return handle.name


def start_mock_server() -> tuple[HTTPServer, int]:
    server = HTTPServer(("127.0.0.1", 0), mock_systemone.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def find_free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        exit_code = main(argv)
    return exit_code, stdout.getvalue(), stderr.getvalue()


class TestCliEndToEnd(unittest.TestCase):

    def setUp(self) -> None:
        self.server, self.port = start_mock_server()
        self.addCleanup(self.server.shutdown)

    def test_cli_stream_mock_un_record_per_riga_gate_review(self) -> None:
        n_input = sum(1 for line in SAMPLE.open(encoding="utf-8") if line.strip())
        exit_code, stdout, stderr = run_cli([
            "triage", "--input", str(SAMPLE), "--config", str(CONFIG),
            "--base-url", f"http://127.0.0.1:{self.port}", "--json",
        ])
        self.assertEqual(exit_code, 0, stderr)
        records = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        self.assertEqual(len(records), n_input)
        for record in records:
            self.assertEqual(record["gate"], "review")
            if "no-snippet" in record["finding_ref"]:
                self.assertIsNone(record["verdict"])  # senza evidenza: review con motivo, non un azzardo
                self.assertIsNotNone(record["error"])
            else:
                self.assertEqual(record["verdict"], "true_positive")  # il mock sceglie la prima opzione
                self.assertIsNone(record["error"])

    def test_cli_senza_json_coda_leggibile_su_stderr(self) -> None:
        exit_code, stdout, stderr = run_cli([
            "triage", "--input", str(SAMPLE), "--config", str(CONFIG),
            "--base-url", f"http://127.0.0.1:{self.port}",
        ])
        self.assertEqual(exit_code, 0, stderr)
        self.assertTrue(stdout.strip())          # JSONL sempre su stdout
        self.assertIn("review", stderr)          # coda leggibile su stderr

    def test_cli_backend_irraggiungibile_tutti_in_review_con_error(self) -> None:
        dead_port = find_free_port()
        exit_code, stdout, stderr = run_cli([
            "triage", "--input", str(SAMPLE), "--config", str(CONFIG),
            "--base-url", f"http://127.0.0.1:{dead_port}", "--json",
        ])
        self.assertEqual(exit_code, 0, stderr)
        records = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        self.assertEqual(len(records), 10)
        for record in records:
            self.assertEqual(record["gate"], "review")
            self.assertIsNotNone(record["error"])

    def test_cli_riga_malformata_exit_2_con_diagnosi(self) -> None:
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as handle:
            handle.write('{"template_id": "ok"}\nnot json\n')
            path = handle.name
        exit_code, stdout, stderr = run_cli([
            "triage", "--input", path, "--config", str(CONFIG),
            "--base-url", f"http://127.0.0.1:{self.port}", "--json",
        ])
        self.assertEqual(exit_code, 2)
        self.assertIn("line 2", stderr)
        self.assertEqual(stdout, "")


class TestPrioritizeCli(unittest.TestCase):

    def setUp(self) -> None:
        self.server, self.port = start_mock_server()
        self.addCleanup(self.server.shutdown)
        self.observations_path = write_observations()

    def test_prioritize_mock_un_record_per_riga_regola_massima(self) -> None:
        exit_code, stdout, stderr = run_cli([
            "prioritize", "--objective", "domain_admin", "--input", self.observations_path,
            "--config", str(PRIORITIZATION_CONFIG), "--base-url", f"http://127.0.0.1:{self.port}", "--json",
        ])
        self.assertEqual(exit_code, 0, stderr)
        records = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        self.assertEqual(len(records), len(OBSERVATIONS))
        for record in records:  # mock: noul 0.5 >= soglia 0.5 -> tutte le regole attive
            self.assertEqual(record["impact"], 4)
            self.assertEqual(record["winning_rule"], "privileged_credentials")
            self.assertTrue(record["quick_win"])
            self.assertIsNone(record["error"])
        self.assertGreaterEqual(records[0]["impact"], records[-1]["impact"])

    def test_prioritize_obiettivo_sconosciuto_exit_2(self) -> None:
        exit_code, stdout, _ = run_cli([
            "prioritize", "--objective", "king_of_the_hill", "--input", self.observations_path,
            "--config", str(PRIORITIZATION_CONFIG),
        ])
        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout, "")

    def test_prioritize_backend_assente_tutti_in_errore_impatto_nullo(self) -> None:
        dead_port = find_free_port()
        exit_code, stdout, stderr = run_cli([
            "prioritize", "--objective", "user_flag", "--input", self.observations_path,
            "--config", str(PRIORITIZATION_CONFIG), "--base-url", f"http://127.0.0.1:{dead_port}", "--json",
        ])
        self.assertEqual(exit_code, 0, stderr)
        records = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        self.assertEqual(len(records), len(OBSERVATIONS))
        for record in records:
            self.assertIsNone(record["impact"])
            self.assertIsNotNone(record["error"])

    def test_prioritize_riga_malformata_exit_2(self) -> None:
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as handle:
            handle.write('{"id": "a", "text": "ok"}\nnot json\n')
            path = handle.name
        exit_code, _, stderr = run_cli([
            "prioritize", "--objective", "domain_admin", "--input", path,
            "--config", str(PRIORITIZATION_CONFIG), "--base-url", f"http://127.0.0.1:{self.port}",
        ])
        self.assertEqual(exit_code, 2)
        self.assertIn("line 2", stderr)


class TestSessionCliEndToEnd(unittest.TestCase):
    """Ciclo senza agente AI end-to-end (spec 005 US4): CLI session ↔ demone ↔ mock, parità col percorso MCP."""

    def setUp(self) -> None:
        import dataclasses
        import tempfile

        import mock_systemone  # noqa: F401
        from jevsec.config import load_config
        from jevsec.rubric import load_rubric
        from jevsec.service import build_service

        self.mock_server, self.port = start_mock_server()
        base_url = f"http://127.0.0.1:{self.port}"
        triage_config = dataclasses.replace(load_config(CONFIG), base_url=base_url)
        prioritization_config = dataclasses.replace(load_rubric(PRIORITIZATION_CONFIG), base_url=base_url)
        self.service, _, _ = build_service(
            Path(tempfile.mkdtemp()), triage_config, prioritization_config, port=0
        )
        threading.Thread(target=self.service.serve_forever, daemon=True).start()
        self.service_url = f"http://127.0.0.1:{self.service.server_address[1]}"

    def tearDown(self) -> None:
        self.service.shutdown()
        self.mock_server.shutdown()

    def _stdin(self, payload_lines: list[dict]) -> io.StringIO:
        return io.StringIO("".join(json.dumps(line) + "\n" for line in payload_lines))

    def test_ciclo_completo_senza_agente_e_parita_mcp(self) -> None:
        from jevsec import mcp_adapter

        finding = {"template_id": "doc-example-banner", "matched_at": "https://192.0.2.10/", "response_snippet": "root banner"}
        observation = {"id": "o1", "text": "Crontab runs /opt/monitor.sh as root; the file is writable by www-data."}

        self.assertEqual(run_cli(["session", "new", "--name", "noagent", "--url", self.service_url])[0], 0)

        with mock.patch("sys.stdin", self._stdin([finding])):
            code, stdout, _ = run_cli(["session", "add-finding", "--session", "noagent", "--url", self.service_url])
        self.assertEqual(code, 0)
        self.assertIn("true_positive", stdout)

        with mock.patch("sys.stdin", self._stdin([observation])):
            code, stdout, _ = run_cli([
                "session", "add-observation", "--session", "noagent", "--objective", "user_flag", "--url", self.service_url,
            ])
        self.assertEqual(code, 0)
        self.assertIn("impact", stdout)

        code, stdout, _ = run_cli(["session", "queue", "--session", "noagent", "--url", self.service_url, "--json"])
        self.assertEqual(code, 0)
        cli_queue = json.loads(stdout)

        mcp_queue = mcp_adapter.call_tool(self.service_url, "jevsec_queue", {"session": "noagent", "queue": "triage"})
        self.assertEqual(cli_queue["triage"], mcp_queue["triage"])

        code, stdout, _ = run_cli([
            "session", "next", "--session", "noagent", "--objective", "user_flag", "--url", self.service_url, "--json",
        ])
        self.assertEqual(code, 0)
        cli_next = json.loads(stdout)
        mcp_next = mcp_adapter.call_tool(
            self.service_url, "jevsec_next", {"session": "noagent", "objective": "user_flag"}
        )
        self.assertEqual(cli_next, mcp_next)
        self.assertEqual(cli_next["cursor"], 1)

        code, stdout, _ = run_cli([
            "session", "feedback", "--session", "noagent", "--ref", "o1", "--ranking-ok", "false",
            "--impact", "2", "--url", self.service_url,
        ])
        self.assertEqual(code, 0)
        self.assertIn("feedback recorded", stdout)

    def test_sessione_unica_usata_senza_flag_session(self) -> None:
        self.assertEqual(run_cli(["session", "new", "--name", "only", "--url", self.service_url])[0], 0)
        with mock.patch("sys.stdin", self._stdin([{"text": "A printer responds on port 9100."}])):
            code, stdout, stderr = run_cli([
                "session", "add-observation", "--objective", "user_flag", "--url", self.service_url,
            ])
        self.assertEqual(code, 0)
        self.assertIn("impact", stdout)


if __name__ == "__main__":
    unittest.main()
