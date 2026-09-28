"""Test di integrazione della drop-zone (spec 007): consegna, valutazione, registro, crash."""

from __future__ import annotations

import dataclasses
import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import HTTPServer
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "harness"))

import mock_systemone  # noqa: E402

from jevsec.config import load_config  # noqa: E402
from jevsec.rubric import load_rubric  # noqa: E402
from jevsec.service import build_service  # noqa: E402

TRIAGE_CONFIG_PATH = REPO_ROOT / "config" / "live-triage.toml"
PRIORITIZATION_CONFIG_PATH = REPO_ROOT / "config" / "prioritization.toml"

FINDING_A = {
    "template_id": "doc-template-a",
    "matched_at": "http://192.0.2.10/app/login",
    "response_snippet": "reflected proof a",
    "info": {"severity": "high"},
}
FINDING_B = {
    "template_id": "doc-template-b",
    "matched_at": "http://192.0.2.11/app/search",
    "response_snippet": "reflected proof b",
    "info": {"severity": "medium"},
}


class MockCallCounter:
    calls = 0


class CountingHandler(mock_systemone.Handler):
    def do_POST(self) -> None:
        MockCallCounter.calls += 1
        super().do_POST()


def api(base_url: str, method: str, path: str, body=None) -> tuple[int, Any]:
    request = urllib.request.Request(
        base_url + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode())


class InboxDaemon(unittest.TestCase):
    """Demone + mock backend + watcher: `interval_s` lungo nei test deterministici
    (scan manuale), corto nel test di temporizzazione (SC-001)."""

    interval_s: float = 60.0

    def setUp(self) -> None:
        MockCallCounter.calls = 0
        mock_server = HTTPServer(("127.0.0.1", 0), CountingHandler)
        threading.Thread(target=mock_server.serve_forever, daemon=True).start()
        self.mock_server = mock_server
        self.sessions_dir = Path(tempfile.mkdtemp())
        triage = load_config(TRIAGE_CONFIG_PATH)
        inbox = dataclasses.replace(triage.inbox, interval_s=self.interval_s, max_file_bytes=2000)
        triage = dataclasses.replace(triage, base_url=f"http://127.0.0.1:{mock_server.server_address[1]}", inbox=inbox)
        prioritization = dataclasses.replace(
            load_rubric(PRIORITIZATION_CONFIG_PATH), base_url=f"http://127.0.0.1:{mock_server.server_address[1]}"
        )
        self.server, _, self.shared = build_service(self.sessions_dir, triage, prioritization, port=0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.addCleanup(self.stop_backend)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(mock_server.shutdown)
        status, _ = api(self.base, "POST", "/api/sessions", {"name": "collaudo"})
        self.assertEqual(status, 200)
        self.session_dir = self.sessions_dir / "collaudo"

    def stop_backend(self) -> None:
        pass

    def mock_calls(self) -> int:
        return MockCallCounter.calls

    def deliver(self, filename: str, text: str) -> None:
        inbox = self.session_dir / "inbox"
        inbox.mkdir(parents=True, exist_ok=True)
        (inbox / filename).write_text(text, encoding="utf-8")

    def scan(self, times: int = 2) -> None:
        watcher = self.shared.get("inbox_watcher")
        for _ in range(times):
            watcher.scan_once()

    def log_entries(self) -> list[dict[str, Any]]:
        path = self.session_dir / "inbox-log.jsonl"
        if not path.exists():
            return []
        with path.open(encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def end_for(self, filename: str) -> dict[str, Any]:
        ends = [e for e in self.log_entries() if e.get("event") == "end" and e.get("file") == filename]
        self.assertTrue(ends, f"nessuna end per {filename}: {self.log_entries()}")
        return ends[-1]

    def queue_triage(self) -> list[dict[str, Any]]:
        status, body = api(self.base, "GET", "/api/sessions/collaudo/queue")
        self.assertEqual(status, 200)
        return body["triage"]


class TestInboxFindings(InboxDaemon):

    def test_consegna_due_validi_uno_malformito_partial_con_archivio(self) -> None:
        self.deliver(
            "findings-misti.jsonl",
            json.dumps(FINDING_A) + "\nnot json {\n" + json.dumps(FINDING_B) + "\n",
        )
        self.scan()
        queue = self.queue_triage()
        self.assertEqual(len(queue), 2)
        end = self.end_for("findings-misti.jsonl")
        self.assertEqual(end["status"], "partial")
        self.assertEqual(end["lines"], 3)
        self.assertEqual(end["evaluated"], 2)
        self.assertEqual(end["duplicates"], 0)
        self.assertEqual([error["line"] for error in end["errors"]], [2])
        archived = self.session_dir / end["archived_as"]
        self.assertTrue(archived.exists())
        self.assertTrue((self.session_dir / "inbox" / "findings-misti.jsonl").exists() is False)

    def test_ricopia_stesso_contenuto_already_processed_coda_invariata(self) -> None:
        content = json.dumps(FINDING_A) + "\n"
        self.deliver("findings-prima.jsonl", content)
        self.scan()
        self.assertEqual(len(self.queue_triage()), 1)
        self.deliver("findings-seconda.jsonl", content)
        self.scan()
        end = self.end_for("findings-seconda.jsonl")
        self.assertEqual(end["status"], "already-processed")
        self.assertEqual(len(self.queue_triage()), 1)

    def test_file_oltre_max_file_bytes_rejected_senza_leggere(self) -> None:
        self.deliver("findings-grande.jsonl", "# padding\n" * 500)
        self.scan()
        end = self.end_for("findings-grande.jsonl")
        self.assertEqual(end["status"], "rejected")
        self.assertIn("max_file_bytes", end["note"])
        self.assertTrue((self.session_dir / end["archived_as"]).exists())
        self.assertEqual(self.queue_triage(), [])

    def test_file_vuoto_processed_zero_righe(self) -> None:
        self.deliver("findings-vuoto.jsonl", "")
        self.scan()
        end = self.end_for("findings-vuoto.jsonl")
        self.assertEqual(end["status"], "processed")
        self.assertEqual(end["lines"], 0)
        self.assertEqual(end["evaluated"], 0)

    def test_righe_vuote_ignorate_non_contate_non_in_errore(self) -> None:
        self.deliver("findings-con-blank.jsonl", "\n" + json.dumps(FINDING_A) + "\n   \n")
        self.scan()
        end = self.end_for("findings-con-blank.jsonl")
        self.assertEqual(end["status"], "processed")
        self.assertEqual(end["lines"], 1)
        self.assertEqual(end["errors"], [])
        self.assertEqual(len(self.queue_triage()), 1)

    def test_prefisso_sconosciuto_rejected_con_diagnosi(self) -> None:
        self.deliver("foo.jsonl", json.dumps(FINDING_A) + "\n")
        self.scan()
        end = self.end_for("foo.jsonl")
        self.assertEqual(end["status"], "rejected")
        self.assertIn("unknown prefix", end["note"])
        self.assertEqual(self.queue_triage(), [])

    def test_estensione_provvisoria_mai_toccata(self) -> None:
        self.deliver("findings-in-arrivo.part", json.dumps(FINDING_A) + "\n")
        self.scan(times=3)
        self.assertTrue((self.session_dir / "inbox" / "findings-in-arrivo.part").exists())
        self.assertEqual(self.log_entries(), [])

    def test_backend_fermo_record_degradati_e_partial(self) -> None:
        self.mock_server.shutdown()
        self.mock_server.server_close()
        self.deliver("findings-backend-giu.jsonl", json.dumps(FINDING_A) + "\n" + json.dumps(FINDING_B) + "\n")
        self.scan()
        queue = self.queue_triage()
        self.assertEqual(len(queue), 2)
        self.assertTrue(all(record["error"] for record in queue))
        end = self.end_for("findings-backend-giu.jsonl")
        self.assertEqual(end["status"], "partial")
        status, body = api(self.base, "GET", "/api/status")
        self.assertFalse(body["backend"]["reachable"])

    def test_nessun_actions_jsonl_dopo_le_consegne(self) -> None:
        self.deliver("findings-a.jsonl", json.dumps(FINDING_A) + "\n")
        self.scan()
        self.assertFalse((self.session_dir / "actions.jsonl").exists())

    def test_dedup_cross_sorgente_finding_gia_in_coda_via_api(self) -> None:
        status, _ = api(self.base, "POST", "/api/sessions/collaudo/findings", FINDING_A)
        self.assertEqual(status, 200)
        self.deliver("findings-ripetuto.jsonl", json.dumps(FINDING_A) + "\n")
        self.scan()
        end = self.end_for("findings-ripetuto.jsonl")
        self.assertEqual(end["duplicates"], 1)
        self.assertEqual(end["evaluated"], 0)
        self.assertEqual(len(self.queue_triage()), 1)


class TestInboxObservations(InboxDaemon):

    def test_tre_osservazioni_una_gia_vista_due_record_un_duplicato(self) -> None:
        seen = {"text": "credential reuse observed on the admin panel of the target"}
        status, _ = api(self.base, "POST", "/api/sessions/collaudo/observations",
                        {"objective": "user_flag", "observation": seen})
        self.assertEqual(status, 200)
        fresh_a = {"text": "sqli error-based extraction reached the students table"}
        fresh_b = {"text": "the basement endpoint leaks the monster list without auth"}
        self.deliver(
            "observations-user_flag-a.jsonl",
            json.dumps(seen) + "\n" + json.dumps(fresh_a) + "\n" + json.dumps(fresh_b) + "\n",
        )
        self.scan()
        end = self.end_for("observations-user_flag-a.jsonl")
        self.assertEqual(end["status"], "processed")
        self.assertEqual(end["evaluated"], 2)
        self.assertEqual(end["duplicates"], 1)
        self.assertEqual(end["objective"], "user_flag")
        status, queue = api(self.base, "GET", "/api/sessions/collaudo/queue")
        # il duplicato scrive la riga puntatore (dedup esistente): i record veri sono 3
        records = queue["prioritize"]["user_flag"]
        self.assertEqual(len([r for r in records if not r.get("duplicate_of")]), 3)
        self.assertEqual(len([r for r in records if r.get("duplicate_of")]), 1)

    def test_obiettivo_senza_rubrica_scartato_prima_di_valutare(self) -> None:
        self.deliver(
            "observations-inesistente.jsonl",
            json.dumps({"text": "observation for an objective without rubric"}) + "\n",
        )
        self.scan()
        end = self.end_for("observations-inesistente.jsonl")
        self.assertEqual(end["status"], "rejected")
        self.assertIn("unknown objective", end["note"])
        self.assertEqual(end.get("lines"), None)  # nessuna fase di valutazione: scarto pre-start
        self.assertTrue((self.session_dir / end["archived_as"]).exists())
        self.assertIn("rejected", end["archived_as"])
        status, queue = api(self.base, "GET", "/api/sessions/collaudo/queue")
        self.assertNotIn("inesistente", queue["prioritize"])


class TestInboxCrashRecovery(InboxDaemon):
    """US3/SC-003: la start senza end si chiude interrupted, mai rivalutata."""

    def _write_start(self, filename: str, sha: str, lines: int = 2, kind: str = "findings") -> None:
        with (self.session_dir / "inbox-log.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "ts": "2026-09-28T00:00:00", "event": "start", "file": filename,
                "sha256": sha, "kind": kind, "lines": lines,
            }) + "\n")

    def test_start_aperta_file_in_consegna_chiusa_interrupted_e_archiviata(self) -> None:
        import hashlib
        content = json.dumps(FINDING_A) + "\n" + json.dumps(FINDING_B) + "\n"
        self.deliver("findings-crash.jsonl", content)
        self._write_start("findings-crash.jsonl", hashlib.sha256(content.encode()).hexdigest())
        calls_before = self.mock_calls()
        self.scan(times=1)
        end = self.end_for("findings-crash.jsonl")
        self.assertEqual(end["status"], "interrupted")
        self.assertTrue((self.session_dir / end["archived_as"]).exists())
        self.assertFalse((self.session_dir / "inbox" / "findings-crash.jsonl").exists())
        self.assertEqual(self.queue_triage(), [])          # zero valutazioni dal residuo
        self.assertEqual(self.mock_calls(), calls_before)  # zero domande al backend
        ricopy = self.end_for("findings-crash.jsonl")
        self.assertEqual(ricopy["status"], "interrupted")  # una sola end

    def test_secondo_file_dopo_il_riavvio_processato_regolarmente(self) -> None:
        import hashlib
        content = json.dumps(FINDING_B) + "\n"
        self.deliver("findings-crash.jsonl", content)
        self._write_start("findings-crash.jsonl", hashlib.sha256(content.encode()).hexdigest(), lines=1)
        self.scan(times=1)
        self.deliver("findings-dopo.jsonl", json.dumps(FINDING_A) + "\n")
        self.scan()
        end = self.end_for("findings-dopo.jsonl")
        self.assertEqual(end["status"], "processed")
        self.assertEqual(end["evaluated"], 1)

    def test_record_scritti_prima_del_crash_restano_una_volta_sola(self) -> None:
        status, _ = api(self.base, "POST", "/api/sessions/collaudo/findings", FINDING_A)
        self.assertEqual(status, 200)
        import hashlib
        content = json.dumps(FINDING_A) + "\n" + json.dumps(FINDING_B) + "\n"
        self.deliver("findings-crash.jsonl", content)
        self._write_start("findings-crash.jsonl", hashlib.sha256(content.encode()).hexdigest())
        self.scan(times=1)
        queue = self.queue_triage()
        self.assertEqual(len(queue), 1)  # solo il record via API: il residuo non ha rivalutato r1

    def test_start_aperta_file_mancante_chiusa_con_nota_senza_archived_as(self) -> None:
        self._write_start("findings-fantasma.jsonl", "deadbeef" * 8)
        self.scan(times=1)
        end = self.end_for("findings-fantasma.jsonl")
        self.assertEqual(end["status"], "interrupted")
        self.assertIn("not found", end["note"])
        self.assertNotIn("archived_as", end)


class TestInboxEndpoint(InboxDaemon):

    def test_get_inbox_directory_pending_e_log(self) -> None:
        status, body = api(self.base, "GET", "/api/sessions/collaudo/inbox")
        self.assertEqual(status, 200)
        self.assertEqual(body["directory"], str(self.session_dir / "inbox"))
        self.assertEqual(body["pending"], [])
        self.assertEqual(body["log"], [])
        self.deliver("findings-pending.jsonl", json.dumps(FINDING_A) + "\n")
        self.deliver("findings-non-ancora.part", "bozza")  # non è una consegna
        status, body = api(self.base, "GET", "/api/sessions/collaudo/inbox")
        self.assertEqual(body["pending"], ["findings-pending.jsonl"])
        self.scan()
        status, body = api(self.base, "GET", "/api/sessions/collaudo/inbox")
        self.assertEqual(body["pending"], [])
        self.assertEqual(body["log"][-1]["status"], "processed")

    def test_status_dichiara_inbox_enabled(self) -> None:
        status, body = api(self.base, "GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertTrue(body["inbox"]["enabled"])

    def test_nome_sessione_invalido_400(self) -> None:
        status, body = api(self.base, "GET", "/api/sessions/NO/inbox")
        self.assertEqual(status, 400)


class TestInboxTiming(InboxDaemon):
    """SC-001: i record compaiono entro pochi intervalli dalla stabilizzazione (thread vero)."""

    interval_s = 0.05

    def test_record_in_coda_entro_doppio_intervallo_dalla_stabilizzazione(self) -> None:
        self.deliver("findings-veloce.jsonl", json.dumps(FINDING_A) + "\n")
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if self.queue_triage():
                break
            time.sleep(0.01)
        self.assertEqual(len(self.queue_triage()), 1, "il record non è apparso entro la finestra")
        # stabilità = stability_reads intervalli + innesco: margine 2x su tutto il ciclo
        self.assertLess(time.monotonic() - (deadline - 2.0), 4 * self.interval_s + 0.5)


if __name__ == "__main__":
    unittest.main()
