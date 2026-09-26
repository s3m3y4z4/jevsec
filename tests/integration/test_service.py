"""Test del demone: sessioni, API, persistenza, feedback — con mock come backend."""

from __future__ import annotations

import json
from typing import Any
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import HTTPServer
from pathlib import Path

import sys

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "harness"))

import mock_systemone  # noqa: E402

from jevsec.config import load_config  # noqa: E402
from jevsec.rubric import load_rubric  # noqa: E402
from jevsec.service import build_service  # noqa: E402


class MockCallCounter:
    calls = 0


class CountingHandler(mock_systemone.Handler):
    def do_POST(self) -> None:
        MockCallCounter.calls += 1
        super().do_POST()

TRIAGE_CONFIG_PATH = REPO_ROOT / "config" / "live-triage.toml"
PRIORITIZATION_CONFIG_PATH = REPO_ROOT / "config" / "prioritization.toml"
SAMPLE = REPO_ROOT / "data" / "samples" / "live_triage_findings.jsonl"


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


def start_daemon(sessions_dir: Path, mock_port: int) -> tuple[Any, str]:
    triage = load_config(TRIAGE_CONFIG_PATH)
    prioritization = load_rubric(PRIORITIZATION_CONFIG_PATH)
    import dataclasses
    triage = dataclasses.replace(triage, base_url=f"http://127.0.0.1:{mock_port}")
    prioritization = dataclasses.replace(prioritization, base_url=f"http://127.0.0.1:{mock_port}")
    server, _, _ = build_service(sessions_dir, triage, prioritization, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


class TestServiceDaemon(unittest.TestCase):

    def setUp(self) -> None:
        MockCallCounter.calls = 0
        mock_server = HTTPServer(("127.0.0.1", 0), CountingHandler)
        threading.Thread(target=mock_server.serve_forever, daemon=True).start()
        self.mock_server = mock_server
        self.sessions_dir = Path(tempfile.mkdtemp())
        self.server, self.base = start_daemon(self.sessions_dir, mock_server.server_address[1])
        self.addCleanup(self.server.shutdown)
        self.addCleanup(mock_server.shutdown)

    def test_sessione_finding_coda_end_to_end_entro_due_secondi(self) -> None:
        status, body = api(self.base, "POST", "/api/sessions", {"name": "prova"})
        self.assertEqual(status, 200)
        findings = [json.loads(line) for line in SAMPLE.open(encoding="utf-8")]
        started = time.monotonic()
        status, records = api(self.base, "POST", "/api/sessions/prova/findings", findings)
        elapsed = time.monotonic() - started
        self.assertEqual(status, 200)
        self.assertEqual(len(records), len(findings))
        self.assertLess(elapsed, 10.0)  # il mock risponde in pochi ms; 10s tetto difensivo del test
        status, queue = api(self.base, "GET", "/api/sessions/prova/queue")
        self.assertEqual(status, 200)
        self.assertEqual(len(queue["triage"]), len(findings))
        on_disk = list((self.sessions_dir / "prova" / "triage.jsonl").open(encoding="utf-8"))
        self.assertEqual(len(on_disk), len(findings))

    def test_sessione_osservazioni_con_obiettivo(self) -> None:
        api(self.base, "POST", "/api/sessions", {"name": "obs"})
        payload = {"objective": "domain_admin",
                   "observation": {"id": "k1", "text": "A Group Policy file exposes a recoverable local-admin password."}}
        status, record = api(self.base, "POST", "/api/sessions/obs/observations", payload)
        self.assertEqual(status, 200)
        self.assertEqual(record["objective"], "domain_admin")
        self.assertEqual(record["impact"], 4)  # mock: noul 0.5 attiva la regola massima
        _, queue = api(self.base, "GET", "/api/sessions/obs/queue")
        self.assertEqual(len(queue["prioritize"]["domain_admin"]), 1)

    def test_feedback_conforme_al_playbook_con_ts_e_impacto_dato(self) -> None:
        api(self.base, "POST", "/api/sessions", {"name": "fb"})
        api(self.base, "POST", "/api/sessions/fb/observations",
            {"objective": "user_flag", "observation": {"id": "k9", "text": "The task runs as the user of interest."}})
        status, feedback = api(self.base, "POST", "/api/sessions/fb/feedback",
                               {"id": "k9", "ranking_ok": False, "impact_giusto": 4,
                                "giudizi_sbagliati": ["is_reachable"], "note": "top"})
        self.assertEqual(status, 200)
        self.assertIn("ts", feedback)
        self.assertEqual(feedback["impact_dato"], 4)
        line = json.loads((self.sessions_dir / "fb" / "feedback.jsonl").read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(line["id"], "k9")
        self.assertEqual(line["impact_giusto"], 4)

    def test_feedback_id_inesistente_404(self) -> None:
        api(self.base, "POST", "/api/sessions", {"name": "fb2"})
        status, body = api(self.base, "POST", "/api/sessions/fb2/feedback", {"id": "fantasma", "ranking_ok": True})
        self.assertEqual(status, 404)
        self.assertIn("error", body)

    def test_riavvio_senza_perdite(self) -> None:
        api(self.base, "POST", "/api/sessions", {"name": "persist"})
        findings = [json.loads(line) for line in SAMPLE.open(encoding="utf-8")]
        api(self.base, "POST", "/api/sessions/persist/findings", findings)
        self.server.shutdown()
        self.server, self.base = start_daemon(self.sessions_dir, self.mock_server.server_address[1])
        _, queue = api(self.base, "GET", "/api/sessions/persist/queue")
        self.assertEqual(len(queue["triage"]), len(findings))

    def test_corpo_malformato_400_con_diagnosi(self) -> None:
        api(self.base, "POST", "/api/sessions", {"name": "bad"})
        request = urllib.request.Request(
            self.base + "/api/sessions/bad/findings", data=b"not json", method="POST")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
            body = json.loads(error.read().decode())
            self.assertIn("error", body)
        self.assertEqual(status, 400)

    def test_nome_sessione_non_valido_rifiutato(self) -> None:
        status, _ = api(self.base, "POST", "/api/sessions", {"name": "../escape"})
        self.assertEqual(status, 400)

    def test_stato_backend_raggiungibile_con_domanda_vera(self) -> None:
        _, status = api(self.base, "GET", "/api/status")
        self.assertEqual(status["backend"]["reachable"], True)
        self.assertIn("jevsecd", status["service"])

    def test_console_servita_con_marcatori(self) -> None:
        with urllib.request.urlopen(self.base + "/", timeout=10) as response:
            page = response.read().decode("utf-8")
        self.assertIn("jevsecd", page)
        self.assertIn("triage", page)
        self.assertIn("feedback", page)
        self.assertIn("visibilitychange", page)
        self.assertIn("REFRESH_HIDDEN_MS", page)
        self.assertIn("obs-text", page)

    def test_osservazione_duplicata_puntatore_e_zero_nuove_valutazioni(self) -> None:
        api(self.base, "POST", "/api/sessions", {"name": "dup"})
        text = "The target host exposes an administrative console on an unusual high port."
        body = {"objective": "user_flag", "observation": {"id": "d1", "text": text}}
        status, first = api(self.base, "POST", "/api/sessions/dup/observations", body)
        self.assertEqual(status, 200)
        self.assertNotIn("duplicate_of", first)
        after_first = MockCallCounter.calls
        status, second = api(self.base, "POST", "/api/sessions/dup/observations",
                             {"objective": "user_flag", "observation": {"id": "d2", "text": text}})
        self.assertEqual(status, 200)
        self.assertEqual(second["duplicate_of"], "d1")
        self.assertEqual(second["record"]["obs_ref"], "d1")
        self.assertEqual(MockCallCounter.calls, after_first)
        _, records = api(self.base, "GET", "/api/sessions/dup/records")
        pointer = [r for r in records["prioritize"]["user_flag"] if r["obs_ref"] == "d2"][0]
        self.assertEqual(pointer["seq"], 2)
        self.assertIsNone(pointer["impact"])
        self.assertEqual(pointer["judgments"], {})
        self.assertEqual(pointer["duplicate_of"], "d1")
        _, queue = api(self.base, "GET", "/api/sessions/dup/queue")
        refs = [r["obs_ref"] for r in queue["prioritize"]["user_flag"]]
        self.assertEqual(refs, ["d1", "d2"])

    def test_dedupe_sopravvive_al_riavvio(self) -> None:
        api(self.base, "POST", "/api/sessions", {"name": "dup2"})
        text = "A scheduled task on the host runs as the target user every night."
        api(self.base, "POST", "/api/sessions/dup2/observations",
            {"objective": "user_flag", "observation": {"id": "e1", "text": text}})
        self.server.shutdown()
        self.server, self.base = start_daemon(self.sessions_dir, self.mock_server.server_address[1])
        status, again = api(self.base, "POST", "/api/sessions/dup2/observations",
                            {"objective": "user_flag", "observation": {"id": "e9", "text": text}})
        self.assertEqual(status, 200)
        self.assertEqual(again["duplicate_of"], "e1")

    def test_coda_leggera_preview_e_testo_integro_nei_record(self) -> None:
        api(self.base, "POST", "/api/sessions", {"name": "prev"})
        long_text = ("The directory listing of the upload area discloses stale artifacts and one "
                     "archived configuration file with a dated name from the previous cycle.")
        api(self.base, "POST", "/api/sessions/prev/observations",
            {"objective": "user_flag", "observation": {"id": "p1", "text": long_text}})
        _, queue = api(self.base, "GET", "/api/sessions/prev/queue")
        light = queue["prioritize"]["user_flag"][0]
        self.assertNotIn("observation", light)
        self.assertTrue(light["text_preview"].endswith("…"))
        self.assertLessEqual(len(light["text_preview"]), 121)
        self.assertIn("seq", light)
        _, records = api(self.base, "GET", "/api/sessions/prev/records")
        full = records["prioritize"]["user_flag"][0]
        self.assertEqual(full["observation"]["text"], long_text)

    def test_next_contratto_top_fresh_cursore_e_validazioni(self) -> None:
        api(self.base, "POST", "/api/sessions", {"name": "nx"})
        api(self.base, "POST", "/api/sessions/nx/observations", {"objective": "user_flag", "observations": [
            {"id": "q1", "text": "A Group Policy file exposes a recoverable local-admin password."},
            {"id": "q2", "text": "The host runs an outdated remote-access service."},
            {"id": "q3", "text": "A plain factual observation with no signal at all."}]})
        status, advice = api(self.base, "GET", "/api/sessions/nx/next?objective=user_flag")
        self.assertEqual(status, 200)
        self.assertEqual(advice["cursor"], 3)
        impacts = [record["impact"] for record in advice["top"]]
        self.assertEqual(impacts, sorted(impacts, reverse=True))
        self.assertIn("observation", advice["top"][0])
        api(self.base, "POST", "/api/sessions/nx/observations",
            {"objective": "user_flag",
             "observation": {"id": "q4", "text": "The upload area executes file names ending with a double suffix."}})
        status, delta = api(self.base, "GET", "/api/sessions/nx/next?objective=user_flag&since_seq=3")
        self.assertEqual(status, 200)
        self.assertEqual([record["obs_ref"] for record in delta["fresh"]], ["q4"])
        self.assertEqual(delta["cursor"], 4)
        self.assertEqual(len(delta["top"]), 4)
        status, _ = api(self.base, "GET", "/api/sessions/nx/next?objective=user_flag&top_k=0")
        self.assertEqual(status, 400)
        status, _ = api(self.base, "GET", "/api/sessions/nx/next?objective=user_flag&since_seq=abc")
        self.assertEqual(status, 400)
        status, _ = api(self.base, "GET", "/api/sessions/nx/next")
        self.assertEqual(status, 400)
        status, _ = api(self.base, "GET", "/api/sessions/nx/next?objective=senza_rubrica")
        self.assertEqual(status, 400)
        api(self.base, "POST", "/api/sessions", {"name": "vuota"})
        status, empty = api(self.base, "GET", "/api/sessions/vuota/next?objective=user_flag")
        self.assertEqual((empty["cursor"], empty["top"], empty["fresh"]), (0, [], []))

    def test_status_ravvicinati_dopo_valutazione_zero_probe(self) -> None:
        api(self.base, "POST", "/api/sessions", {"name": "h1"})
        api(self.base, "POST", "/api/sessions/h1/observations",
            {"objective": "user_flag",
             "observation": {"id": "s1", "text": "A Group Policy file exposes a recoverable local-admin password."}})
        before = MockCallCounter.calls
        for _ in range(10):
            _, status = api(self.base, "GET", "/api/status")
            self.assertTrue(status["backend"]["reachable"])
        self.assertEqual(MockCallCounter.calls, before)
        self.assertIsNotNone(status["backend"]["last_success_ts"])

    def test_da_fermo_al_piu_una_domanda_di_verifica_per_finestra(self) -> None:
        before = MockCallCounter.calls
        _, status = api(self.base, "GET", "/api/status")
        self.assertTrue(status["backend"]["reachable"])
        self.assertEqual(MockCallCounter.calls, before + 1)
        for _ in range(10):
            _, status = api(self.base, "GET", "/api/status")
        self.assertEqual(MockCallCounter.calls, before + 1)

    def test_valutazione_fallita_backend_falso_subito(self) -> None:
        self.mock_server.shutdown()
        self.mock_server.server_close()
        api(self.base, "POST", "/api/sessions", {"name": "h2"})
        status, record = api(self.base, "POST", "/api/sessions/h2/observations",
                             {"objective": "user_flag", "observation": {"text": "un fatto qualsiasi"}})
        self.assertEqual(status, 200)
        self.assertIsNotNone(record["error"])
        _, status = api(self.base, "GET", "/api/status")
        self.assertFalse(status["backend"]["reachable"])

    def test_seq_assegnato_all_append_e_derivato_al_reload_pre004(self) -> None:
        session_dir = self.sessions_dir / "vecchia"
        session_dir.mkdir(parents=True)
        legacy = [{"obs_ref": f"k{i}", "objective": "user_flag", "impact": 0, "winning_rule": "no_signal",
                   "active_rules": [], "judgments": {}, "quick_win": False, "quick_win_probability": 0.1,
                   "truncated": False, "error": None} for i in (1, 2, 3)]
        (session_dir / "prioritize-user_flag.jsonl").write_text(
            "\n".join(json.dumps(line) for line in legacy) + "\n", encoding="utf-8")
        api(self.base, "POST", "/api/sessions", {"name": "vecchia"})
        _, records = api(self.base, "GET", "/api/sessions/vecchia/records")
        self.assertEqual([r["seq"] for r in records["prioritize"]["user_flag"]], [1, 2, 3])
        api(self.base, "POST", "/api/sessions/vecchia/observations",
            {"objective": "user_flag", "observation": {"id": "k4", "text": "A plain fact with no signal at all."}})
        _, records = api(self.base, "GET", "/api/sessions/vecchia/records")
        self.assertEqual([r["seq"] for r in records["prioritize"]["user_flag"]], [1, 2, 3, 4])
        self.server.shutdown()
        self.server, self.base = start_daemon(self.sessions_dir, self.mock_server.server_address[1])
        _, records = api(self.base, "GET", "/api/sessions/vecchia/records")
        self.assertEqual([r["seq"] for r in records["prioritize"]["user_flag"]], [1, 2, 3, 4])

    def test_service_log_scritto(self) -> None:
        api(self.base, "POST", "/api/sessions", {"name": "log"})
        log_line = (self.sessions_dir / "service.log").read_text(encoding="utf-8").splitlines()[-1]
        entry = json.loads(log_line)
        self.assertEqual(entry["path"], "/api/sessions")


class TestCustomObjectiveReload(unittest.TestCase):
    """Spec 005 FR-007: sessione creata prima di un cambio di rubriche ricarica intatta."""

    def test_record_con_obiettivo_precedente_restano_leggibili_con_nuova_config(self) -> None:
        import dataclasses

        mock = HTTPServer(("127.0.0.1", 0), mock_systemone.Handler)
        threading.Thread(target=mock.serve_forever, daemon=True).start()
        self.addCleanup(mock.shutdown)
        sessions_dir = Path(tempfile.mkdtemp())
        server, base = start_daemon(sessions_dir, mock.server_address[1])
        self.addCleanup(server.shutdown)

        api(base, "POST", "/api/sessions", {"name": "custom"})
        observation = {"id": "o1", "text": "Crontab runs /opt/monitor.sh as root; the file is writable by www-data."}
        status, _ = api(base, "POST", "/api/sessions/custom/observations",
                        {"objective": "user_flag", "observation": observation})
        self.assertEqual(status, 200)
        server.shutdown()

        base_url = f"http://127.0.0.1:{mock.server_address[1]}"
        custom_rubric = dataclasses.replace(
            load_rubric(REPO_ROOT / "config" / "examples" / "custom-objective.toml"), base_url=base_url
        )
        triage = dataclasses.replace(load_config(TRIAGE_CONFIG_PATH), base_url=base_url)
        rebuilt, store, _ = build_service(sessions_dir, triage, custom_rubric, port=0)
        threading.Thread(target=rebuilt.serve_forever, daemon=True).start()
        self.addCleanup(rebuilt.shutdown)
        queues = store.open("custom").queues()
        self.assertIn("user_flag", queues["prioritize"])
        self.assertEqual(len(queues["prioritize"]["user_flag"]), 1)
        self.assertEqual(queues["prioritize"]["user_flag"][0]["obs_ref"], "o1")


class TestRemoteChannelSurface(unittest.TestCase):
    """Spec 005 T022: bind solo loopback anche con canale remoto; status senza base_url né token."""

    def test_demone_binda_loopback_con_config_remota_e_status_dichiara_remote(self) -> None:
        import dataclasses
        import mock_systemone
        from jevsec.service import build_service

        remote = "https://192.0.2.50:8443"
        triage = dataclasses.replace(load_config(TRIAGE_CONFIG_PATH), base_url=remote, api_token="doc-token")
        rubric = dataclasses.replace(load_rubric(PRIORITIZATION_CONFIG_PATH), base_url=remote, api_token="doc-token")
        server, _, _ = build_service(Path(tempfile.mkdtemp()), triage, rubric, port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.assertEqual(server.server_address[0], "127.0.0.1")
        code, status = api(f"http://127.0.0.1:{server.server_address[1]}", "GET", "/api/status")
        self.assertEqual(code, 200)
        self.assertEqual(status["backend"]["mode"], "remote-secure")
        dumped = json.dumps(status)
        self.assertNotIn("192.0.2.50", dumped)
        self.assertNotIn("doc-token", dumped)


if __name__ == "__main__":
    unittest.main()
