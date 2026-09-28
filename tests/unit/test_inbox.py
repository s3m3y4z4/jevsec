"""Test unitari delle fondamenta inbox: routing dei nomi, stabilità, registro (spec 007)."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from jevsec.inbox import DeliveryLog, StabilityTracker, route_name  # noqa: E402


class TestRouteName(unittest.TestCase):
    """FR-013: la forma del nome file è contratto."""

    def test_route_name_findings_jsonl_nudo_findings(self) -> None:
        self.assertEqual(route_name("findings.jsonl").action, "deliver-findings")

    def test_route_name_findings_con_nota_findings(self) -> None:
        self.assertEqual(route_name("findings-nuclei-2026.jsonl").action, "deliver-findings")

    def test_route_name_observations_nudo_objective_estratto(self) -> None:
        routing = route_name("observations-user_flag.jsonl")
        self.assertEqual(routing.action, "deliver-observations")
        self.assertEqual(routing.objective, "user_flag")

    def test_route_name_observations_con_nota_objective_estratto(self) -> None:
        routing = route_name("observations-host_admin-2.jsonl")
        self.assertEqual(routing.action, "deliver-observations")
        self.assertEqual(routing.objective, "host_admin")

    def test_route_name_observations_objective_vuoto_passato_com_e(self) -> None:
        # la validità contro la rubrica spetta al processore: qui arriva grezzo
        routing = route_name("observations-.jsonl")
        self.assertEqual(routing.action, "deliver-observations")
        self.assertEqual(routing.objective, "")

    def test_route_name_prefisso_sconosciuto_scarto_con_diagnosi(self) -> None:
        routing = route_name("foo.jsonl")
        self.assertEqual(routing.action, "reject")
        self.assertIn("unknown prefix", routing.reason)

    def test_route_name_prefisso_maiuscolo_scarto(self) -> None:
        self.assertEqual(route_name("Findings-x.jsonl").action, "reject")

    def test_route_name_estensione_provvisoria_ignorata(self) -> None:
        self.assertEqual(route_name("findings-x.part").action, "ignore")
        self.assertEqual(route_name("findings-x.tmp").action, "ignore")

    def test_route_name_estensione_maiuscola_ignorata(self) -> None:
        self.assertEqual(route_name("findings-x.JSONL").action, "ignore")

    def test_route_name_file_nascosto_ignorato(self) -> None:
        self.assertEqual(route_name(".findings-x.jsonl").action, "ignore")


class TestStabilityTracker(unittest.TestCase):
    """FR-006: stabile quando le ultime N letture consecutive sono identiche."""

    def test_stabilita_crescita_poi_invariata(self) -> None:
        tracker = StabilityTracker(reads=2)
        self.assertFalse(tracker.observe("f.jsonl", 10))
        self.assertFalse(tracker.observe("f.jsonl", 12))
        self.assertTrue(tracker.observe("f.jsonl", 12))

    def test_stabilita_tre_letture(self) -> None:
        tracker = StabilityTracker(reads=3)
        tracker.observe("f.jsonl", 1)
        tracker.observe("f.jsonl", 1)
        self.assertFalse(tracker.observe("f.jsonl", 2))
        self.assertFalse(tracker.observe("f.jsonl", 2))
        self.assertTrue(tracker.observe("f.jsonl", 2))

    def test_stabilita_file_distinti_indipendenti(self) -> None:
        tracker = StabilityTracker(reads=2)
        tracker.observe("a.jsonl", 5)
        tracker.observe("b.jsonl", 7)
        self.assertTrue(tracker.observe("a.jsonl", 5))
        self.assertTrue(tracker.observe("b.jsonl", 7))

    def test_forget_azzera_le_letture(self) -> None:
        tracker = StabilityTracker(reads=2)
        tracker.observe("f.jsonl", 5)
        tracker.observe("f.jsonl", 5)
        tracker.forget("f.jsonl")
        self.assertFalse(tracker.observe("f.jsonl", 5))


class TestDeliveryLog(unittest.TestCase):
    """FR-003: registro append-only, una riga per fase, ricostruibile."""

    def _log(self) -> tuple[DeliveryLog, Path]:
        directory = Path(tempfile.mkdtemp())
        return DeliveryLog(directory / "inbox-log.jsonl"), directory

    def test_append_e_entries_in_ordine_con_ts(self) -> None:
        log, _ = self._log()
        log.append({"event": "start", "file": "f.jsonl", "sha256": "aa"})
        log.append({"event": "end", "file": "f.jsonl", "sha256": "aa", "status": "processed"})
        entries = log.entries()
        self.assertEqual([entry["event"] for entry in entries], ["start", "end"])
        self.assertTrue(all(entry.get("ts") for entry in entries))

    def test_known_outcomes_sha_mappato_all_ultimo_status(self) -> None:
        log, _ = self._log()
        log.append({"event": "start", "file": "f.jsonl", "sha256": "aa"})
        log.append({"event": "end", "file": "f.jsonl", "sha256": "aa", "status": "partial"})
        log.append({"event": "end", "file": "g.jsonl", "sha256": "bb", "status": "already-processed"})
        self.assertEqual(log.known_outcomes(), {"aa": "partial", "bb": "already-processed"})

    def test_open_starts_solo_senza_end(self) -> None:
        log, _ = self._log()
        log.append({"event": "start", "file": "f.jsonl", "sha256": "aa"})
        log.append({"event": "end", "file": "f.jsonl", "sha256": "aa", "status": "processed"})
        log.append({"event": "start", "file": "g.jsonl", "sha256": "bb"})
        self.assertEqual([entry["sha256"] for entry in log.open_starts()], ["bb"])

    def test_ricostruzione_da_disco_dopo_riapertura(self) -> None:
        log, _ = self._log()
        log.append({"event": "start", "file": "f.jsonl", "sha256": "aa"})
        log.append({"event": "end", "file": "f.jsonl", "sha256": "aa", "status": "rejected"})
        reopened = DeliveryLog(log.path)
        self.assertEqual(reopened.known_outcomes(), {"aa": "rejected"})
        self.assertEqual(reopened.open_starts(), [])


if __name__ == "__main__":
    unittest.main()
