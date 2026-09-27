"""Sentinelle: validazione del set, barriere mai-nel-training/mai-esportate, metriche (piano 2026-09-27 fase 2.2)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "tools"))

import run_sentinelle as rs  # noqa: E402
from jevsec.config import load_config  # noqa: E402
from jevsec.rubric import load_rubric  # noqa: E402

PRIO_SET = REPO_ROOT / "data" / "sentinelle" / "sentinelle-v001-prioritize.jsonl"
TRIAGE_SET = REPO_ROOT / "data" / "sentinelle" / "sentinelle-v001-triage.jsonl"


def fake_ask(value: float = 0.5):
    """Motore finto: ogni domanda noul risponde value; nessuna rete."""
    def _ask(base_url, state, questions, timeout_s, api_token=None, model=None):
        answers = {name: {"type": "noul", "noul": value} for name in questions}
        return {"model": "fake", "answers": answers, "usage": {}}, 0.01
    return _ask


class TestValidazioneSet(unittest.TestCase):
    def test_set_reale_passa_la_validazione(self) -> None:
        rubric = load_rubric(REPO_ROOT / "config" / "prioritization.toml")
        cases = rs.load_cases(PRIO_SET)
        self.assertEqual(len(cases), 24)
        rs.validate_prioritize_set(cases, rubric)
        triage_cases = rs.load_cases(TRIAGE_SET)
        self.assertEqual(len(triage_cases), 12)
        rs.validate_triage_set(triage_cases)

    def test_copertura_classi_in_entrmbi_i_versi(self) -> None:
        cases = rs.load_cases(PRIO_SET)
        for question in ("exposes_credentials", "is_reachable", "is_privileged", "is_escalation_path",
                         "is_path_as_user", "is_injection_point", "is_takeover_lead", "is_attack_surface",
                         "quick_win"):
            values = {case["expected"][question] for case in cases if question in case["expected"]}
            self.assertEqual(values, {0, 1}, f"{question} mai vista in una delle due classi")
        quick_no = sum(1 for case in cases if not case["expected"]["quick_win"])
        self.assertGreaterEqual(quick_no, 8, "quick_win negativi sotto il minimo (§1.6)")

    def test_validatore_rifiuta_atteso_incoerente_con_rubrica(self) -> None:
        rubric = load_rubric(REPO_ROOT / "config" / "prioritization.toml")
        cases = rs.load_cases(PRIO_SET)
        cases[0]["expected_impact"] = (cases[0]["expected_impact"] + 1) % 5
        with self.assertRaises(SystemExit):
            rs.validate_prioritize_set(cases, rubric)

    def test_validatore_rifiuta_indirizzo_non_documentale(self) -> None:
        rubric = load_rubric(REPO_ROOT / "config" / "prioritization.toml")
        cases = rs.load_cases(PRIO_SET)
        # costruito a pezzi: un IPv4 pubblico letterale nel sorgente violerebbe
        # l'audit contenuti dell'export (regola I.5) proprio mentre lo testa
        public_ip = ".".join(("9", "9", "9", "9"))
        cases[0]["observation"]["text"] = cases[0]["observation"]["text"].replace("198.51.100.42", public_ip)
        with self.assertRaises(SystemExit):
            rs.validate_prioritize_set(cases, rubric)


class TestBarriere(unittest.TestCase):
    def test_sentinelle_mai_esportate(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("export_public", REPO_ROOT / "tools" / "export_public.py")
        export_public = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(export_public)
        exported = {path.as_posix() for path in export_public.iter_export_files()}
        self.assertFalse(any(path.startswith("data/sentinelle") for path in exported),
                         "le sentinelle sono finite nel repo pubblico")
        self.assertNotIn("config/actions.toml", exported,
                         "la config operativa con le scope reali è finita nel repo pubblico")

    def test_sentinelle_mai_nel_training(self) -> None:
        import build_training_data as btd
        rubric = load_rubric(REPO_ROOT / "config" / "prioritization.toml")
        sentinel_case = rs.load_cases(PRIO_SET)[0]
        # una sessione allowlistata contiene lo stesso fatto della sentinella
        record = {"obs_ref": "s1", "objective": sentinel_case["objective"], "seq": 1,
                  "error": None, "duplicate_of": None, "judgments": {"exposes_credentials": 0.9},
                  "observation": dict(sentinel_case["observation"])}
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "sospetta"
            session.mkdir()
            (session / f"prioritize-{sentinel_case['objective']}.jsonl").write_text(
                json.dumps(record) + "\n", encoding="utf-8")
            rows = btd.rows_from_sessions(Path(tmp), rubric, only_sessions=frozenset({"sospetta"}))
        sentinel_hashes = btd.sentinel_state_hashes(btd.SENTINELLE_DIR)
        kept, dropped = btd.drop_sentinel_overlaps(rows, sentinel_hashes)
        self.assertEqual(dropped, len(rows))
        self.assertEqual(kept, [])


class TestMetriche(unittest.TestCase):
    def test_wilson_interval_non_degeneri_0_su_12(self) -> None:
        lo, hi = rs.wilson(0, 12)
        self.assertGreater(lo, 0.0)
        self.assertLess(lo, 0.2)
        self.assertLessEqual(hi, 0.35)

    def test_mcnemar_esatto_su_discordanti(self) -> None:
        b, c, p_value = rs.mcnemar_exact([True] * 5 + [True] * 5, [False] * 5 + [True] * 5)
        self.assertEqual((b, c), (5, 0))
        self.assertAlmostEqual(p_value, 0.0625)  # 2 × (1/2)^5: esatto two-sided
        _, _, p_simmetrico = rs.mcnemar_exact([True, True, True], [False, False, False])
        self.assertEqual(p_simmetrico, 0.25)  # 2 × (1/2)^3
        _, _, p_paritario = rs.mcnemar_exact([True, True, False], [False, False, True])
        self.assertEqual(p_paritario, 1.0)  # 2/3 discordanti: nessuna evidenza, non un bug

    def test_baseline_maggioritaria(self) -> None:
        self.assertEqual(rs.majority_baseline([True] * 7 + [False] * 3), 0.7)
        self.assertEqual(rs.majority_baseline([False] * 9 + [True]), 0.9)

    def test_report_contiene_baseline_maggioritaria_e_wilson(self) -> None:
        rubric = load_rubric(REPO_ROOT / "config" / "prioritization.toml")
        cases = rs.load_cases(PRIO_SET)[:4]
        with mock.patch.object(rs, "ask", fake_ask(0.5)):
            results = rs.run_prioritize(cases, rubric, "http://127.0.0.1:9")
        evaluation = rs.evaluate_prioritize(results)
        self.assertEqual(len(results[0]["raw"][0]["response"]["answers"]),
                         len(rubric.objectives[cases[0]["objective"]].questions))  # risposte grezze intere
        import argparse
        args = argparse.Namespace(set="v001", label="test", base_url="http://127.0.0.1:9", baseline_url=None)
        report = rs.build_report(args, evaluation, {"verdict_hits": [], "no_auth_hits": [], "errors": []},
                                 results, None, None)
        self.assertIn("baseline maggioritaria", report)
        self.assertIn("Wilson 95", report)
        self.assertIn("FPR quick_win", report)
        self.assertIn("§1.6", report)

    def test_errori_contati_come_fallimenti_con_bound(self) -> None:
        case = rs.load_cases(PRIO_SET)[0]
        record = {"impact": None, "winning_rule": None, "judgments": {}, "error": "engine down"}
        evaluation = rs.evaluate_prioritize([{"case": case, "record": record, "raw": []}])
        self.assertEqual(evaluation["impact_hits"], [])  # l'errore non gonfia l'accuratezza
        self.assertEqual(sum(evaluation["errors"]), 1)


if __name__ == "__main__":
    unittest.main()
