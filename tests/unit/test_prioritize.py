"""Test prioritize: payload inviato al modello (domande esatte, neutralità), pipeline, memoria del record."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from typing import Any

import sys

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from jevsec.client import SystemOneError  # noqa: E402
from jevsec.prioritize import SCENARIO_WORDS, prioritize_observation  # noqa: E402
from jevsec.rubric import load_rubric  # noqa: E402

CONFIG = load_rubric(REPO_ROOT / "config" / "prioritization.toml")

OBSERVATION = {
    "id": "obs-1",
    "text": "A Group Policy file contains a recoverable password for a local administrator account.",
    "context": "host: doc-workstation",
}

CAPTURED: dict[str, Any] = {}


def capturing_ask(base_url: str, state: dict, questions: dict, timeout_s: float, api_token: str | None = None, model: str = "jev-latest") -> tuple[dict, float]:
    CAPTURED["state"] = state
    CAPTURED["questions"] = questions
    answers = {name: {"type": "noul", "noul": 0.8} for name in questions}
    return {"model": "canned", "answers": answers}, 0.001


class TestPayloadNeutrality(unittest.TestCase):
    """FR-003 e FR-010: domande atomiche esatte, obiettivo e scenari assenti dal payload."""

    def test_prioritize_domande_inviate_esattamente_quelle_della_rubrica(self) -> None:
        record = prioritize_observation(OBSERVATION, "obs-1", CONFIG, CONFIG.objectives["domain_admin"], capturing_ask)
        self.assertIsNone(record["error"])
        self.assertEqual(set(CAPTURED["questions"]), set(CONFIG.objectives["domain_admin"].questions))

    def test_prioritize_obiettivo_assente_dallo_state(self) -> None:
        prioritize_observation(OBSERVATION, "obs-1", CONFIG, CONFIG.objectives["domain_admin"], capturing_ask)
        blob = json.dumps(CAPTURED["state"]).lower()
        for objective_sentence in CONFIG.objective_names.values():
            self.assertNotIn(objective_sentence.lower()[:40], blob)
        self.assertNotIn("domain_admin", blob)

    def test_prioritize_payload_senza_parole_scenario(self) -> None:
        for rubric in CONFIG.objectives.values():
            with self.subTest(objective=rubric.name):
                payload = json.dumps({"state": CAPTURED.get("state", ""), "questions": rubric.questions}).lower()
                for word in SCENARIO_WORDS:
                    self.assertNotIn(word, payload)

    def test_prioritize_state_solo_text_e_context_redatti(self) -> None:
        observation = {**OBSERVATION, "extra": "non deve passare", "text": "digest 0123456789abcdef listed"}
        record = prioritize_observation(observation, "obs-1", CONFIG, CONFIG.objectives["domain_admin"], capturing_ask)
        self.assertEqual(set(CAPTURED["state"]), {"text", "context"})
        self.assertNotIn("0123456789abcdef", CAPTURED["state"]["text"])
        self.assertIsNone(record["error"])


class TestPipeline(unittest.TestCase):

    def test_prioritize_giudizi_alti_regola_massima(self) -> None:
        record = prioritize_observation(OBSERVATION, "obs-1", CONFIG, CONFIG.objectives["domain_admin"], capturing_ask)
        self.assertEqual(record["impact"], 4)
        self.assertEqual(record["winning_rule"], "privileged_credentials")
        self.assertIn("credentials", record["active_rules"])
        self.assertTrue(record["quick_win"])

    def test_prioritize_giudizi_bassi_default(self) -> None:
        def low_ask(base_url, state, questions, timeout_s, api_token=None, model="jev-latest"):
            return {"model": "x", "answers": {name: {"type": "noul", "noul": 0.1} for name in questions}}, 0.001
        record = prioritize_observation(OBSERVATION, "obs-1", CONFIG, CONFIG.objectives["domain_admin"], low_ask)
        self.assertEqual(record["impact"], 0)
        self.assertEqual(record["winning_rule"], "no_signal")
        self.assertFalse(record["quick_win"])

    def test_prioritize_text_assente_errore_non_scartato(self) -> None:
        record = prioritize_observation({"id": "x"}, "x", CONFIG, CONFIG.objectives["domain_admin"], capturing_ask)
        self.assertIsNotNone(record["error"])
        self.assertIsNone(record["impact"])

    def test_prioritize_risposta_malformata_errore_impatto_nullo(self) -> None:
        def broken_ask(base_url, state, questions, timeout_s, api_token=None, model="jev-latest"):
            return {"model": "x", "answers": {}}, 0.001
        record = prioritize_observation(OBSERVATION, "obs-1", CONFIG, CONFIG.objectives["domain_admin"], broken_ask)
        self.assertIsNotNone(record["error"])
        self.assertIsNone(record["impact"])


class TestRecordMemory(unittest.TestCase):
    """004 FR-003: il record fotografa lo state giudicato e il suo hash di contenuto."""

    def test_record_contiene_observation_identica_allo_state_visto_dal_modello(self) -> None:
        record = prioritize_observation(OBSERVATION, "obs-1", CONFIG, CONFIG.objectives["domain_admin"], capturing_ask)
        self.assertIsNone(record["error"])
        self.assertEqual(record["observation"], CAPTURED["state"])

    def test_record_obs_hash_sha256_di_testo_e_contesto_redatti(self) -> None:
        record = prioritize_observation(OBSERVATION, "obs-1", CONFIG, CONFIG.objectives["domain_admin"], capturing_ask)
        state = CAPTURED["state"]
        expected = hashlib.sha256((state["text"] + "\x00" + state.get("context", "")).encode("utf-8")).hexdigest()
        self.assertEqual(record["obs_hash"], expected)

    def test_record_senza_context_hash_su_solo_testo(self) -> None:
        observation = {"id": "o", "text": "A plain factual observation without any context."}
        record = prioritize_observation(observation, "o", CONFIG, CONFIG.objectives["domain_admin"], capturing_ask)
        state = CAPTURED["state"]
        self.assertNotIn("context", state)
        expected = hashlib.sha256((state["text"] + "\x00" + "").encode("utf-8")).hexdigest()
        self.assertEqual(record["obs_hash"], expected)

    def test_text_assente_errore_senza_observation_né_hash(self) -> None:
        record = prioritize_observation({"id": "x"}, "x", CONFIG, CONFIG.objectives["domain_admin"], capturing_ask)
        self.assertIsNotNone(record["error"])
        self.assertIsNone(record["observation"])
        self.assertIsNone(record["obs_hash"])

    def test_errore_motore_ma_state_comunque_fotografato(self) -> None:
        def dead_ask(base_url, state, questions, timeout_s, api_token=None, model="jev-latest"):
            raise SystemOneError("connessione fallita")
        record = prioritize_observation(OBSERVATION, "obs-1", CONFIG, CONFIG.objectives["domain_admin"], dead_ask)
        self.assertIsNotNone(record["error"])
        self.assertIn("text", record["observation"])
        self.assertIsNotNone(record["obs_hash"])


if __name__ == "__main__":
    unittest.main()
