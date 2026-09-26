"""Test dei giudizi: estrazione dal wire, risposte malformate, needs_review."""

from __future__ import annotations

import dataclasses
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import sys

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from jevsec.client import ask  # noqa: E402
from jevsec.config import load_config  # noqa: E402
from jevsec.triage import triage_finding  # noqa: E402

CONFIG = load_config(REPO_ROOT / "config" / "live-triage.toml")
CONFIG_ARMED = dataclasses.replace(CONFIG, auto_gate_enabled=True)  # gate armato come da Fase E

FINDING = {
    "template_id": "doc-t",
    "matched_at": "http://192.0.2.1/",
    "response_snippet": "vulnerable banner confirmed",
    "info": {"severity": "medium"},
}


def canned_ask(verdict_answer: dict[str, Any] | None, no_auth_answer: dict[str, Any] | None,
               *, omit: str | None = None) -> Any:
    """Backend finto: risposte canned per verdict e no_auth, iniettabile in triage_finding."""

    def ask(base_url: str, state: dict, questions: dict, timeout_s: float, api_token: str | None = None, model: str = "jev-latest") -> tuple[dict, float]:
        answers: dict[str, Any] = {}
        if omit != "verdict" and verdict_answer is not None:
            answers["verdict"] = verdict_answer
        if omit != "no_auth" and no_auth_answer is not None:
            answers["no_auth"] = no_auth_answer
        return {"model": "canned", "answers": answers}, 0.001

    return ask


def verdict_answer(choice: str, probability: float) -> dict[str, Any]:
    probabilities = {"true_positive": 0.1, "false_positive": 0.1, "needs_review": 0.1}
    probabilities[choice] = probability
    return {"type": "choice", "choice": choice, "probabilities": probabilities}


NO_AUTH_ANSWER = {"type": "noul", "noul": 0.8}


class TestJudgmentExtraction(unittest.TestCase):

    def test_triage_risposta_certa_tp_auto_con_probabilita_alta(self) -> None:
        record = triage_finding(FINDING, "r1", CONFIG_ARMED, canned_ask(verdict_answer("true_positive", 0.9), NO_AUTH_ANSWER))
        self.assertEqual(record["verdict"], "true_positive")
        self.assertEqual(record["verdict_probability"], 0.9)
        self.assertEqual(record["gate"], "auto")
        self.assertTrue(record["no_auth"])
        self.assertEqual(record["no_auth_probability"], 0.8)
        self.assertIsNone(record["error"])

    def test_triage_gate_disarmato_anche_oltre_soglia_resta_review(self) -> None:
        record = triage_finding(FINDING, "r1", CONFIG, canned_ask(verdict_answer("true_positive", 0.99), NO_AUTH_ANSWER))
        self.assertEqual(record["gate"], "review")  # default di config: auto_gate_enabled = false (Fase C)

    def test_triage_probabilita_bassa_tp_restata_in_review(self) -> None:
        record = triage_finding(FINDING, "r1", CONFIG, canned_ask(verdict_answer("true_positive", 0.6), NO_AUTH_ANSWER))
        self.assertEqual(record["verdict"], "true_positive")
        self.assertEqual(record["gate"], "review")

    def test_triage_risposta_senza_answers_record_in_errore(self) -> None:
        def broken_ask(base_url, state, questions, timeout_s, api_token=None, model="jev-latest"):
            return {"model": "x"}, 0.001
        record = triage_finding(FINDING, "r1", CONFIG, broken_ask)
        self.assertIsNone(record["verdict"])
        self.assertEqual(record["gate"], "review")
        self.assertIsNotNone(record["error"])

    def test_triage_risposta_prima_di_valore_noto_record_in_errore(self) -> None:
        malformed = {"type": "choice", "probabilities": {"true_positive": 1.0}}
        record = triage_finding(FINDING, "r1", CONFIG, canned_ask(malformed, NO_AUTH_ANSWER))
        self.assertIsNone(record["verdict"])
        self.assertIsNotNone(record["error"])

    def test_triage_probabilita_mancanti_record_in_errore(self) -> None:
        no_probs = {"type": "choice", "choice": "true_positive"}
        record = triage_finding(FINDING, "r1", CONFIG, canned_ask(no_probs, NO_AUTH_ANSWER))
        self.assertIsNotNone(record["error"])
        self.assertEqual(record["gate"], "review")

    def test_triage_verdetto_needs_review_sempre_in_review(self) -> None:
        record = triage_finding(FINDING, "r1", CONFIG, canned_ask(verdict_answer("needs_review", 0.95), NO_AUTH_ANSWER))
        self.assertEqual(record["verdict"], "needs_review")
        self.assertEqual(record["gate"], "review")

    def test_triage_noul_sotto_soglia_no_auth_falso(self) -> None:
        record = triage_finding(FINDING, "r1", CONFIG, canned_ask(verdict_answer("true_positive", 0.9), {"type": "noul", "noul": 0.3}))
        self.assertFalse(record["no_auth"])


class TestNeedsReviewSemantics(unittest.TestCase):

    def test_triage_evidenza_mancante_record_in_review_con_motivo(self) -> None:
        finding = {"template_id": "doc-t", "matched_at": "http://192.0.2.1/"}
        record = triage_finding(finding, "r1", CONFIG, canned_ask(verdict_answer("true_positive", 0.99), NO_AUTH_ANSWER))
        self.assertEqual(record["gate"], "review")
        self.assertIsNotNone(record["error"])

    def test_triage_evidenza_vuota_record_in_review_con_motivo(self) -> None:
        finding = {"template_id": "doc-t", "response_snippet": "", "extracted_results": []}
        record = triage_finding(finding, "r1", CONFIG, canned_ask(verdict_answer("true_positive", 0.99), NO_AUTH_ANSWER))
        self.assertEqual(record["gate"], "review")
        self.assertIsNotNone(record["error"])

    def test_triage_template_id_assente_record_in_review_mai_scartato(self) -> None:
        finding = {"matched_at": "http://192.0.2.1/", "response_snippet": "body"}
        record = triage_finding(finding, "r1", CONFIG, canned_ask(verdict_answer("true_positive", 0.99), NO_AUTH_ANSWER))
        self.assertIsNotNone(record["error"])
        self.assertIn("template_id", record["error"])
        self.assertEqual(record["gate"], "review")


class TestBearerToken(unittest.TestCase):
    """Spec 005 T021: con api_token la richiesta porta l'header Bearer; senza, non c'è."""

    def test_header_authorization_presente_solo_con_token(self) -> None:
        seen_headers = {}

        class CapturingHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                seen_headers.update(self.headers)
                body = b'{"answers": {"q": {"noul": 0.5}}}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args) -> None:
                pass

        server = HTTPServer(("127.0.0.1", 0), CapturingHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        questions = {"q": {"type": "noul", "instructions": "probe"}}
        try:
            ask(base_url, "state", questions, timeout_s=5, api_token="doc-token-1")
            self.assertEqual(seen_headers.get("Authorization"), "Bearer doc-token-1")
            seen_headers.clear()
            ask(base_url, "state", questions, timeout_s=5)
            self.assertNotIn("Authorization", seen_headers)
        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
