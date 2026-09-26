"""Test severity dalla fonte e audit: set esatto di domande, purezza, truncated."""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

import sys

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from jevsec.config import load_config  # noqa: E402
from jevsec.redact import build_state  # noqa: E402
from jevsec.triage import triage_finding  # noqa: E402

CONFIG = load_config(REPO_ROOT / "config" / "live-triage.toml")

CAPTURED: dict[str, Any] = {}


def capturing_ask(base_url: str, state: dict, questions: dict, timeout_s: float, api_token: str | None = None, model: str = "jev-latest") -> tuple[dict, float]:
    CAPTURED["state"] = state
    CAPTURED["questions"] = questions
    return (
        {
            "model": "canned",
            "answers": {
                "verdict": {"type": "choice", "choice": "true_positive",
                            "probabilities": {"true_positive": 0.9, "false_positive": 0.05, "needs_review": 0.05}},
                "no_auth": {"type": "noul", "noul": 0.8},
            },
        },
        0.001,
    )


class TestSeverityFromSource(unittest.TestCase):

    def test_triage_severity_della_fonte_copiata_domande_esatte(self) -> None:
        finding = {"template_id": "doc-t", "response_snippet": "body", "info": {"severity": "high"}}
        record = triage_finding(finding, "r1", CONFIG, capturing_ask)
        self.assertEqual(record["severity"], "high")
        self.assertEqual(set(CAPTURED["questions"]), {"verdict", "no_auth"})

    def test_triage_senza_severity_null_nessuna_domanda_severity(self) -> None:
        finding = {"template_id": "doc-t", "response_snippet": "body"}
        record = triage_finding(finding, "r1", CONFIG, capturing_ask)
        self.assertIsNone(record["severity"])
        self.assertNotIn("severity", CAPTURED["questions"])


class TestAuditReconstruction(unittest.TestCase):

    def test_redact_pura_payload_byte_identico(self) -> None:
        finding = {"template_id": "doc-t", "response_snippet": "x 0123456789abcdef y", "extracted_results": ["Y29uZmlndXJhdGlvbi1ibG9iLWRvY3VtZW50YXppb25hbGUtMjY="]}
        self.assertEqual(build_state(finding, CONFIG.max_state_chars), build_state(finding, CONFIG.max_state_chars))

    def test_triage_state_inviato_uguale_a_redazione_dichiarata(self) -> None:
        finding = {"template_id": "doc-t", "response_snippet": "digest 0123456789abcdef end",
                   "altro_campo": "che non deve arrivare al motore"}
        triage_finding(finding, "r1", CONFIG, capturing_ask)
        expected_state, _ = build_state(finding, CONFIG.max_state_chars)
        self.assertEqual(CAPTURED["state"], expected_state)
        self.assertNotIn("altro_campo", CAPTURED["state"])

    def test_triage_truncated_true_solo_se_troncamento_avvenuto(self) -> None:
        long_body = ("riga realistica di risposta con spazi e punteggiatura.\r\n" * 120)[:2500]
        short_body = "banner breve"
        long_record = triage_finding({"template_id": "doc-l", "response_snippet": long_body}, "r1", CONFIG, capturing_ask)
        short_record = triage_finding({"template_id": "doc-s", "response_snippet": short_body}, "r2", CONFIG, capturing_ask)
        self.assertTrue(long_record["truncated"])
        self.assertFalse(short_record["truncated"])


if __name__ == "__main__":
    unittest.main()
