"""Test della redazione: selezione campi, truncation, hex, base64, determinismo."""

from __future__ import annotations

import unittest

from jevsec.redact import (
    BLOB_PLACEHOLDER,
    HEX_PLACEHOLDER,
    TRUNCATION_MARKER,
    build_state,
    redact_text,
)

LONG_TEXT = ("realistic response body line with spaces and punctuation 42.\r\n" * 60)[:2500]
HEX_16 = "0123456789abcdef"
HEX_8 = "01234567"
BASE64_BLOB = "Y29uZmlndXJhdGlvbi1ibG9iLWRvY3VtZW50YXppb25hbGUtMjY="


class TestRedactText(unittest.TestCase):

    def test_redact_text_hex_lungo_sostituito(self) -> None:
        redacted, was_truncated = redact_text(f"digest {HEX_16} listed", 2000)
        self.assertIn(HEX_PLACEHOLDER, redacted)
        self.assertNotIn(HEX_16, redacted)
        self.assertFalse(was_truncated)

    def test_redact_text_hex_corto_conservato(self) -> None:
        redacted, _ = redact_text(f"prefix {HEX_8} suffix", 2000)
        self.assertIn(HEX_8, redacted)
        self.assertNotIn(HEX_PLACEHOLDER, redacted)

    def test_redact_text_blob_base64_sostituito(self) -> None:
        redacted, _ = redact_text(f"config {BASE64_BLOB} end", 2000)
        self.assertIn(BLOB_PLACEHOLDER, redacted)

    def test_redact_text_oltre_limite_troncato_con_marcatore(self) -> None:
        redacted, was_truncated = redact_text(LONG_TEXT, 2000)
        self.assertTrue(was_truncated)
        self.assertTrue(redacted.endswith(TRUNCATION_MARKER))
        self.assertEqual(len(redacted), len(LONG_TEXT[:2000]) + len(TRUNCATION_MARKER))


class TestBuildState(unittest.TestCase):

    def test_build_state_solo_campi_giudicabili_passano(self) -> None:
        finding = {
            "template_id": "doc-t",
            "matched_at": "http://192.0.2.1/",
            "matcher_status": True,
            "response_snippet": "body",
            "extracted_results": ["proof"],
            "info": {"severity": "high"},
            "campo_inventato": "non deve passare",
        }
        state, _ = build_state(finding, 2000)
        self.assertEqual(set(state), {"template_id", "matched_at", "response_snippet", "extracted_results"})

    def test_build_state_finding_vuoto_state_vuoto(self) -> None:
        state, was_truncated = build_state({}, 2000)
        self.assertEqual(state, {})
        self.assertFalse(was_truncated)

    def test_build_state_snippet_lungo_truncated_vero(self) -> None:
        finding = {"template_id": "doc-t", "response_snippet": LONG_TEXT}
        state, was_truncated = build_state(finding, 2000)
        self.assertTrue(was_truncated)
        self.assertTrue(state["response_snippet"].endswith(TRUNCATION_MARKER))

    def test_build_state_pura_stesso_input_stesso_output(self) -> None:
        finding = {"template_id": "doc-t", "response_snippet": f"x {HEX_16} y", "extracted_results": [BASE64_BLOB]}
        first = build_state(finding, 200)
        second = build_state(finding, 200)
        self.assertEqual(first, second)

    def test_build_state_extracted_results_redatti(self) -> None:
        finding = {"template_id": "doc-t", "extracted_results": [HEX_16]}
        state, _ = build_state(finding, 2000)
        self.assertEqual(state["extracted_results"], [HEX_PLACEHOLDER])


if __name__ == "__main__":
    unittest.main()
