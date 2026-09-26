"""Test dell'ordinamento coda: bucket, probabilità, parità."""

from __future__ import annotations

import unittest

from jevsec.queue import bucket_of, sort_records

ORDER = ("auto_tp_preauth", "review_tp", "review_uncertain", "auto_tp_no_preauth", "false_positive")


def record(ref: str, verdict: str | None, probability: float | None, gate: str = "review",
           no_auth: bool | None = None, error: str | None = None) -> dict:
    return {
        "finding_ref": ref,
        "verdict": verdict,
        "verdict_probability": probability,
        "gate": gate,
        "no_auth": no_auth,
        "error": error,
    }


class TestBucketOf(unittest.TestCase):

    def test_bucket_of_auto_tp_preauth_bucket_corretto(self) -> None:
        self.assertEqual(bucket_of(record("r", "true_positive", 0.9, gate="auto", no_auth=True)), "auto_tp_preauth")

    def test_bucket_of_auto_tp_dietro_auth_bucket_corretto(self) -> None:
        self.assertEqual(bucket_of(record("r", "true_positive", 0.9, gate="auto", no_auth=False)), "auto_tp_no_preauth")

    def test_bucket_of_tp_in_review_bucket_corretto(self) -> None:
        self.assertEqual(bucket_of(record("r", "true_positive", 0.6, gate="review")), "review_tp")

    def test_bucket_of_needs_review_bucket_uncertain(self) -> None:
        self.assertEqual(bucket_of(record("r", "needs_review", 0.4)), "review_uncertain")

    def test_bucket_of_errore_bucket_uncertain(self) -> None:
        self.assertEqual(bucket_of(record("r", None, None, error="connessione")), "review_uncertain")

    def test_bucket_of_false_positive_bucket_fp(self) -> None:
        self.assertEqual(bucket_of(record("r", "false_positive", 0.7, gate="auto")), "false_positive")


class TestSortRecords(unittest.TestCase):

    def test_sort_records_ordinamento_tra_bucket(self) -> None:
        records = [
            record("5-fp", "false_positive", 0.9),
            record("4-auto-noauth", "true_positive", 0.95, gate="auto", no_auth=False),
            record("3-uncertain", "needs_review", 0.5),
            record("2-review-tp", "true_positive", 0.6),
            record("1-auto", "true_positive", 0.9, gate="auto", no_auth=True),
        ]
        ordered = sort_records(records, ORDER)
        self.assertEqual([r["finding_ref"] for r in ordered],
                         ["1-auto", "2-review-tp", "3-uncertain", "4-auto-noauth", "5-fp"])

    def test_sort_records_dentro_bucket_probabilita_decrescente(self) -> None:
        records = [
            record("low", "true_positive", 0.55),
            record("high", "true_positive", 0.75),
            record("mid", "true_positive", 0.65),
        ]
        ordered = sort_records(records, ORDER)
        self.assertEqual([r["finding_ref"] for r in ordered], ["high", "mid", "low"])

    def test_sort_records_parita_probabilita_ordine_per_finding_ref(self) -> None:
        records = [
            record("b", "true_positive", 0.6),
            record("a", "true_positive", 0.6),
        ]
        ordered = sort_records(records, ORDER)
        self.assertEqual([r["finding_ref"] for r in ordered], ["a", "b"])

    def test_sort_records_probabilita_nulla_dentro_bucket(self) -> None:
        records = [
            record("con-p", "true_positive", 0.6),
            record("senza-p", None, None, error="x"),
        ]
        ordered = sort_records(records, ORDER)
        self.assertEqual(ordered[0]["finding_ref"], "con-p")


if __name__ == "__main__":
    unittest.main()
