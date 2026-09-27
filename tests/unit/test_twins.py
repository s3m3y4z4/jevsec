"""Coppie gemelle: generatore dichiarativo, augmentation cappata e solo-train, misura di divergenza (fase 2.3)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "tools"))

import build_training_data as btd  # noqa: E402
import make_twin_pairs as mtp  # noqa: E402
import run_sentinelle as rs  # noqa: E402
from jevsec.rubric import load_rubric  # noqa: E402

TWIN_FILE = REPO_ROOT / "data" / "twins" / "twin-pairs-v001.jsonl"


class TestGeneratore(unittest.TestCase):
    def test_deterministico_e_bersagli_rfc(self) -> None:
        first, second = mtp.build_pairs(), mtp.build_pairs()
        self.assertEqual(first, second)
        mtp.check(first)  # coerenza con la rubrica + id unici + varies chiuso
        for pair in first:
            text = pair["variant_a"]["text"] + pair["variant_b"]["text"]
            self.assertNotRegex(text, r"\b(?!192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)\d+\.\d+\.\d+\.\d+\b")

    def test_check_rifiuta_varies_aperto(self) -> None:
        pairs = mtp.build_pairs()
        pairs[0]["varies"] = ["typography"]
        with self.assertRaises(SystemExit):
            mtp.check(pairs)

    def test_check_rifiuta_atteso_incoerente(self) -> None:
        pairs = mtp.build_pairs()
        # is_reachable è nelle condizioni della regola vincitrice: flipparlo cambia l'impact
        # (quick_win non è in nessuna regola: flipparlo NON deve far fallire il check)
        pairs[0]["expected"]["is_reachable"] = 1 - pairs[0]["expected"]["is_reachable"]
        with self.assertRaises(SystemExit):
            mtp.check(pairs)
        sane = mtp.build_pairs()
        sane[0]["expected"]["quick_win"] = 1 - sane[0]["expected"]["quick_win"]
        sane[0]["expected_impact"] = next(p for p in mtp.build_pairs() if p["id"] == sane[0]["id"])["expected_impact"]
        mtp.check(sane)  # quick_win non influenza le regole: resta coerente


class TestAugmentation(unittest.TestCase):
    def test_twin_augment_solo_train_e_cappato(self) -> None:
        from collections import Counter
        rubric = load_rubric(REPO_ROOT / "config" / "prioritization.toml")
        user_flag_pair = next(pair for pair in mtp.build_pairs() if pair["objective"] == "user_flag")
        rce_pair = next(pair for pair in mtp.build_pairs() if pair["objective"] == "rce_app")
        with tempfile.TemporaryDirectory() as tmp:
            twin_path = Path(tmp) / "twins.jsonl"
            with twin_path.open("w", encoding="utf-8") as handle:
                for pair in (user_flag_pair, rce_pair):
                    handle.write(json.dumps(pair) + "\n")
            splits, manifest = btd.build_dataset(REPO_ROOT, twin_pairs=twin_path)
        twin_rows = [row for row in splits["train"] if ":twin:" in row["id"]]
        self.assertTrue(twin_rows)
        self.assertFalse(any(":twin:" in row["id"] for row in splits["dev"] + splits["calibration"]))
        per_variant = Counter(row["id"].split(":twin:")[-1] for row in twin_rows)
        present = set(per_variant)
        for pair in (user_flag_pair, rce_pair):
            variant_ids = {pair["variant_a"]["id"], pair["variant_b"]["id"]}
            if variant_ids & present:
                self.assertEqual(variant_ids & present, variant_ids, "mai un membro senza il suo gemello")
                declared = len(pair["expected"])
                for variant_id in variant_ids:
                    self.assertEqual(per_variant[variant_id], declared)
        train_before = len(splits["train"]) - len(twin_rows)
        self.assertLessEqual(len(twin_rows), int(train_before * btd.TWIN_CAP_SHARE), "cap 5% superato")
        self.assertIn("twin_augmentation", manifest)
        self.assertEqual(set(manifest["twin_augmentation"]["twin_ids"]), present)

    def test_twin_augment_off_default_manifest_senza_twin_ids(self) -> None:
        splits, manifest = btd.build_dataset(REPO_ROOT)
        self.assertNotIn("twin_augmentation", manifest)
        self.assertFalse(any(":twin:" in row["id"] for name in splits for row in splits[name]))


class TestDivergenza(unittest.TestCase):
    def test_twin_divergence_max_delta_e_flip_con_ask_fn_divergente(self) -> None:
        rubric = load_rubric(REPO_ROOT / "config" / "prioritization.toml")
        pairs = mtp.build_pairs()[:1]  # coppia filename-heuristic: A "login-form.css", B "theme-base.css"

        def hostile_ask(base_url, state, questions, timeout_s, api_token=None, model=None):
            value = 0.9 if "login-form" in state.get("text", "") else 0.1
            answers = {name: {"type": "noul", "noul": value} for name in questions}
            return {"model": "fake", "answers": answers, "usage": {}}, 0.01

        with mock.patch.object(rs, "ask", hostile_ask):
            evaluation = rs.evaluate_twins(pairs, rs.run_twins(pairs, rubric, "http://127.0.0.1:9"))
        self.assertEqual(evaluation["pairs"], 1)
        self.assertEqual(evaluation["clean_pairs"], 0)  # flip su ogni domanda: A sì B no
        entry = evaluation["per_pair"][pairs[0]["id"]]
        self.assertGreaterEqual(entry["max_delta"], 0.7)
        self.assertTrue(all(detail["flip"] for detail in entry["questions"].values()))

    def test_twin_divergence_invariante_con_ask_fn_stabile(self) -> None:
        rubric = load_rubric(REPO_ROOT / "config" / "prioritization.toml")
        pairs = mtp.build_pairs()[:1]

        def stable_ask(base_url, state, questions, timeout_s, api_token=None, model=None):
            answers = {name: {"type": "noul", "noul": 0.7} for name in questions}
            return {"model": "fake", "answers": answers, "usage": {}}, 0.01

        with mock.patch.object(rs, "ask", stable_ask):
            evaluation = rs.evaluate_twins(pairs, rs.run_twins(pairs, rubric, "http://127.0.0.1:9"))
        self.assertEqual(evaluation["clean_pairs"], 1)
        entry = evaluation["per_pair"][pairs[0]["id"]]
        self.assertEqual(entry["max_delta"], 0.0)

    def test_soglia_pre_dichiarata_nell_header(self) -> None:
        lines = rs.report_twins_block({"per_pair": {}, "pairs": 0, "clean_pairs": 0, "clean_share": 0.0})
        self.assertIn("pre-registrate", "\n".join(lines))
        self.assertIn(str(rs.TWIN_DELTA_LIMIT), "\n".join(lines))


if __name__ == "__main__":
    unittest.main()
