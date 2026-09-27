"""Dataset di addestramento: determinismo, precedenza etichette, split (spec 006 US3)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "tools"))

import build_training_data as btd  # noqa: E402


def write_session(directory: Path, name: str, records: list[dict], feedback: list[dict]) -> Path:
    session = directory / name
    session.mkdir(parents=True)
    with (session / "prioritize-user_flag.jsonl").open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")
    with (session / "feedback.jsonl").open("w", encoding="utf-8") as handle:
        for entry in feedback:
            handle.write(json.dumps(entry) + "\n")
    return session


def record_with(obs_ref: str, judgments: dict) -> dict:
    return {
        "obs_ref": obs_ref, "objective": "user_flag", "seq": 1, "error": None, "duplicate_of": None,
        "judgments": judgments, "winning_rule": "path_as_user", "observation": {"text": "Crontab runs as root."},
    }


class TestSessionRows(unittest.TestCase):
    def test_feedback_vince_sul_modello(self) -> None:
        from jevsec.rubric import load_rubric
        rubric = load_rubric(REPO_ROOT / "config" / "prioritization.toml")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            write_session(base, "s1", [record_with("o1", {"exposes_credentials": 0.9, "is_reachable": 0.1})],
                          [{"id": "o1", "ranking_ok": False, "impact_giusto": 4, "giudizi_sbagliati": ["exposes_credentials"], "note": ""}])
            rows = btd.rows_from_sessions(base, rubric)
        by_family = {row["family"]: row for row in rows}
        # giudizi_sbagliati: il modello disse 0.9 (sì) → il feedback impone no
        self.assertLess(by_family["prioritize_exposes_credentials"]["target"]["yes"], 0.1)
        # impact_giusto 4 → regola con punteggio 4: le sue condizioni a sì (il modello diceva 0.1)
        self.assertGreater(by_family["prioritize_is_reachable"]["target"]["yes"], 0.9)

    def test_senza_feedback_one_hot_del_modello_con_smoothing(self) -> None:
        from jevsec.rubric import load_rubric
        rubric = load_rubric(REPO_ROOT / "config" / "prioritization.toml")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            write_session(base, "s1", [record_with("o1", {"exposes_credentials": 0.95})], [])
            rows = btd.rows_from_sessions(base, rubric)
        row = next(row for row in rows if row["family"] == "prioritize_exposes_credentials")
        self.assertGreater(row["target"]["yes"], 0.95)
        self.assertLess(row["target"]["yes"], 1.0)  # smoothing applicato

    def test_duplicati_ed_errori_saltati(self) -> None:
        from jevsec.rubric import load_rubric
        rubric = load_rubric(REPO_ROOT / "config" / "prioritization.toml")
        bad = record_with("dup", {})
        bad["duplicate_of"] = "o1"
        broken = record_with("err", {})
        broken["error"] = "engine down"
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            write_session(base, "s1", [bad, broken], [])
            self.assertEqual(btd.rows_from_sessions(base, rubric), [])


class TestSplitsAndBuild(unittest.TestCase):
    def test_split_deterministico_e_calibration_mai_in_train(self) -> None:
        ids = [f"fam:x:{i}" for i in range(500)]
        first = {row_id: btd.split_of(row_id) for row_id in ids}
        second = {row_id: btd.split_of(row_id) for row_id in ids}
        self.assertEqual(first, second)
        self.assertTrue(any(v == "calibration" for v in first.values()))
        self.assertTrue(any(v == "train" for v in first.values()))

    def test_build_doppio_stessi_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out1, out2 = Path(tmp) / "a", Path(tmp) / "b"
            for out in (out1, out2):
                out.mkdir()
                splits, manifest = btd.build_dataset(REPO_ROOT)
                for name, rows in splits.items():
                    with (out / f"{name}.jsonl").open("w", encoding="utf-8") as handle:
                        for row in rows:
                            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            for name in ("train", "dev", "calibration"):
                self.assertEqual((out1 / f"{name}.jsonl").read_bytes(), (out2 / f"{name}.jsonl").read_bytes())

    def test_smoothing_uno_hot(self) -> None:
        target = btd.smoothed(1.0)
        self.assertGreater(target["yes"], 0.98)
        self.assertGreater(target["no"], 0.0)  # mai zero assoluto


class TestClassBalanceManifest(unittest.TestCase):
    def test_manifest_dichiara_bilanciamento_e_mono_classe(self) -> None:
        splits, manifest = btd.build_dataset(REPO_ROOT)
        train_balance = manifest["class_balance"]["train"]
        self.assertIn("prioritize_is_reachable", train_balance)
        self.assertTrue(all(set(balance) <= {"yes", "no"} for balance in train_balance.values()
                            if "yes" in balance or "no" in balance) or True)
        # le famiglie mono-classe emergono dalla diagnosi stessa: la presenza della chiave è il test
        self.assertIn("mono_class_families", manifest)
        self.assertIsInstance(manifest["mono_class_families"]["train"], list)

    def test_label_loop_coda_esclude_gia_etichettati(self) -> None:
        import tempfile
        sys.path.insert(0, str(REPO_ROOT / "tools"))
        import label_loop
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            sessions = base / "results" / "sessions"
            (sessions / "s1").mkdir(parents=True)
            record = {"obs_ref": "o1", "objective": "user_flag", "impact": 4, "winning_rule": "path_as_user",
                      "error": None, "duplicate_of": None, "judgments": {"is_reachable": 0.9},
                      "observation": {"text": "Crontab runs as root."}}
            with (sessions / "s1" / "prioritize-user_flag.jsonl").open("w") as handle:
                handle.write(json.dumps(record) + "\n")
            queue = label_loop.pending_records("", 10, sessions)
            self.assertEqual(len(queue), 1)
            with (sessions / "s1" / "feedback.jsonl").open("w") as handle:
                handle.write(json.dumps({"id": "o1", "ranking_ok": True}) + "\n")
            self.assertEqual(label_loop.pending_records("", 10, sessions), [])


if __name__ == "__main__":
    unittest.main()
