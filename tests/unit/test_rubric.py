"""Test rubric.py: validazione loader, applicazione regole, rubrica dichiarata."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from jevsec.rubric import RubricError, apply_rules, load_rubric

VALID_CONFIG = """\
[backend]
base_url = "http://127.0.0.1:8000"

[thresholds]
max_state_chars = 2000
default_condition = 0.5

[objective_names]
test_obj = "Test objective sentence."

[objectives.test_obj.questions.has_creds]
type = "noul"
instructions = "The observation exposes usable authentication material."

[objectives.test_obj.questions.is_priv]
type = "noul"
instructions = "The account carries administrative privileges."

[[objectives.test_obj.rules]]
name = "priv_creds"
score = 4
conditions = { has_creds = 0.5, is_priv = 0.5 }

[[objectives.test_obj.rules]]
name = "any_creds"
score = 2
conditions = { has_creds = 0.5 }

[objectives.test_obj.default_rule]
name = "no_signal"
score = 0
"""


def write_config(text: str) -> Path:
    handle = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8")
    handle.write(text)
    handle.close()
    return Path(handle.name)


class TestLoadRubric(unittest.TestCase):

    def test_load_rubric_config_valida(self) -> None:
        config = load_rubric(write_config(VALID_CONFIG))
        self.assertIn("test_obj", config.objectives)
        rubric = config.objectives["test_obj"]
        self.assertEqual(len(rubric.rules), 2)
        self.assertEqual(rubric.default_rule.name, "no_signal")

    def test_load_rubric_domanda_non_noul_errore(self) -> None:
        broken = VALID_CONFIG.replace('type = "noul"\ninstructions = "The observation exposes', 'type = "choice"\ninstructions = "The observation exposes')
        with self.assertRaises(RubricError):
            load_rubric(write_config(broken))

    def test_load_rubric_condizione_domanda_inesistente_errore(self) -> None:
        broken = VALID_CONFIG.replace("conditions = { has_creds = 0.5 }", "conditions = { fantasma = 0.5 }")
        with self.assertRaises(RubricError):
            load_rubric(write_config(broken))

    def test_load_rubric_score_fuori_range_errore(self) -> None:
        broken = VALID_CONFIG.replace("score = 4", "score = 7")
        with self.assertRaises(RubricError):
            load_rubric(write_config(broken))

    def test_load_rubric_default_rule_mancante_errore(self) -> None:
        broken = VALID_CONFIG.replace('[objectives.test_obj.default_rule]\nname = "no_signal"\nscore = 0\n', "")
        with self.assertRaises(RubricError):
            load_rubric(write_config(broken))

    def test_load_rubric_soglia_fuori_intervallo_errore(self) -> None:
        broken = VALID_CONFIG.replace("conditions = { has_creds = 0.5, is_priv = 0.5 }", "conditions = { has_creds = 1.4, is_priv = 0.5 }")
        with self.assertRaises(RubricError):
            load_rubric(write_config(broken))

    def test_load_rubric_obiettivo_sconosciuto(self) -> None:
        config = load_rubric(write_config(VALID_CONFIG))
        self.assertNotIn("king_of_the_hill", config.objectives)


class TestApplyRules(unittest.TestCase):

    def setUp(self) -> None:
        self.config = load_rubric(write_config(VALID_CONFIG))
        self.rubric = self.config.objectives["test_obj"]

    def test_apply_rules_regola_massima_attiva_vince(self) -> None:
        active, winner = apply_rules({"has_creds": 0.8, "is_priv": 0.7}, self.rubric)
        self.assertEqual(winner.name, "priv_creds")
        self.assertEqual([r.name for r in active], ["priv_creds", "any_creds"])

    def test_apply_rules_sotto_soglia_regola_inattiva(self) -> None:
        active, winner = apply_rules({"has_creds": 0.49}, self.rubric)
        self.assertEqual(winner.name, "no_signal")
        self.assertEqual(active, [])

    def test_apply_rules_condizioni_multiple_tutti_requisiti(self) -> None:
        active, winner = apply_rules({"has_creds": 0.9, "is_priv": 0.3}, self.rubric)
        self.assertEqual(winner.name, "any_creds")
        self.assertEqual(len(active), 1)

    def test_apply_rules_nessun_giudizio_default(self) -> None:
        active, winner = apply_rules({}, self.rubric)
        self.assertEqual(winner.name, "no_signal")

    def test_apply_rules_parita_vince_prima_dichiarata(self) -> None:
        extra = VALID_CONFIG + """
[[objectives.test_obj.rules]]
name = "altra_alta"
score = 4
conditions = { is_priv = 0.5 }
"""
        rubric = load_rubric(write_config(extra)).objectives["test_obj"]
        _, winner = apply_rules({"has_creds": 0.9, "is_priv": 0.9}, rubric)
        self.assertEqual(winner.name, "priv_creds")


class TestRubricaDichiarata(unittest.TestCase):
    """User Story 2: cambiare la rubrica cambia il punteggio, codice invariato."""

    def test_modifica_soglia_cambia_esito_senza_codice(self) -> None:
        base = {"has_creds": 0.6, "is_priv": 0.6}
        before = apply_rules(base, load_rubric(write_config(VALID_CONFIG)).objectives["test_obj"])
        stricter = VALID_CONFIG.replace(
            "conditions = { has_creds = 0.5, is_priv = 0.5 }",
            "conditions = { has_creds = 0.7, is_priv = 0.7 }",
        )
        after = apply_rules(base, load_rubric(write_config(stricter)).objectives["test_obj"])
        self.assertEqual(before[1].name, "priv_creds")
        self.assertEqual(after[1].name, "any_creds")  # priv_creds non piu attiva a soglia 0.7

    def test_aggiunta_regola_cambia_vincitore(self) -> None:
        base = {"has_creds": 0.6, "is_priv": 0.0}
        extra = VALID_CONFIG + """
[[objectives.test_obj.rules]]
name = "creds_for_win"
score = 4
conditions = { has_creds = 0.55 }
"""
        rubric = load_rubric(write_config(extra)).objectives["test_obj"]
        _, winner = apply_rules(base, rubric)
        self.assertEqual(winner.name, "creds_for_win")


class TestCustomObjective(unittest.TestCase):
    """Spec 005 US5: obiettivi personalizzati dichiarativi, config incompleta rifiutata."""

    CUSTOM = """[backend]
base_url = "http://127.0.0.1:8000"

[thresholds]
max_state_chars = 2000
default_condition = 0.5

[objectives.exfil_path.questions.q_egress]
type = "noul"
instructions = "The observation mentions an outbound channel usable to move data out."

[objectives.exfil_path.questions.q_reachable]
type = "noul"
instructions = "The described outbound channel can actually be reached from the current position."

[[objectives.exfil_path.rules]]
name = "exfil_ready"
score = 3
conditions = { q_egress = 0.5, q_reachable = 0.5 }

[[objectives.exfil_path.rules]]
name = "channel_spotted"
score = 1
conditions = { q_egress = 0.5 }

[objectives.exfil_path.default_rule]
name = "no_signal"
score = 0
"""

    def test_obiettivo_custom_completo_carica_e_ricombina(self) -> None:
        rubric = load_rubric(write_config(self.CUSTOM)).objectives["exfil_path"]
        _, winner = apply_rules({"q_egress": 0.9, "q_reachable": 0.8}, rubric)
        self.assertEqual((winner.name, winner.score), ("exfil_ready", 3))
        _, winner = apply_rules({"q_egress": 0.9, "q_reachable": 0.1}, rubric)
        self.assertEqual((winner.name, winner.score), ("channel_spotted", 1))
        _, winner = apply_rules({"q_egress": 0.2, "q_reachable": 0.9}, rubric)
        self.assertEqual((winner.name, winner.score), ("no_signal", 0))

    def test_obiettivo_custom_senza_rules_rifiutato_nomina_obiettivo_e_campo(self) -> None:
        broken = """[backend]
base_url = "http://127.0.0.1:8000"

[thresholds]
max_state_chars = 2000
default_condition = 0.5

[objectives.exfil_path.questions.q_egress]
type = "noul"
instructions = "The observation mentions an outbound channel usable to move data out."

[objectives.exfil_path.default_rule]
name = "no_signal"
score = 0
"""
        with self.assertRaises(RubricError) as caught:
            load_rubric(write_config(broken))
        message = str(caught.exception)
        self.assertIn("exfil_path", message)
        self.assertIn("rules", message)

    def test_obiettivo_custom_senza_domande_rifiutato(self) -> None:
        broken = """[backend]
base_url = "http://127.0.0.1:8000"

[thresholds]
max_state_chars = 2000
default_condition = 0.5

[[objectives.exfil_path.rules]]
name = "always"
score = 1
conditions = { q_egress = 0.5 }

[objectives.exfil_path.default_rule]
name = "no_signal"
score = 0
"""
        with self.assertRaises(RubricError) as caught:
            load_rubric(write_config(broken))
        self.assertIn("questions", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
