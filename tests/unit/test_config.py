"""Test della validazione config: ogni violazione è fatale con diagnosi precisa."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from jevsec.config import ConfigError, load_config

VALID_CONFIG = """\
[backend]
base_url = "http://127.0.0.1:8000"
timeout_s = 30.0

[thresholds]
auto_verdict = 0.80
pre_auth = 0.50
max_state_chars = 2000

[queue]
order = ["auto_tp_preauth", "review_tp", "review_uncertain", "auto_tp_no_preauth", "false_positive"]

[questions.verdict]
type = "choice"
instructions = "Classify this scanner finding."

[questions.verdict.criteria]
true_positive = "confirmed"
false_positive = "absent"
needs_review = "insufficient"

[questions.no_auth]
type = "noul"
instructions = "Pre-authentication reachability."
"""


def write_config(text: str) -> Path:
    handle = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8")
    handle.write(text)
    handle.close()
    return Path(handle.name)


class TestLoadConfig(unittest.TestCase):

    def test_load_config_config_valida_restituisce_campi(self) -> None:
        config = load_config(write_config(VALID_CONFIG))
        self.assertEqual(config.base_url, "http://127.0.0.1:8000")
        self.assertEqual(config.auto_verdict, 0.80)
        self.assertEqual(config.pre_auth, 0.50)
        self.assertEqual(config.max_state_chars, 2000)
        self.assertEqual(set(config.questions), {"verdict", "no_auth"})

    def test_load_config_file_assente_config_error(self) -> None:
        with self.assertRaises(ConfigError):
            load_config(Path("/non/esiste/live-triage.toml"))

    def test_load_config_toml_malformato_config_error(self) -> None:
        with self.assertRaises(ConfigError):
            load_config(write_config("[backend"))

    def test_load_config_auto_verdict_sopra_uno_config_error(self) -> None:
        broken = VALID_CONFIG.replace("auto_verdict = 0.80", "auto_verdict = 1.5")
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))

    def test_load_config_auto_verdict_sotto_minimo_config_error(self) -> None:
        broken = VALID_CONFIG.replace("auto_verdict = 0.80", "auto_verdict = 0.3")
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))

    def test_load_config_pre_auth_fuori_intervallo_config_error(self) -> None:
        broken = VALID_CONFIG.replace("pre_auth = 0.50", "pre_auth = -0.1")
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))

    def test_load_config_noul_con_criteria_config_error(self) -> None:
        broken = VALID_CONFIG.replace(
            '[questions.no_auth]\ntype = "noul"\ninstructions = "Pre-authentication reachability."',
            '[questions.no_auth]\ntype = "noul"\ninstructions = "Pre."\ncriteria = { x = "y" }',
        )
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))

    def test_load_config_choice_senza_criteria_config_error(self) -> None:
        broken = VALID_CONFIG.replace(
            '[questions.verdict]\ntype = "choice"',
            '[questions.verdict]\ntype = "choice"\n# criteria rimossa sotto',
        ).replace('[questions.verdict.criteria]\ntrue_positive = "confirmed"\nfalse_positive = "absent"\nneeds_review = "insufficient"\n', "")
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))

    def test_load_config_domanda_sconosciuta_config_error(self) -> None:
        broken = VALID_CONFIG + '\n[questions.severity]\ntype = "noul"\ninstructions = "severity"\n'
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))

    def test_load_config_campo_non_ammesso_config_error(self) -> None:
        broken = VALID_CONFIG.replace(
            'instructions = "Pre-authentication reachability."',
            'instructions = "Pre."\nweight = 3',
        )
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))

    def test_load_config_bucket_sconosciuto_config_error(self) -> None:
        broken = VALID_CONFIG.replace('"review_tp",', '"review_tp", "bucket_fantasma",')
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))

    def test_load_config_bucket_mancante_config_error(self) -> None:
        broken = VALID_CONFIG.replace(', "review_tp"', "")
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))

    def test_load_config_base_url_non_http_config_error(self) -> None:
        broken = VALID_CONFIG.replace('base_url = "http://127.0.0.1:8000"', 'base_url = "ftp://x"')
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))

    def test_load_config_auto_gate_enabled_non_bool_config_error(self) -> None:
        broken = VALID_CONFIG.replace("auto_verdict = 0.80", 'auto_verdict = 0.80\nauto_gate_enabled = "sì"')
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))

    def test_load_config_auto_gate_enabled_default_disarmato(self) -> None:
        config = load_config(write_config(VALID_CONFIG))
        self.assertFalse(config.auto_gate_enabled)

    def test_load_config_health_ttl_s_default_300(self) -> None:
        config = load_config(write_config(VALID_CONFIG))
        self.assertEqual(config.health_ttl_s, 300.0)

    def test_load_config_health_ttl_s_accettato(self) -> None:
        broken = VALID_CONFIG.replace("timeout_s = 30.0", "timeout_s = 30.0\nhealth_ttl_s = 60.0")
        config = load_config(write_config(broken))
        self.assertEqual(config.health_ttl_s, 60.0)

    def test_load_config_health_ttl_s_non_positivo_config_error(self) -> None:
        broken = VALID_CONFIG.replace("timeout_s = 30.0", "timeout_s = 30.0\nhealth_ttl_s = 0")
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))


class TestBackendChannel(unittest.TestCase):
    """Spec 005 US6, contratto backend-channel.md: rifiuto pre-invio, loopback ammesso."""

    BODY = """
[thresholds]
auto_verdict = 0.8
pre_auth = 0.5
max_state_chars = 2000
[queue]
order = ["auto_tp_preauth", "review_tp", "review_uncertain", "auto_tp_no_preauth", "false_positive"]
[questions.verdict]
type = "choice"
instructions = "Classify the finding."
criteria = {true_positive = "It is real.", false_positive = "It is not real.", needs_review = "Uncertain."}
[questions.no_auth]
type = "noul"
instructions = "Reachable before authentication."
"""

    def _write(self, backend_lines: str) -> Path:
        return write_config("[backend]\n" + backend_lines + self.BODY)

    def test_remote_http_rifiutata_con_messaggio_esatto(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            load_config(self._write('base_url = "http://192.0.2.50:8000"'))
        self.assertEqual(
            str(caught.exception),
            "remote backend requires https: 192.0.2.50; refused to send engagement text in clear",
        )

    def test_remote_https_senza_token_rifiutata(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            load_config(self._write('base_url = "https://192.0.2.50:8000"'))
        self.assertEqual(
            str(caught.exception),
            "remote backend requires api_token in [backend]; refused unauthenticated remote channel",
        )

    def test_remote_https_con_token_ammessa_e_token_in_config(self) -> None:
        config = load_config(self._write('base_url = "https://192.0.2.50:8000"\napi_token = "doc-token"'))
        self.assertEqual(config.api_token, "doc-token")

    def test_loopback_http_ammessa_senza_token(self) -> None:
        for base_url in ("http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000"):
            config = load_config(self._write(f'base_url = "{base_url}"'))
            self.assertIsNone(config.api_token)

    def test_messaggi_di_rifiuto_non_contengono_mai_il_token(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            load_config(self._write('base_url = "http://192.0.2.50:8000"\napi_token = "secret-doc"'))
        self.assertNotIn("secret-doc", str(caught.exception))


class TestInboxConfig(unittest.TestCase):
    """Spec 007 FR-011: sezione [inbox] opzionale, default documentati, violazioni fatali."""

    def test_inbox_assente_default_documentati(self) -> None:
        config = load_config(write_config(VALID_CONFIG))
        self.assertTrue(config.inbox.enabled)
        self.assertEqual(config.inbox.interval_s, 2.0)
        self.assertEqual(config.inbox.max_file_bytes, 2000000)
        self.assertEqual(config.inbox.stability_reads, 2)

    def test_inbox_valida_valori_letti(self) -> None:
        config = load_config(write_config(
            VALID_CONFIG + "\n[inbox]\nenabled = false\ninterval_s = 5.0\nmax_file_bytes = 1000\nstability_reads = 3\n"
        ))
        self.assertFalse(config.inbox.enabled)
        self.assertEqual(config.inbox.interval_s, 5.0)
        self.assertEqual(config.inbox.max_file_bytes, 1000)
        self.assertEqual(config.inbox.stability_reads, 3)

    def test_inbox_interval_s_zero_config_error(self) -> None:
        broken = VALID_CONFIG + "\n[inbox]\ninterval_s = 0\n"
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))

    def test_inbox_max_file_bytes_zero_config_error(self) -> None:
        broken = VALID_CONFIG + "\n[inbox]\nmax_file_bytes = 0\n"
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))

    def test_inbox_stability_reads_uno_config_error(self) -> None:
        broken = VALID_CONFIG + "\n[inbox]\nstability_reads = 1\n"
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))

    def test_inbox_enabled_non_bool_config_error(self) -> None:
        broken = VALID_CONFIG + '\n[inbox]\nenabled = "sì"\n'
        with self.assertRaises(ConfigError):
            load_config(write_config(broken))

    def test_replace_conserva_inbox(self) -> None:
        import dataclasses
        config = load_config(write_config(VALID_CONFIG + "\n[inbox]\ninterval_s = 0.05\n"))
        patched = dataclasses.replace(config, base_url="http://127.0.0.1:9999")
        self.assertEqual(patched.inbox.interval_s, 0.05)
        self.assertEqual(patched.base_url, "http://127.0.0.1:9999")


if __name__ == "__main__":
    unittest.main()
