"""Azioni assistite: config, target, proposta (spec 006 US1, contratto actions.md)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import sys

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from jevsec.actions import (  # noqa: E402
    ActionConfigError,
    ActionsConfig,
    load_actions_config,
    proposal_for,
    target_from_url,
    target_in_scope,
)

EXAMPLE = REPO_ROOT / "config" / "examples" / "actions.toml"


def write_config(text: str) -> Path:
    handle = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8")
    handle.write(text)
    handle.close()
    return Path(handle.name)


VALID = """\
[triage.review_tp]
description = "Verify the surface"
command = ["nmap", "-sV", "-p", "{port}", "{host}"]

[prioritize.credentials]
description = "Verify reuse"
suggestion = "Try the credentials on in-scope services"

[allowlist]
tools = ["nmap"]

[scope]
targets = ["192.0.2.0/24"]

[execution]
timeout_s = 60
"""


class TestActionsConfig(unittest.TestCase):
    def test_config_valida_carica_tutto(self) -> None:
        config = load_actions_config(write_config(VALID))
        self.assertIn("review_tp", config.triage)
        self.assertIn("credentials", config.prioritize)
        self.assertEqual(config.tools, ("nmap",))
        self.assertTrue(config.enabled)
        self.assertEqual(config.timeout_s, 60.0)

    def test_config_assente_disabilita_ma_le_proposte_restano_possibili(self) -> None:
        config = load_actions_config(Path("/nonexistent/actions.toml"))
        self.assertFalse(config.enabled)
        self.assertEqual(config.triage, {})

    def test_placeholder_sconosciuto_rifiuta_nomina_template(self) -> None:
        broken = VALID.replace('"{port}", "{host}"', '"{port}", "{host}", "{fantasma}"')
        with self.assertRaises(ActionConfigError) as caught:
            load_actions_config(write_config(broken))
        message = str(caught.exception)
        self.assertIn("triage.review_tp", message)
        self.assertIn("fantasma", message)

    def test_percent_placeholder_dello_strumento_e_ammesso(self) -> None:
        extra = VALID.replace('command = ["nmap", "-sV", "-p", "{port}", "{host}"]',
                              'command = ["curl", "-w", "%{http_code}", "{scheme}://{host}:{port}"]')
        config = load_actions_config(write_config(extra))
        self.assertIn("curl", config.triage["review_tp"].command)  # %{http_code} non è un nostro placeholder

    def test_command_e_suggestion_insieme_rifiutati(self) -> None:
        both = """\
[triage.review_tp]
description = "Both"
command = ["echo", "{host}"]
suggestion = "also text"

[allowlist]
tools = ["echo"]
"""
        with self.assertRaises(ActionConfigError) as caught:
            load_actions_config(write_config(both))
        self.assertIn("mutually exclusive", str(caught.exception))

    def test_bucket_inesistente_rifiutato(self) -> None:
        broken = VALID.replace("[triage.review_tp]", "[triage.nessun_bucket]")
        with self.assertRaises(ActionConfigError) as caught:
            load_actions_config(write_config(broken))
        self.assertIn("nessun_bucket", str(caught.exception))

    def test_scope_invalido_rifiutato(self) -> None:
        broken = VALID.replace('targets = ["192.0.2.0/24"]', 'targets = ["192.0.2.0/24", "non un target"]')
        with self.assertRaises(ActionConfigError):
            load_actions_config(write_config(broken))

    def test_esempio_esportato_inerte(self) -> None:
        config = load_actions_config(EXAMPLE)
        self.assertEqual(config.tools, ())
        self.assertFalse(config.enabled)
        self.assertEqual(len(config.triage), 5)
        self.assertEqual(len(config.prioritize), 2)


class TestTarget(unittest.TestCase):
    def test_url_completa_riempie_tutti_i_campi(self) -> None:
        target = target_from_url("https://192.0.2.10:8443/admin/login")
        self.assertEqual(target, {"host": "192.0.2.10", "port": "8443", "scheme": "https", "path": "admin/login"})

    def test_senza_porta_usa_default_dello_schema(self) -> None:
        self.assertEqual(target_from_url("http://www.example.com/x")["port"], "80")
        self.assertEqual(target_from_url("https://www.example.com")["port"], "443")

    def test_non_url_none(self) -> None:
        self.assertIsNone(target_from_url("not a url"))
        self.assertIsNone(target_from_url(""))

    def test_scope_cidr_e_suffisso(self) -> None:
        scope = ("192.0.2.0/24", ".example.com")
        self.assertTrue(target_in_scope("192.0.2.10", scope))
        self.assertFalse(target_in_scope("203.0.113.9", scope))
        self.assertTrue(target_in_scope("app.example.com", scope))
        self.assertFalse(target_in_scope("app.example.org", scope))
        self.assertFalse(target_in_scope("192.0.2.10", ()))  # scope assente: tutto fuori


class TestProposal(unittest.TestCase):
    CONFIG = load_actions_config(EXAMPLE)

    def test_proposta_triage_con_target_riempie_argv(self) -> None:
        record = {"target": {"host": "192.0.2.10", "port": "443", "scheme": "https", "path": "admin"}}
        proposal = proposal_for(record, self.CONFIG, bucket="review_tp")
        self.assertEqual(proposal["argv"], ["nmap", "-sV", "-p", "443", "192.0.2.10"])
        self.assertEqual(proposal["template"], "triage.review_tp")

    def test_proposta_triage_senza_target_assenza_dichiarata(self) -> None:
        self.assertIsNone(proposal_for({"target": None}, self.CONFIG, bucket="review_tp"))

    def test_placeholder_non_risolvibile_null(self) -> None:
        record = {"target": {"host": "192.0.2.10", "scheme": "https", "path": ""}}  # manca port
        self.assertIsNone(proposal_for(record, self.CONFIG, bucket="review_tp"))

    def test_proposta_prioritize_da_regola_vincitrice(self) -> None:
        proposal = proposal_for({"winning_rule": "credentials"}, self.CONFIG)
        self.assertEqual(proposal["template"], "prioritize.credentials")
        self.assertIn("suggestion", proposal)
        self.assertNotIn("argv", proposal)

    def test_regola_senza_template_null(self) -> None:
        self.assertIsNone(proposal_for({"winning_rule": "qualunque_altra"}, self.CONFIG))

    def test_record_vecchio_senza_target_suggestion_resta_possibile(self) -> None:
        proposal = proposal_for({"winning_rule": "credentials", "target": None}, self.CONFIG)
        self.assertIsNotNone(proposal)


EXEC_CONFIG = """\
[triage.review_tp]
description = "Echo probe"
command = ["@@TOOL@@", "probe", "{host}"]

[allowlist]
tools = ["@@TOOL@@"]

[scope]
targets = ["192.0.2.0/24"]

[execution]
timeout_s = @@TIMEOUT@@
"""


class TestExecuteAction(unittest.TestCase):
    import tempfile as _tf

    def _config(self, tool="/bin/echo", timeout=30):
        text = EXEC_CONFIG.replace("@@TOOL@@", tool).replace("@@TIMEOUT@@", str(timeout))
        return load_actions_config(write_config(text))

    def _record(self, host="192.0.2.10"):
        return {"finding_ref": "r1:t", "target": {"host": host, "port": "443", "scheme": "https", "path": ""}}

    def _run(self, config, confirm, record=None):
        from jevsec.actions import ActionRefused, execute_action
        with tempfile.TemporaryDirectory() as tmp:
            return execute_action(
                session_name="s", session_dir=Path(tmp), record=record or self._record(),
                template_name="triage.review_tp", confirm=confirm, config=config,
            ), Path(tmp) / "actions.jsonl"

    def test_conferma_coincide_esegue_e_audita(self) -> None:
        from jevsec.actions import execute_action
        config = self._config()
        with tempfile.TemporaryDirectory() as tmp:
            result = execute_action(session_name="s", session_dir=Path(tmp), record=self._record(),
                                    template_name="triage.review_tp",
                                    confirm=["/bin/echo", "probe", "192.0.2.10"], config=config)
            self.assertEqual(result["exit_code"], 0)
            self.assertIn("probe 192.0.2.10", result["stdout"])
            audit = (Path(tmp) / "actions.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(audit), 1)
            import json as j
            self.assertEqual(j.loads(audit[0])["argv"], ["/bin/echo", "probe", "192.0.2.10"])

    def test_confirm_diverso_rifiutato_zero_audit(self) -> None:
        from jevsec.actions import ActionRefused, execute_action
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ActionRefused) as caught:
                execute_action(session_name="s", session_dir=Path(tmp), record=self._record(),
                               template_name="triage.review_tp",
                               confirm=["/bin/echo", "probe", "203.0.113.9"], config=self._config())
            self.assertIn("confirm does not match", str(caught.exception))
            self.assertFalse((Path(tmp) / "actions.jsonl").exists())

    def test_tool_del_template_fuori_allowlist_rifiutato(self) -> None:
        # confirm coincide (l'argv ricostruito usa il tool del template), ma il tool non è in allowlist
        from jevsec.actions import ActionRefused, execute_action
        text = EXEC_CONFIG.replace("@@TOOL@@", "/bin/echo").replace("@@TIMEOUT@@", "30") \
            .replace('tools = ["/bin/echo"]', 'tools = ["/usr/bin/env"]')
        config = load_actions_config(write_config(text))
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ActionRefused) as caught:
                execute_action(session_name="s", session_dir=Path(tmp),
                               record=self._record(), template_name="triage.review_tp",
                               confirm=["/bin/echo", "probe", "192.0.2.10"], config=config)
            self.assertIn("tool not in allowlist: /bin/echo", str(caught.exception))

    def test_confirm_con_altro_tool_non_coincide_mai(self) -> None:
        # argv da rete con tool diverso: non coincide con la ricostruzione, rifiuto a monte
        from jevsec.actions import ActionRefused, execute_action
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ActionRefused) as caught:
                execute_action(session_name="s", session_dir=Path(tmp),
                               record=self._record(), template_name="triage.review_tp",
                               confirm=["/usr/bin/env", "probe", "192.0.2.10"], config=self._config())
            self.assertIn("confirm does not match", str(caught.exception))

    def test_host_fuori_scope_rifiutato(self) -> None:
        from jevsec.actions import ActionRefused, execute_action
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ActionRefused) as caught:
                execute_action(session_name="s", session_dir=Path(tmp),
                               record=self._record(host="203.0.113.9"),
                               template_name="triage.review_tp",
                               confirm=["/bin/echo", "probe", "203.0.113.9"], config=self._config())
            self.assertIn("target out of scope: 203.0.113.9", str(caught.exception))

    def test_allowlist_assente_execution_disabled(self) -> None:
        from jevsec.actions import ActionRefused, execute_action
        text = EXEC_CONFIG.replace("@@TOOL@@", "/bin/echo").replace("@@TIMEOUT@@", "30")
        disabled = load_actions_config(write_config(text.replace('[allowlist]\ntools = ["/bin/echo"]\n\n', "")))
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ActionRefused) as caught:
                execute_action(session_name="s", session_dir=Path(tmp), record=self._record(),
                               template_name="triage.review_tp",
                               confirm=["/bin/echo", "probe", "192.0.2.10"], config=disabled)
            self.assertIn("execution disabled", str(caught.exception))

    def test_timeout_audit_con_exit_null(self) -> None:
        from jevsec.actions import execute_action
        text = """\
[triage.review_tp]
description = "Pend"
command = ["/bin/sleep", "5"]

[allowlist]
tools = ["/bin/sleep"]

[scope]
targets = ["192.0.2.0/24"]

[execution]
timeout_s = 0.3
"""
        config = load_actions_config(write_config(text))
        with tempfile.TemporaryDirectory() as tmp:
            result = execute_action(session_name="s", session_dir=Path(tmp), record=self._record(),
                                    template_name="triage.review_tp",
                                    confirm=["/bin/sleep", "5"], config=config)
            self.assertIsNone(result["exit_code"])
            self.assertIn("timed out", result["stderr"])
            self.assertTrue((Path(tmp) / "actions.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
