"""CLI session: grammatica, exit code e messaggi d'errore EN (spec 005 T015, contratto cli-session.md)."""

from __future__ import annotations

import io
import socket
import unittest
from unittest import mock

from jevsec import cli


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class TestSessionGrammar(unittest.TestCase):
    def test_session_new_accetta_nome_url_json(self) -> None:
        args = cli.build_parser().parse_args(["session", "new", "--name", "demo", "--url", "http://127.0.0.1:1", "--json"])
        self.assertEqual((args.session_command, args.name, args.json), ("new", "demo", True))

    def test_add_finding_accetta_trattino_posizionale(self) -> None:
        args = cli.build_parser().parse_args(["session", "add-finding", "--session", "s", "-"])
        self.assertEqual(cli._input_path(args), "-")

    def test_add_finding_posizionale_e_file_insieme_rifiutati(self) -> None:
        args = cli.build_parser().parse_args(["session", "add-finding", "--session", "s", "a.jsonl", "--file", "b.jsonl"])
        with self.assertRaises(ValueError):
            cli._input_path(args)

    def test_add_observation_richiede_obiettivo(self) -> None:
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["session", "add-observation", "--session", "s"])

    def test_feedback_ranking_ok_solo_true_false(self) -> None:
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["session", "feedback", "--session", "s", "--ref", "o1", "--ranking-ok", "maybe"])


class TestSessionErrors(unittest.TestCase):
    def test_add_finding_input_non_json_exit_2_messaggio_en(self) -> None:
        args = cli.build_parser().parse_args(["session", "add-finding", "--session", "s", "--url", "http://127.0.0.1:1"])
        with mock.patch("sys.stdin", io.StringIO("{not json\n")), \
                mock.patch("sys.stderr", io.StringIO()) as stderr:
            code = cli.main(["session", "add-finding", "--session", "s", "--url", "http://127.0.0.1:1"])
        self.assertEqual(code, 2)
        self.assertIn("line 1 is not JSON", stderr.getvalue())

    def test_queue_demone_spento_exit_2_con_indicazione_avvio(self) -> None:
        url = f"http://127.0.0.1:{_free_port()}"
        with mock.patch("sys.stderr", io.StringIO()) as stderr:
            code = cli.main(["session", "queue", "--session", "s", "--url", url])
        self.assertEqual(code, 2)
        message = stderr.getvalue()
        self.assertIn("service not reachable", message)
        self.assertIn("python3 -m jevsec.service", message)


class FakeTty(io.StringIO):
    def isatty(self) -> bool:
        return True


class TestSessionRun(unittest.TestCase):
    """Spec 006 US2: conferma interattiva per-azione; senza TTY mai esecuzione."""

    def test_run_senza_tty_rifiutato_prima_di_ogni_rete(self) -> None:
        with mock.patch("sys.stderr", io.StringIO()) as stderr, \
                mock.patch.object(cli, "_service_call") as service_call:
            code = cli.main(["session", "run", "--session", "s", "--ref", "r", "--template", "t",
                             "--url", "http://127.0.0.1:1"])
        self.assertEqual(code, 2)
        self.assertIn("interactive confirmation required", stderr.getvalue())
        service_call.assert_not_called()  # senza TTY nemmeno la coda viene chiesta

    def test_run_con_tty_conferma_no_non_esegue(self) -> None:
        args = cli.build_parser().parse_args(
            ["session", "run", "--session", "s", "--ref", "r1:t", "--template", "triage.review_tp",
             "--url", "http://127.0.0.1:1"])
        queue_payload = {"triage": [{"finding_ref": "r1:t",
                                     "playbook": {"template": "triage.review_tp",
                                                  "description": "Echo probe",
                                                  "argv": ["/bin/echo", "probe", "192.0.2.10"]}}]}
        with mock.patch.object(cli, "_service_call", return_value=queue_payload), \
                mock.patch("sys.stdin", FakeTty("n\n")), \
                mock.patch("sys.stdout", io.StringIO()) as stdout:
            code = cli.run_session_run(args)
        self.assertEqual(code, 0)
        self.assertIn("aborted", stdout.getvalue())

    def test_run_con_tty_conferma_si_invia_confirm_esatto(self) -> None:
        args = cli.build_parser().parse_args(
            ["session", "run", "--session", "s", "--ref", "r1:t", "--template", "triage.review_tp",
             "--url", "http://127.0.0.1:1"])
        queue_payload = {"triage": [{"finding_ref": "r1:t",
                                     "playbook": {"template": "triage.review_tp",
                                                  "description": "Echo probe",
                                                  "argv": ["/bin/echo", "probe", "192.0.2.10"]}}]}
        calls = {}

        def fake_call(url, method, path, body=None):
            calls["path"], calls["body"] = path, body
            if method == "GET":
                return queue_payload
            return {"exit_code": 0, "stdout": "probe 192.0.2.10\n", "stderr": "", "duration_ms": 3,
                    "ts": "", "session": "s", "ref": "r1:t", "template": "triage.review_tp",
                    "argv": body["confirm"], "target": ["192.0.2.10"]}

        with mock.patch.object(cli, "_service_call", side_effect=fake_call), \
                mock.patch("sys.stdin", FakeTty("y\n")), \
                mock.patch("sys.stdout", io.StringIO()):
            code = cli.run_session_run(args)
        self.assertEqual(code, 0)
        self.assertEqual(calls["body"]["confirm"], ["/bin/echo", "probe", "192.0.2.10"])


if __name__ == "__main__":
    unittest.main()
