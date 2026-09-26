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


if __name__ == "__main__":
    unittest.main()
