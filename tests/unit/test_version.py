"""Versione: fonte unica __version__, tre superfici coerenti (spec 005 T002)."""

from __future__ import annotations

import contextlib
import io
import unittest

from jevsec import __version__
from jevsec.cli import build_parser
from jevsec.service import SERVICE_VERSION


class TestSingleVersionSource(unittest.TestCase):
    def test_service_version_deriva_da_version_del_pacchetto(self) -> None:
        self.assertEqual(SERVICE_VERSION, __version__)

    def test_cli_version_stampa_la_versione_del_pacchetto(self) -> None:
        buffer = io.StringIO()
        with self.assertRaises(SystemExit) as caught, contextlib.redirect_stdout(buffer):
            build_parser().parse_args(["--version"])
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(buffer.getvalue().strip(), f"jevsec {__version__}")


if __name__ == "__main__":
    unittest.main()
