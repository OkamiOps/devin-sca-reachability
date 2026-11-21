import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from sca_reachability.cli import main


class CliTests(unittest.TestCase):
    def test_demo_emits_json_with_unknown_reachability(self):
        root = Path(__file__).resolve().parents[1]
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = main(
                [
                    "analyze",
                    "--sbom",
                    str(root / "fixtures/demo-sbom.json"),
                    "--osv-response",
                    str(root / "fixtures/demo-osv-response.json"),
                ]
            )

        report = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(report["summary"]["unknown"], 1)

    def test_missing_input_is_reported_to_stderr(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = main(
                [
                    "analyze",
                    "--sbom",
                    "/path/that/does/not/exist.json",
                    "--osv-response",
                    "/also/missing.json",
                ]
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("error: cannot read SBOM file", stderr.getvalue())

    def test_invalid_json_is_reported_to_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            sbom_path = Path(directory) / "sbom.json"
            response_path = Path(directory) / "response.json"
            sbom_path.write_text("{", encoding="utf-8")
            response_path.write_text('{"results": []}', encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = main(
                    [
                        "analyze",
                        "--sbom",
                        str(sbom_path),
                        "--osv-response",
                        str(response_path),
                    ]
                )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("is not valid JSON", stderr.getvalue())
