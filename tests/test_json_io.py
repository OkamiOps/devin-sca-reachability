import tempfile
import unittest
from pathlib import Path

from sca_reachability.errors import InputError
from sca_reachability.json_io import load_json_file


class JsonFileTests(unittest.TestCase):
    def test_rejects_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_bytes(b"\xff")

            with self.assertRaisesRegex(InputError, "not valid UTF-8"):
                load_json_file(path, "input")
