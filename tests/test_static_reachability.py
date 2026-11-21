import sqlite3
import tempfile
import unittest
from pathlib import Path

from sca_reachability.models import ReachabilityStatus
from sca_reachability.server.db import SCHEMA, Database
from sca_reachability.server.manifests import LockedComponent
from sca_reachability.server.osv_client import OsvClient
from sca_reachability.server.sources import collect_sources
from sca_reachability.static_reachability import SourceCoverage, SourceFile, analyze_package

REACHABLE = ReachabilityStatus.REACHABLE
UNREACHABLE = ReachabilityStatus.UNREACHABLE
UNKNOWN = ReachabilityStatus.UNKNOWN


def run(ecosystem, package, files, symbols=(), gaps=(), manifest_path=None):
    coverage = SourceCoverage([SourceFile(path, text) for path, text in files.items()], list(gaps))
    return analyze_package(ecosystem=ecosystem, package=package, coverage=coverage,
                           symbols=symbols, manifest_path=manifest_path)


class NpmReachabilityTests(unittest.TestCase):
    def test_named_import_call_is_reachable_with_import_and_call_evidence(self):
        result = run("npm", "lodash", {
            "src/a.ts": "import { merge, template as tpl } from 'lodash';\n\nexport const html = tpl('x');\n",
        }, ["template"])
        self.assertEqual(result.status, REACHABLE)
        self.assertEqual([(item.path, item.line, item.kind) for item in result.evidence],
                         [("src/a.ts", 1, "import"), ("src/a.ts", 3, "call")])
        self.assertEqual(result.evidence[1].snippet, "export const html = tpl('x');")

    def test_require_namespace_and_scoped_subpath_calls(self):
        self.assertEqual(run("npm", "lodash", {
            "a.js": "const _ = require('lodash');\n_.template('x');\n"}, ["template"]).status, REACHABLE)
        self.assertEqual(run("npm", "@scope/pkg", {
            "a.mjs": "import * as p from '@scope/pkg/sub';\np.run();\n"}).status, REACHABLE)
        self.assertEqual(run("npm", "lodash", {
            "a.cjs": "const { template: t } = require(\"lodash\");\nt();\n"}, ["template"]).status, REACHABLE)

    def test_import_without_vulnerable_symbol_call_is_unreachable(self):
        result = run("npm", "lodash", {"a.js": "import { merge } from 'lodash';\nmerge({}, {});\n"},
                     ["template"])
        self.assertEqual(result.status, UNREACHABLE)
        self.assertIn("não é garantia", result.reason)
        self.assertEqual(result.evidence[0].kind, "import")

    def test_mentions_in_comments_and_strings_do_not_count(self):
        result = run("npm", "lodash", {
            "a.js": "// require('lodash').template()\nconst s = \"import x from 'lodash'\";\n"})
        self.assertEqual(result.status, UNREACHABLE)
        self.assertEqual(result.evidence, ())

    def test_dynamic_require_escape_and_gaps_are_unknown(self):
        cases = [
            ({"a.js": "module.exports = (name) => require(name);\n"}, ()),
            ({"a.js": "import * as l from 'lodash';\nuse(l);\n"}, ()),
            ({"a.js": "import { template } from 'lodash';\nconst f = template;\n"}, ()),
            ({"a.js": "export * from 'lodash';\n"}, ()),
            ({"a.js": "const x = 1;\n"}, ("vendor.js excede o limite de leitura.",)),
            ({}, ()),
        ]
        for files, gaps in cases:
            with self.subTest(files=files, gaps=gaps):
                result = run("npm", "lodash", files, ["template"], gaps=gaps)
                self.assertEqual(result.status, UNKNOWN)
                self.assertIn("Desconhecido não significa seguro", result.reason)

    def test_nodegoat_config_blocks_negative_proof_not_complete_unimported_sources(self):
        config = ('const path = require("path");\n'
                  'const allConf = require(path.resolve(__dirname + "/../config/env/all.js"));\n'
                  'const envConf = require(path.resolve(__dirname + "/../config/env/" + finalEnv.toLowerCase() + ".js")) || {};\n')
        result = run("npm", "grunt", {"config/config.js": config, "main.js": "const x = 1;"})
        self.assertEqual(result.status, UNKNOWN)
        self.assertEqual(result.evidence[0].kind, "dynamic")
        self.assertEqual(result.evidence[0].path, "config/config.js")
        self.assertEqual(run("npm", "grunt", {"main.js": "const x = 1;"}).status, UNREACHABLE)

    def test_import_without_call_and_without_symbol_data_is_unknown(self):
        result = run("npm", "lodash", {"a.js": "import 'lodash';\n"})
        self.assertEqual(result.status, UNKNOWN)
        self.assertEqual(result.granularity, "package")

    def test_analysis_is_scoped_to_manifest_directory(self):
        files = {"web/a.js": "require('lodash').template();\n", "api/b.js": "const x = 1;\n"}
        self.assertEqual(run("npm", "lodash", files, manifest_path="api/package-lock.json").status,
                         UNREACHABLE)
        self.assertEqual(run("npm", "lodash", files, manifest_path="web/package-lock.json").status,
                         REACHABLE)


class PythonReachabilityTests(unittest.TestCase):
    def test_from_import_alias_call_is_reachable(self):
        result = run("PyPI", "PyYAML", {"app.py": "from yaml import load as parse\n\nparse(data)\n"},
                     ["yaml.load"])
        self.assertEqual(result.status, REACHABLE)
        self.assertEqual([(item.line, item.kind) for item in result.evidence],
                         [(1, "import"), (3, "call")])

    def test_module_attribute_call_without_symbols_is_package_level_reachable(self):
        result = run("PyPI", "requests", {"app.py": "import requests as r\nr.get(url)\n"})
        self.assertEqual(result.status, REACHABLE)
        self.assertIn("qualquer chamada ao pacote conta", result.reason)

    def test_safe_api_only_and_missing_import_are_unreachable(self):
        self.assertEqual(run("PyPI", "PyYAML", {"app.py": "import yaml\nyaml.safe_load(s)\n"},
                             ["load"]).status, UNREACHABLE)
        self.assertEqual(run("PyPI", "requests", {"app.py": "import os\n"}).status, UNREACHABLE)

    def test_dynamic_escape_parse_errors_and_import_only_are_unknown(self):
        cases = [
            ({"app.py": "import importlib\nm = importlib.import_module(name)\n"}, ["load"]),
            ({"app.py": "import yaml\nfn = getattr(yaml, name)\n"}, ["load"]),
            ({"app.py": "import yaml\nhandler(yaml)\n"}, ["load"]),
            ({"app.py": "import yaml\nf = yaml.load\n"}, ["load"]),
            ({"app.py": "from yaml import *\n"}, ["load"]),
            ({"app.py": "def broken(:\n"}, ["load"]),
            ({"app.py": "import yaml\n"}, []),
        ]
        for files, symbols in cases:
            with self.subTest(files=files):
                self.assertEqual(run("PyPI", "PyYAML", files, symbols).status, UNKNOWN)

    def test_unsupported_ecosystem_is_unknown(self):
        self.assertEqual(run("Maven", "x", {}).status, UNKNOWN)


class SourceCollectionTests(unittest.TestCase):
    def test_collects_only_safe_source_blobs_and_records_gaps(self):
        sha = "a" * 40
        tree = [
            {"path": "src/a.js", "type": "blob", "mode": "100644", "sha": sha},
            {"path": "node_modules/x/index.js", "type": "blob", "mode": "100644", "sha": sha},
            {"path": "src/link.js", "type": "blob", "mode": "120000", "sha": sha},
            {"path": "src/big.py", "type": "blob", "mode": "100644", "sha": sha, "size": 2 << 20},
            {"path": "README.md", "type": "blob", "mode": "100644", "sha": sha},
        ]
        reads = []
        coverage = collect_sources(tree, lambda blob: reads.append(blob) or b"const a = 1;\n")
        self.assertEqual([item.path for item in coverage.files], ["src/a.js"])
        self.assertEqual(len(reads), 1)
        self.assertEqual(len(coverage.gaps), 2)


class AdvisorySymbolTests(unittest.TestCase):
    def test_osv_affected_functions_and_import_symbols_are_extracted(self):
        component = LockedComponent("pyyaml", "5.3", "PyPI", "pkg:pypi/pyyaml@5.3", "requirements.txt")
        advisory = OsvClient(None)._to_advisory("GHSA-x", {"affected": [{
            "package": {"name": "PyYAML", "ecosystem": "PyPI"},
            "ecosystem_specific": {"affected_functions": ["yaml.load", "yaml.load"],
                                   "imports": [{"path": "yaml", "symbols": ["full_load"]}]},
        }]}, component, None)
        self.assertEqual(advisory.symbols, ("load", "full_load"))


class MigrationTests(unittest.TestCase):
    def test_legacy_unknown_only_findings_table_is_migrated_in_place(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.sqlite3"
            start = SCHEMA.index("    reachability TEXT NOT NULL DEFAULT 'unknown'")
            end = SCHEMA.index("    PRIMARY KEY (scan_id, ordinal)", start)
            legacy = SCHEMA[:start] + (
                "    reachability TEXT NOT NULL DEFAULT 'unknown' CHECK (reachability = 'unknown'),\n"
            ) + SCHEMA[end:]
            raw = sqlite3.connect(path)
            raw.executescript(legacy)
            raw.execute("INSERT INTO scan_findings VALUES ('s', 0, 'A', 'p', '1', 'npm', 'pkg:npm/p@1',"
                        " 'A', NULL, NULL, '[]', 'unknown')")
            raw.commit()
            raw.close()
            database = Database(path)
            database.initialize()
            with database.connection() as connection:
                connection.execute("PRAGMA foreign_keys = OFF")
                row = connection.execute("SELECT * FROM scan_findings").fetchone()
                self.assertEqual((row["advisory_id"], row["reachability"],
                                  row["reachability_evidence_json"]), ("A", "unknown", "[]"))
                connection.execute("UPDATE scan_findings SET reachability = 'reachable'")
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute("UPDATE scan_findings SET reachability = 'safe'")
            database.initialize()


if __name__ == "__main__":
    unittest.main()
