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


def run(ecosystem, package, files, symbols=(), gaps=(), manifest_path=None, dependency_dev=False):
    coverage = SourceCoverage([SourceFile(path, text) for path, text in files.items()], list(gaps))
    return analyze_package(ecosystem=ecosystem, package=package, coverage=coverage,
                           symbols=symbols, manifest_path=manifest_path, dependency_dev=dependency_dev)


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

    def test_nodegoat_local_config_loads_do_not_block_negative_proof(self):
        config = ('const path = require("path");\n'
                  'const allConf = require(path.resolve(__dirname + "/../config/env/all.js"));\n'
                  'const envConf = require(path.resolve(__dirname + "/../config/env/" + finalEnv.toLowerCase() + ".js")) || {};\n')
        result = run("npm", "grunt", {"config/config.js": config, "main.js": "const x = 1;"})
        self.assertEqual(result.status, UNREACHABLE)
        self.assertEqual(result.evidence, ())
        self.assertEqual([(note.path, note.line, note.kind) for note in result.notes],
                         [("config/config.js", 2, "local_load"), ("config/config.js", 3, "local_load")])
        self.assertIn('path.resolve', result.analysis_dict()['notes'][1]['snippet'])
        self.assertEqual(run("npm", "grunt", {"main.js": "const x = 1;"}).status, UNREACHABLE)

    def test_local_load_prefixes_and_templates_are_recorded(self):
        expressions = [
            '"./config/" + name', '"../config/" + name', '"/app/config/" + name',
            '__dirname + "/config/" + name', '__filename + name', '__dirname',
            '`./config/${name}.js`', '`../config/${name}`', '`/app/${name}`',
            '`${__dirname}/config/${name}.js`', '`${__filename}${suffix}`',
            'path.resolve(__dirname, name)', 'path.join(__dirname, name)',
            'path.resolve("./config", name)', 'path.resolve("../config", name)',
            'path.join("../config", name)', 'path.join("../", name)',
        ]
        for expression in expressions:
            for function in ('require', 'import'):
                with self.subTest(expression=expression, function=function):
                    result = run('npm', 'lodash', {'main.js': f'{function}({expression});'})
                    self.assertEqual(result.status, UNREACHABLE)
                    self.assertEqual(len(result.notes), 1)
                    self.assertEqual(result.notes[0].kind, 'local_load')

    def test_dynamic_package_loads_and_unsafe_prefixes_stay_unknown(self):
        expressions = [
            'x', '"node_modules/" + x', '"./node_modules/" + x',
            'path.resolve(x, "./config")', 'path.join(x, "./config")',
            'path.resolve("node_modules/", x)', 'path.join(__dirname, "node_modules", x)',
            'path.join("./", x)', 'path.join("./config", x)',
            '"./" + x ? packageName : other', '"./" + x, packageName',
            '"./" + x || packageName', '"./" + x - 0 + packageName',
            'path.join(__dirname + x ? packageName : other, "file")',
            '"./".replace("./", packageName)', '`${name}/file`',
            '`${__dirname}/node_modules/${name}`', '`./${require(name)}`',
        ]
        for expression in expressions:
            with self.subTest(expression=expression):
                result = run('npm', 'lodash', {'main.js': f'require({expression});'})
                self.assertEqual(result.status, UNKNOWN)
                self.assertEqual(result.notes, ())
        self.assertEqual(run('npm', 'lodash', {'main.js': 'require(__dirname'}).status, UNKNOWN)

    def test_local_notes_never_override_gaps_or_package_calls(self):
        files = {'main.js': 'require("./" + name);\nrequire("lodash").template();'}
        result = run('npm', 'lodash', files, ['template'])
        self.assertEqual(result.status, REACHABLE)
        self.assertEqual(result.evidence[-1].kind, 'call')
        self.assertEqual(len(result.notes), 1)
        result = run('npm', 'lodash', {'main.js': 'require("./" + name);'}, gaps=['missing source'])
        self.assertEqual(result.status, UNKNOWN)
        self.assertEqual(len(result.notes), 1)
        self.assertEqual(run('npm', 'lodash', {
            'main.js': 'require(path.resolve(__dirname, require(name)));'}).status, UNKNOWN)

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


class ReachabilityScopeTests(unittest.TestCase):
    def test_call_contexts_for_javascript_and_python_do_not_change_classification(self):
        for ecosystem, package, suffix, code in [
            ('npm', 'lodash', 'js', 'const p = require("lodash");\np.template();'),
            ('PyPI', 'PyYAML', 'py', 'import yaml\nyaml.load(data)'),
        ]:
            for path, expected in [
                ('src/app', 'production'), ('config/config', 'production'), ('test/app', 'test_only'),
                ('tests/app', 'test_only'), ('__tests__/app', 'test_only'),
                ('spec/app', 'test_only'), ('src/app.test', 'test_only'),
                ('src/app.spec', 'test_only'), ('scripts/check', 'dev_tooling'),
                ('build/generate', 'dev_tooling'), ('Gruntfile', 'dev_tooling'),
                ('gulpfile', 'dev_tooling'), ('webpack.config', 'dev_tooling'),
                ('build.config', 'dev_tooling'), ('vite.config', 'dev_tooling'),
            ]:
                with self.subTest(ecosystem=ecosystem, path=path):
                    files = {path + '.' + suffix: code}
                    result = run(ecosystem, package, files)
                    self.assertEqual(result.status, REACHABLE)
                    self.assertEqual(result.scope, expected)
                    dev_result = run(ecosystem, package, files, dependency_dev=True)
                    self.assertEqual(dev_result.status, result.status)
                    self.assertEqual(dev_result.evidence, result.evidence)
                    self.assertEqual(dev_result.scope, 'test_only' if expected == 'test_only' else 'dev_tooling')

    def test_production_calls_win_before_evidence_is_limited(self):
        for ecosystem, package, suffix, code in [
            ('npm', 'lodash', 'js', 'const p = require("lodash");\np.template();'),
            ('PyPI', 'PyYAML', 'py', 'import yaml\nyaml.load(data)'),
        ]:
            with self.subTest(ecosystem=ecosystem):
                files = {f'tests/test{i}.{suffix}': code for i in range(8)}
                files['src/app.' + suffix] = code
                result = run(ecosystem, package, files)
                self.assertEqual(result.scope, 'production')
                self.assertEqual(result.status, REACHABLE)
                self.assertEqual(len(result.evidence), 6)
                self.assertEqual([item.path for item in result.evidence[:2]], ['src/app.' + suffix] * 2)
                self.assertIn('src/app.' + suffix, result.reason)

    def test_scope_uses_calls_not_an_uncalled_production_import(self):
        result = run('npm', 'lodash', {
            'src/app.js': 'import p from "lodash";',
            'tests/app.js': 'const p = require("lodash");\np.template();'})
        self.assertEqual(result.status, REACHABLE)
        self.assertEqual(result.scope, 'test_only')
        for path in ('test_app.py', 'app_test.py', 'conftest.py'):
            self.assertEqual(run('PyPI', 'PyYAML', {path: 'import yaml\nyaml.load(data)'}).scope, 'test_only')

    def test_empty_unknown_unreachable_and_parse_errors_keep_classification(self):
        for files, status in [({}, UNKNOWN), ({'main.js': 'const x = 1;'}, UNREACHABLE),
                              ({'tests/main.js': 'require(name);'}, UNKNOWN)]:
            for dev in (False, True):
                with self.subTest(files=files, dev=dev):
                    result = run('npm', 'lodash', files, dependency_dev=dev)
                    self.assertEqual(result.status, status)
                    self.assertEqual(result.scope, 'dev_tooling' if dev else 'production')
        result = run('PyPI', 'PyYAML', {'tests/main.py': 'bad syntax :'}, dependency_dev=True)
        self.assertEqual(result.status, UNKNOWN)
        self.assertTrue(result.analysis_dict()['dependency_dev'])


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
