import json
import unittest
from unittest.mock import patch

from sca_reachability.models import ReachabilityStatus
from sca_reachability.server.manifests import _parse_package_lock, _parse_requirements
from sca_reachability.server.osv_client import Advisory
from sca_reachability.server.sources import collect_sources, reachability_for
from sca_reachability.static_reachability import SourceCoverage, SourceFile


class DependencyGraphTests(unittest.TestCase):
    def analyze(self, packages, sources=None, *, target='node_modules/qs', gaps=(), version=3, symbols=()):
        components, _ = _parse_package_lock(json.dumps({
            'lockfileVersion': version, 'packages': packages,
        }).encode(), 'package-lock.json')
        coverage = SourceCoverage([SourceFile(path, code) for path, code in
                                   (sources or {'server.js': 'const unused = 1;'}).items()], list(gaps))
        advisories = [[Advisory('GHSA-test', None, None, (), symbols)] if item.lock_path == target else []
                      for item in components]
        results = reachability_for(components, advisories, coverage)
        index = next(i for i, item in enumerate(components) if item.lock_path == target)
        return components[index], results[index][0]

    def fixture(self):
        return {
            '': {'dependencies': {'body-parser': '1.0.0'}},
            'node_modules/body-parser': {'version': '1.0.0', 'dependencies': {'qs': '1.0.0'}},
            'node_modules/qs': {'version': '1.0.0'},
        }

    def test_nodegoat_qs_via_imported_body_parser_is_unknown_not_unreachable(self):
        for version in (2, 3):
            with self.subTest(version=version):
                component, result = self.analyze(self.fixture(), {'server.js':
                    'const bodyParser = require("body-parser");\nbodyParser.json();\n'
                    'require(path.resolve(__dirname + "/config/" + env + ".js"));'}, version=version)
                self.assertEqual(component.dependency_relation, 'transitive')
                self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)
                self.assertTrue(result.transitive_imported_via)
                self.assertEqual(result.dependency_via, (('body-parser', 'qs'),))
                self.assertIn('body-parser, importado em server.js:1', result.dependency_note)
                self.assertIn('não foi analisado', result.dependency_note)
                self.assertEqual(result.evidence[0].kind, 'transitive_import')
                self.assertEqual(result.scope, 'production')
                self.assertTrue(result.notes)

    def test_transitive_via_never_imported_direct_is_unreachable(self):
        component, result = self.analyze(self.fixture())
        self.assertTrue(component.dependency_graph_complete)
        self.assertEqual(result.status, ReachabilityStatus.UNREACHABLE)
        self.assertIn('Todos os ancestrais diretos (body-parser)', result.reason)
        self.assertFalse(result.transitive_imported_via)

    def test_one_imported_of_multiple_ancestors_blocks_negative_proof(self):
        packages = self.fixture()
        packages['']['devDependencies'] = {'unused': '1.0.0'}
        packages['node_modules/unused'] = {'version': '1.0.0', 'dependencies': {'middle': '1.0.0'}}
        packages['node_modules/middle'] = {'version': '1.0.0', 'dependencies': {'qs': '1.0.0'}}
        component, result = self.analyze(packages, {'server.js': 'require("body-parser");'})
        self.assertEqual(set(component.dependency_via),
                         {('body-parser', 'qs'), ('unused', 'middle', 'qs')})
        self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)
        self.assertTrue(result.transitive_imported_via)
        self.assertEqual(self.analyze(packages)[1].status, ReachabilityStatus.UNREACHABLE)

    def test_nearest_nested_resolution_scoped_names_and_hoisting(self):
        packages = self.fixture()
        packages['']['dependencies']['@scope/tool'] = '1.0.0'
        packages['node_modules/@scope/tool'] = {'version': '1.0.0', 'dependencies': {'qs': '2.0.0'}}
        packages['node_modules/@scope/tool/node_modules/qs'] = {'version': '2.0.0'}
        sources = {'server.js': 'require("@scope/tool");'}
        component, result = self.analyze(packages, sources)
        self.assertEqual(component.dependency_via, (('body-parser', 'qs'),))
        self.assertEqual(result.status, ReachabilityStatus.UNREACHABLE)
        component, result = self.analyze(packages, sources, target='node_modules/@scope/tool/node_modules/qs')
        self.assertEqual(component.dependency_via, (('@scope/tool', 'qs'),))
        self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)

    def test_direct_package_also_used_transitively_is_not_a_false_negative(self):
        packages = self.fixture()
        packages['']['dependencies']['qs'] = '1.0.0'
        component, result = self.analyze(packages, {'server.js': 'require("body-parser").json();'})
        self.assertEqual(component.dependency_relation, 'direct')
        self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)
        self.assertIn('direta também usada via body-parser', result.dependency_note)
        self.assertFalse(result.transitive_imported_via)

    def test_every_root_dependency_field_is_direct_but_nested_same_name_is_not(self):
        packages = {'': {field: {name: '1.0.0'} for field, name in [
            ('dependencies', 'prod'), ('devDependencies', 'dev'),
            ('optionalDependencies', 'optional'), ('peerDependencies', 'peer')]}}
        packages.update({f'node_modules/{name}': {'version': '1.0.0'}
                         for name in ('prod', 'dev', 'optional', 'peer')})
        packages['node_modules/prod']['dependencies'] = {'dev': '2.0.0'}
        packages['node_modules/prod/node_modules/dev'] = {'version': '2.0.0'}
        components, _ = _parse_package_lock(json.dumps({'lockfileVersion': 3, 'packages': packages}).encode(), 'package-lock.json')
        self.assertTrue(all(item.dependency_relation == 'direct' for item in components[:-1]))
        self.assertEqual(components[-1].dependency_relation, 'transitive')
        self.assertEqual(components[-1].dependency_via, (('prod', 'dev'),))

    def test_unresolvable_missing_malformed_and_orphan_graphs_are_unknown(self):
        fixtures = []
        missing = self.fixture()
        missing['node_modules/body-parser']['dependencies']['missing'] = '*'
        fixtures.append(missing)
        malformed = self.fixture()
        malformed['node_modules/body-parser']['dependencies'] = ['qs']
        fixtures.append(malformed)
        no_root = self.fixture()
        del no_root['']
        fixtures.append(no_root)
        orphan = self.fixture()
        orphan['node_modules/body-parser']['dependencies'] = {}
        fixtures.append(orphan)
        unsafe = self.fixture()
        unsafe['/node_modules/invalid'] = {'version': '1.0.0', 'dependencies': {'missing': '*'}}
        fixtures.append(unsafe)
        for packages in fixtures:
            with self.subTest(packages=packages):
                _, result = self.analyze(packages)
                self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)
                self.assertIn('Grafo npm incompleto', result.dependency_note)
        with patch('sca_reachability.server.manifests.MAX_COMPONENTS', 1):
            self.assertFalse(self.analyze(self.fixture())[0].dependency_graph_complete)

    def test_cycles_terminate_and_dynamic_loads_or_coverage_gaps_block_negative_proof(self):
        packages = self.fixture()
        packages['node_modules/qs']['dependencies'] = {'body-parser': '1.0.0'}
        self.assertEqual(self.analyze(packages)[1].status, ReachabilityStatus.UNREACHABLE)
        for sources, gaps in [({'main.js': 'require(name);'}, ()),
                              ({'main.js': 'const x = 1;'}, ('missing source',))]:
            self.assertEqual(self.analyze(packages, sources, gaps=gaps)[1].status, ReachabilityStatus.UNKNOWN)
        self.assertEqual(self.analyze(packages, {'main.py': 'pass'})[1].status, ReachabilityStatus.UNKNOWN)

    def test_transitive_mentions_do_not_prove_reachability_of_a_locked_version(self):
        _, result = self.analyze(self.fixture(), {'server.js': 'require("qs").parse();'})
        self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)
        self.assertFalse(result.transitive_imported_via)
        _, result = self.analyze(self.fixture(), {'server.js': 'require("qs");'}, symbols=('parse',))
        self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)

    def test_transitive_imports_keep_test_scope_without_promoting_to_reachable(self):
        _, result = self.analyze(self.fixture(), {'tests/app.js': 'require("body-parser").json();'})
        self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)
        self.assertEqual(result.scope, 'test_only')

    def test_python_pins_remain_direct_without_graph(self):
        components, _ = _parse_requirements(b'PyYAML==5.3\n', 'requirements.txt')
        for source, expected in [('import yaml\nyaml.load(data)', ReachabilityStatus.REACHABLE),
                                 ('pass', ReachabilityStatus.UNREACHABLE)]:
            result = reachability_for(components, [[Advisory('GHSA-test', None, None, ())]],
                                      SourceCoverage([SourceFile('main.py', source)]))[0][0]
            self.assertEqual(result.dependency_relation, 'direct')
            self.assertEqual(result.status, expected)

    def test_grunt_plugin_loads_block_false_negative_ancestors(self):
        for code in ('grunt.loadNpmTasks("body-parser");', 'grunt.loadNpmTasks(name);'):
            _, result = self.analyze(self.fixture(), {'Gruntfile.js': code})
            self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)
        _, result = self.analyze(self.fixture(), {'Gruntfile.js': 'grunt.loadNpmTasks("body-parser");'})
        self.assertTrue(result.transitive_imported_via)
        self.assertEqual(result.scope, 'dev_tooling')

    def test_npm_script_cli_alias_and_unresolved_scripts_are_unknown(self):
        packages = self.fixture()
        packages['node_modules/body-parser']['bin'] = {'parse-body': 'bin.js'}
        for command in ('parse-body test', 'node node_modules/body-parser/bin.js', '$TOOL', 'npm run other'):
            with self.subTest(command=command):
                _, result = self.analyze(packages, {'main.js': 'const x = 1;', 'package.json':
                    json.dumps({'scripts': {'test': command}}, indent=2)})
                self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)
        _, result = self.analyze(packages, {'main.js': 'const x = 1;', 'package.json':
            json.dumps({'scripts': {'test': 'parse-body test'}}, indent=2)})
        self.assertTrue(result.transitive_imported_via)
        self.assertEqual(result.evidence[0].kind, 'transitive_entrypoint')
        self.assertEqual(result.evidence[0].path, 'package.json')
        self.assertIn('invocado por CLI', result.reason)
        self.assertEqual(result.scope, 'dev_tooling')
        _, result = self.analyze(packages, {'main.js': 'const x = 1;', 'package.json': '{bad json'})
        self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)

    def test_collects_script_metadata_without_scanning_installed_dependencies(self):
        tree = [{'path': path, 'type': 'blob', 'mode': '100644', 'sha': 'a' * 40}
                for path in ('package.json', 'node_modules/pkg/package.json')]
        coverage = collect_sources(tree, lambda _: b'{"scripts":{"test":"grunt"}}')
        self.assertEqual([source.path for source in coverage.files], ['package.json'])
