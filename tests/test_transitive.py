import base64
from dataclasses import replace
import hashlib
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from sca_reachability.models import ReachabilityStatus
from sca_reachability.server.app import create_app
from sca_reachability.server.config import Settings
from sca_reachability.server.manifests import _parse_package_lock
from sca_reachability.server.npm_sources import NpmSources, PackageSource, PackageUnknown
from sca_reachability.server.osv_client import Advisory, OsvClient
from sca_reachability.server.public_github import PublicGitHubAdapter
from sca_reachability.server.sources import reachability_for
from sca_reachability.server.transitive import javascript_loads, resolve_entry, trace_transitives
from sca_reachability.static_reachability import SourceCoverage, SourceFile
from test_public_github import archive, refs


def package(name, files=None, **metadata):
    content = {'package/package.json': json.dumps({'name': name, 'version': '1.0.0', **metadata}).encode()}
    content.update({'package/' + path: text.encode() for path, text in (files or {'index.js': 'exports.ok = true;'}).items()})
    return archive(content)


def pin(data, name):
    return {'version': '1.0.0', 'resolved': f'https://registry.npmjs.org/{name}/-/package.tgz',
            'integrity': 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode()}


def fixture(a_files=None, **a_metadata):
    blobs = {'a': package('a', a_files, **a_metadata), 'b': package('b')}
    packages = {'': {'dependencies': {'a': '1.0.0'}},
                'node_modules/a': {**pin(blobs['a'], 'a'), 'dependencies': {'b': '1.0.0'}},
                'node_modules/b': pin(blobs['b'], 'b')}
    return blobs, packages


def components(packages):
    return _parse_package_lock(json.dumps({'lockfileVersion': 3, 'packages': packages}).encode(), 'package-lock.json')[0]


class PackageAcquisitionTests(unittest.TestCase):
    def test_integrity_cache_and_no_filesystem_extraction(self):
        blobs, packages = fixture()
        calls = []
        client = httpx.Client(transport=httpx.MockTransport(lambda request: (
            calls.append(str(request.url)) or httpx.Response(200, content=blobs['a']))))
        component = components(packages)[0]
        with NpmSources(client) as source, patch('tarfile.TarFile.extractall', side_effect=AssertionError('disk forbidden')):
            self.assertIn('index.js', source.get(component).files)
            same = replace(component, resolved='https://registry.npmjs.org/a/-/other.tgz')
            self.assertEqual(source.get(component), source.get(same))
            self.assertEqual(len(calls), 1)
        client.close()

    def test_sha1_and_integrity_host_archive_and_budget_failures(self):
        blobs, packages = fixture()
        component = components(packages)[0]
        client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=blobs['a'])))
        with NpmSources(client) as source:
            sha1 = replace(component, integrity='sha1-' + base64.b64encode(hashlib.sha1(blobs['a']).digest()).decode())
            self.assertEqual(source.get(sha1).metadata['name'], 'a')
        for replacement, kwargs, code in [
            ({'resolved': 'https://evil.example/a.tgz'}, {}, 'host'),
            ({'resolved': 'https://registry.npmjs.org@evil.example/a.tgz'}, {}, 'host'),
            ({'resolved': 'http://registry.npmjs.org/a.tgz'}, {}, 'host'),
            ({'resolved': 'https://registry.npmjs.org:8443/a.tgz'}, {}, 'host'),
            ({'integrity': 'sha512-invalid'}, {}, 'integrity'),
            ({'integrity': 'sha512-' + base64.b64encode(b'x' * 64).decode()}, {}, 'integrity'),
            ({}, {'max_packages': 0}, 'package_limit'),
            ({}, {'max_download': 1}, 'byte_limit'),
            ({}, {'max_package': 1}, 'byte_limit'),
            ({}, {'max_unpacked': 100}, 'archive'),
            ({}, {'max_entries': 1}, 'archive'),
        ]:
            with self.subTest(replacement=replacement, kwargs=kwargs), NpmSources(client, **kwargs) as source:
                with self.assertRaises(PackageUnknown) as error:
                    source.get(replace(component, **replacement))
                self.assertEqual(error.exception.code, code)
        for status in (302, 404):
            transport = httpx.MockTransport(lambda request: httpx.Response(status, headers={'Location': 'https://evil.example/a.tgz'}))
            with httpx.Client(transport=transport) as redirects, NpmSources(redirects) as source:
                with self.assertRaises(PackageUnknown) as error:
                    source.get(component)
                self.assertEqual(error.exception.code, 'download')
        unsafe = archive({'package/../escape.js': b'no'})
        with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=unsafe))) as bad, NpmSources(bad) as source:
            with self.assertRaises(PackageUnknown):
                source.get(replace(component, integrity=None))
        client.close()

    def test_entry_main_exports_require_subpath_and_directory(self):
        files = {path: b'' for path in ('index.js', 'lib/a.js', 'lib/b.js', 'folder/index.js')}
        self.assertEqual(resolve_entry(PackageSource(files, {}), 'a', 'a'), 'index.js')
        self.assertEqual(resolve_entry(PackageSource(files, {'main': 'lib/a'}), 'a', 'a'), 'lib/a.js')
        self.assertEqual(resolve_entry(PackageSource(files, {}), 'a/folder', 'a'), 'folder/index.js')
        exports = {'.': {'import': './lib/b.js', 'require': './lib/a.js'}, './feature': './lib/b.js'}
        source = PackageSource(files, {'exports': exports})
        self.assertEqual(resolve_entry(source, 'a', 'a'), 'lib/a.js')
        self.assertEqual(resolve_entry(source, 'a', 'a', 'import'), 'lib/b.js')
        self.assertEqual(resolve_entry(source, 'a/feature', 'a'), 'lib/b.js')
        for spec in ('a/missing', 'a/../../outside'):
            with self.assertRaises(PackageUnknown):
                resolve_entry(source, spec, 'a')
        with self.assertRaises(PackageUnknown):
            resolve_entry(PackageSource(files, {'exports': ['fallback']}), 'a', 'a')


class StaticPathTests(unittest.TestCase):
    def test_regex_scanning_is_bounded_on_bracket_heavy_non_regex(self):
        subprocess.run([sys.executable, '-c',
            'from sca_reachability.server.transitive import javascript_loads; '
            'javascript_loads("/" + "[x]" * 40000 + "!", "probe.js")'],
            check=True, timeout=10)

    def analyze(self, blobs, packages, repo='const a = require("a");', gaps=(), **limits):
        locked = components(packages)
        coverage = SourceCoverage([SourceFile('server.js', repo)], list(gaps))
        advisories = [[Advisory('GHSA-test', None, None, (), ('danger',))] if item.name == 'b' else [] for item in locked]
        baseline = reachability_for(locked, advisories, coverage)
        client = httpx.Client(transport=httpx.MockTransport(lambda request:
            httpx.Response(200, content=blobs[request.url.path.split('/')[1]])))
        with client, NpmSources(client, **limits) as source:
            result = trace_transitives(locked, baseline, coverage, source)
        return next(row[0] for row in result if row)

    def test_full_reachable_chain_with_relative_steps_and_known_symbols(self):
        blobs, packages = fixture({'index.js': 'module.exports = require("./lib/start");', 'lib/start.js': 'const b = require("b");'})
        result = self.analyze(blobs, packages)
        self.assertEqual(result.status, ReachabilityStatus.REACHABLE)
        self.assertEqual(result.granularity, 'import')
        self.assertEqual(result.symbols, ('danger',))
        self.assertEqual([step['file'] for step in result.transitive_path], ['server.js', 'index.js', 'lib/start.js', 'index.js'])
        self.assertIn('Não comprova chamada', result.reason)
        self.assertEqual(result.scope, 'production')

    def test_unreachable_requires_full_package_and_complete_source_coverage(self):
        blobs, packages = fixture()
        self.assertEqual(self.analyze(blobs, packages).status, ReachabilityStatus.UNREACHABLE)
        self.assertEqual(self.analyze(blobs, packages, gaps=('missing source',)).status, ReachabilityStatus.UNKNOWN)
        self.assertEqual(self.analyze(blobs, packages, repo='require("a");require(name);').status, ReachabilityStatus.UNKNOWN)
        for files, metadata in [({'index.js': 'exports.x=1;', 'unused.js': 'require("b");'}, {}),
                                ({'index.js': 'require(name);'}, {}),
                                ({'index.js': 'exports.x=1;'}, {'bin': {'a': 'cli.js'}}),
                                ({'index.js': 'exports.x=1;'}, {'scripts': {'start': 'node cli.js'}})]:
            blobs, packages = fixture(files, **metadata)
            self.assertEqual(self.analyze(blobs, packages).status, ReachabilityStatus.UNKNOWN)

    def test_unknown_budget_and_incomplete_graph_and_missing_entry(self):
        blobs, packages = fixture({'index.js': 'require("b");'})
        self.assertEqual(self.analyze(blobs, packages, max_packages=0).transitive_unknown_reason, 'package_limit')
        self.assertEqual(self.analyze(blobs, packages, repo='require("a");require(name);', max_packages=0).transitive_unknown_reason, 'package_limit')
        packages['node_modules/a']['dependencies']['missing'] = '*'
        self.assertEqual(self.analyze(blobs, packages).transitive_unknown_reason, 'graph')
        blobs, packages = fixture(main='missing.js')
        self.assertEqual(self.analyze(blobs, packages).transitive_unknown_reason, 'entry')

    def test_alternative_graph_paths_are_not_discarded(self):
        blobs, packages = fixture({'index.js': 'require("c");require("d");'})
        packages['node_modules/a']['dependencies'] = {'c': '1.0.0', 'd': '1.0.0'}
        for name, code in [('c', 'exports.ok=1;'), ('d', 'require("b");')]:
            blobs[name] = package(name, {'index.js': code})
            packages['node_modules/' + name] = {**pin(blobs[name], name), 'dependencies': {'b': '1.0.0'}}
        self.assertEqual(self.analyze(blobs, packages).status, ReachabilityStatus.REACHABLE)
        blobs['d'] = package('d', {'index.js': 'require(name);'})
        packages['node_modules/d'].update(pin(blobs['d'], 'd'))
        self.assertEqual(self.analyze(blobs, packages).status, ReachabilityStatus.UNKNOWN)

    def test_extractors_reject_comments_regex_shadowing_and_alias_uncertainty(self):
        loads, uncertain = javascript_loads('// require("bad")\nconst re=/require("bad")/; require("good/sub");', 'a.js')
        self.assertEqual([load.specifier for load in loads], ['good/sub'])
        self.assertTrue(uncertain)
        loads, uncertain = javascript_loads('const require = other; require("bad");', 'a.js')
        self.assertEqual(loads, [])
        self.assertTrue(uncertain)

    def test_empty_findings_and_cli_only_root_remain_honest(self):
        self.assertEqual(trace_transitives([], [], SourceCoverage(), None), [])
        blobs, packages = fixture({'index.js': 'require("b");'})
        result = self.analyze(blobs, packages, repo='grunt.loadNpmTasks("a");')
        self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)
        self.assertFalse(result.transitive_decided)

    def test_production_root_evidence_is_preferred_over_earlier_test_import(self):
        blobs, packages = fixture({'index.js': 'require("b");'})
        locked = components(packages)
        advisories = [[], [Advisory('GHSA-example', None, None, (), ())]]
        coverage = SourceCoverage([SourceFile('test/a.js', 'require("a");'), SourceFile('server.js', 'require("a");')])
        with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=blobs[request.url.path.split('/')[1]]))) as client, NpmSources(client) as sources:
            result = trace_transitives(locked, reachability_for(locked, advisories, coverage), coverage, sources)[1][0]
        self.assertEqual(result.scope, 'production')
        self.assertEqual(result.transitive_path[0]['file'], 'server.js')


class TransitivePipelineTests(unittest.TestCase):
    def test_public_worker_with_mock_registry_and_persisted_api_path(self):
        blobs, packages = fixture({'index.js': 'module.exports=require("b");'})
        snapshot = archive({'root/package-lock.json': json.dumps({'lockfileVersion': 3, 'packages': packages}).encode(),
                            'root/server.js': b'const a = require("a");'})
        def handler(request):
            if request.url.host == 'github.com':
                return httpx.Response(200, content=refs())
            if request.url.host == 'codeload.github.com':
                return httpx.Response(200, content=snapshot)
            if request.url.host == 'registry.npmjs.org':
                return httpx.Response(200, content=blobs[request.url.path.split('/')[1]])
            if request.url.path == '/v1/querybatch':
                return httpx.Response(200, json={'results': [{'vulns': [{'id': 'GHSA-test-1234-abcd'}]} if query['package']['name'] == 'b' else {} for query in json.loads(request.content)['queries']]})
            return httpx.Response(200, json={'affected': [{'package': {'name': 'b', 'ecosystem': 'npm'}}]})
        with tempfile.TemporaryDirectory() as directory, httpx.Client(transport=httpx.MockTransport(handler)) as transport:
            settings = Settings.from_env({'SCA_MODE': 'public', 'SCA_PUBLIC_REPOSITORIES': 'owner/repo',
                'SCA_DASHBOARD_TOKEN': 't'*32, 'SCA_DATABASE_PATH': str(Path(directory)/'db.sqlite3')})
            github = PublicGitHubAdapter(('owner/repo',), transport)
            app = create_app(settings, github_adapter=github, osv_adapter=OsvClient(transport), worker_enabled=False,
                             npm_sources_factory=lambda: NpmSources(transport))
            with patch('httpx.HTTPTransport.handle_request', side_effect=AssertionError('network forbidden')), TestClient(app) as client:
                headers = {'Authorization': 'Bearer ' + 't'*32}
                self.assertEqual(client.post('/api/installations/sync', headers=headers).status_code, 200)
                scope = f'/api/installations/9003/repositories/{github.repository_id("owner/repo")}'
                scan = client.post(scope+'/scan', headers=headers, json={'branch': 'main'}).json()['scan_id']
                app.state.worker.run_once()
                result = client.get('/api/scans/'+scan, headers=headers).json()
                self.assertEqual(result['status'], 'completed', result)
                self.assertEqual(result['transitive_summary']['decided'], 1)
                finding = result['findings'][0]
                self.assertEqual(finding['reachability'], 'reachable')
                self.assertEqual(finding['reachability_analysis']['transitive_path'][-1]['package'], 'b')
                self.assertEqual(client.get('/api/scans', headers=headers).json()['items'][0]['transitive_summary']['reachable'], 1)
