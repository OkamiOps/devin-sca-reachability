import json
import unittest

import httpx

from sca_reachability.models import ReachabilityStatus
from sca_reachability.server.npm_sources import NpmSources
from sca_reachability.server.osv_client import Advisory
from sca_reachability.server.sources import reachability_for
from sca_reachability.server.transitive import repository_entries, trace_transitives
from sca_reachability.static_reachability import SourceCoverage, SourceFile
from test_transitive import components, fixture, package, pin


class NpmEntryTests(unittest.TestCase):
    def analyze(self, files, repo, *, metadata=None, lock_bin=None):
        blobs, packages = fixture(files, **(metadata or {}))
        if lock_bin is not None:
            packages['node_modules/a']['bin'] = lock_bin
        locked = components(packages)
        coverage = SourceCoverage([SourceFile(path, content) for path, content in repo.items()])
        advisories = [[], [Advisory('GHSA-test', None, None, ())]]
        with httpx.Client(transport=httpx.MockTransport(lambda request:
                httpx.Response(200, content=blobs[request.url.path.split('/')[1]]))) as client, NpmSources(client) as sources:
            return trace_transitives(locked, reachability_for(locked, advisories, coverage), coverage, sources)[1][0]

    def test_grunt_literal_loads_every_top_level_js_not_main(self):
        result = self.analyze({'index.js': '', 'tasks/first.js': '',
            'tasks/second.js': 'require("../lib/loader");', 'lib/loader.js': 'require("b");'},
            {'Gruntfile.js': 'module.exports = function(grunt) {\n grunt.loadNpmTasks("a");\n};'})
        self.assertEqual(result.status, ReachabilityStatus.REACHABLE)
        self.assertEqual(result.scope, 'dev_tooling')
        self.assertEqual(result.transitive_path[0]['kind'], 'grunt')
        self.assertEqual(result.transitive_path[0]['line'], 2)
        self.assertEqual(result.transitive_path[1]['file'], 'tasks/second.js')

    def test_grunt_dynamic_comments_regex_nested_coffee_and_collections(self):
        for code in ('grunt.loadNpmTasks(name);', '// grunt.loadNpmTasks("a");',
                     'const r=/grunt.loadNpmTasks("a")/;',
                     'const grunt = other; grunt.loadNpmTasks("a");',
                     'other.grunt.loadNpmTasks("a");'):
            result = self.analyze({'tasks/a.js': 'require("b");'}, {'Gruntfile.js': code})
            self.assertNotEqual(result.status, ReachabilityStatus.REACHABLE)
        for files, metadata in [
            ({'tasks/nested/a.js': 'require("b");'}, {}),
            ({'tasks/.hidden.js': 'require("b");'}, {}),
            ({'tasks/a.coffee': 'require "b"'}, {}),
            ({'tasks/a.js': '', 'tasks/b.coffee': 'require name'}, {}),
            ({'tasks/a.js': 'require("b");'}, {'keywords': ['gruntcollection']}),
            ({'tasks/a.js': 'require("b");'}, {'keywords': 42}),
        ]:
            result = self.analyze(files, {'Gruntfile.js': 'grunt.loadNpmTasks("a");'}, metadata=metadata)
            self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)

    def test_npm_bins_string_object_extensionless_and_node_pinned_bin(self):
        for bins, command, entry in [
            ('cli.js', 'a --reporter spec', 'cli.js'),
            ({'runner': './cli.js'}, 'runner && runner --flag; runner', 'cli.js'),
            ({'runner': 'bin/run'}, 'runner', 'bin/run'),
            ({'runner': 'bin/run'}, 'node node_modules/a/bin/run test', 'bin/run'),
        ]:
            result = self.analyze({entry: '#!/usr/bin/env node\nrequire("b");'},
                {'package.json': json.dumps({'scripts': {'test': command}})}, metadata={'bin': bins}, lock_bin=bins)
            self.assertEqual(result.status, ReachabilityStatus.REACHABLE, command)
            self.assertEqual(result.scope, 'test_only')
            self.assertEqual(result.transitive_path[0]['kind'], 'npm_script')
            self.assertEqual(result.transitive_path[0]['label'], 'scripts.test')
            self.assertEqual(result.transitive_path[1]['file'], entry)

    def test_ambiguous_shell_and_bin_entries_never_become_reachable(self):
        for command in ('runner $ARGS', 'runner | other', 'runner $(other)', 'FOO=x runner',
                        'echo "hello;runner;hello"', 'echo hi #;runner', 'runner > output'):
            result = self.analyze({'cli.js': 'require("b");'},
                {'package.json': json.dumps({'scripts': {'test': command}})},
                metadata={'bin': {'runner': 'cli.js'}}, lock_bin={'runner': 'cli.js'})
            self.assertNotEqual(result.status, ReachabilityStatus.REACHABLE, command)
        result = self.analyze({'cli.js': 'require("b");'},
            {'package.json': '{"scripts":{"dev":"runner"}}'}, metadata={'bin': {'different': 'cli.js'}},
            lock_bin={'runner': 'cli.js'})
        self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)
        self.assertEqual(result.transitive_unknown_reason, 'bin')
        for entry, content in [('missing.js', None), ('cli.js', '#!/bin/sh\nrequire("b");')]:
            result = self.analyze({'other.js': ''} if content is None else {entry: content},
                {'package.json': '{"scripts":{"dev":"runner"}}'}, metadata={'bin': {'runner': entry}},
                lock_bin={'runner': entry})
            self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)

    def test_binary_collisions_and_hoisted_bins(self):
        _, packages = fixture()
        packages['node_modules/a']['bin'] = {'runner': 'cli.js'}
        packages['node_modules/b']['bin'] = {'runner': 'cli.js'}
        locked = components(packages)
        nodes = {node.lock_path: node for node in locked}
        coverage = SourceCoverage([SourceFile('package.json', '{"scripts":{"dev":"runner"}}')])
        entries, uncertain = repository_entries(nodes, coverage, 'package-lock.json')
        self.assertFalse(entries)
        self.assertTrue(uncertain)
        packages['node_modules/a'].pop('bin')
        nodes = {node.lock_path: node for node in components(packages)}
        entries, uncertain = repository_entries(nodes, coverage, 'package-lock.json')
        self.assertIn('node_modules/b', entries)
        self.assertFalse(uncertain)

    def test_dynamic_script_blocks_new_negative_proof(self):
        result = self.analyze({'index.js': '', 'cli.js': ''},
            {'server.js': 'require("a");', 'package.json': '{"scripts":{"test":"a $ARGS"}}'},
            metadata={'bin': 'cli.js'}, lock_bin='cli.js')
        self.assertEqual(result.status, ReachabilityStatus.UNKNOWN)

    def test_hoisted_bin_invalidates_previous_negative_ancestor_proof(self):
        blobs, packages = fixture()
        blobs['b'] = package('b', {'cli.js': '#!/usr/bin/env node\nrequire("c");'},
                             bin={'runner': 'cli.js'})
        packages['node_modules/b'].update(pin(blobs['b'], 'b'), bin={'runner': 'cli.js'},
                                        dependencies={'c': '1.0.0'})
        blobs['c'] = package('c')
        packages['node_modules/c'] = pin(blobs['c'], 'c')
        locked = components(packages)
        coverage = SourceCoverage([SourceFile('server.js', 'module.exports = true;'),
                                   SourceFile('package.json', '{"scripts":{"test":"runner"}}')])
        advisories = [[], [], [Advisory('GHSA-test', None, None, ())]]
        baseline = reachability_for(locked, advisories, coverage)
        self.assertEqual(baseline[2][0].status, ReachabilityStatus.UNREACHABLE)
        with httpx.Client(transport=httpx.MockTransport(lambda request:
                httpx.Response(200, content=blobs[request.url.path.split('/')[1]]))) as client, NpmSources(client) as sources:
            result = trace_transitives(locked, baseline, coverage, sources)[2][0]
        self.assertEqual(result.status, ReachabilityStatus.REACHABLE)
        self.assertEqual(result.scope, 'test_only')
        self.assertEqual(result.transitive_path[1]['file'], 'cli.js')
        self.assertEqual(result.transitive_path[-1]['package'], 'c')
        blobs['d'] = package('d', {'cli.js': ''}, bin={'runner': 'cli.js'})
        packages['']['dependencies']['d'] = '1.0.0'
        packages['node_modules/d'] = {**pin(blobs['d'], 'd'), 'bin': {'runner': 'cli.js'}}
        locked = components(packages)
        advisories.append([])
        baseline = reachability_for(locked, advisories, coverage)
        self.assertEqual(baseline[2][0].status, ReachabilityStatus.UNREACHABLE)
        with httpx.Client(transport=httpx.MockTransport(lambda request:
                httpx.Response(200, content=blobs[request.url.path.split('/')[1]]))) as client, NpmSources(client) as sources:
            ambiguous = trace_transitives(locked, baseline, coverage, sources)[2][0]
        self.assertEqual(ambiguous.status, ReachabilityStatus.UNKNOWN)
        self.assertEqual(ambiguous.transitive_unknown_reason, 'entry_dynamic')
        self.assertIn('Bin runner ambíguo', ambiguous.reason)
