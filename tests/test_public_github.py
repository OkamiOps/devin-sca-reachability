import gzip
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_server import SERVER_AVAILABLE

if SERVER_AVAILABLE:
    import httpx
    import tarfile
    from fastapi.testclient import TestClient
    from sca_reachability.server.app import create_app
    from sca_reachability.server.config import Settings
    from sca_reachability.server.errors import ScanError
    from sca_reachability.server.osv_client import OsvClient
    from sca_reachability.server.public_github import PublicGitHubAdapter, parse_refs, parse_tarball


def packet(value):
    return f'{len(value) + 4:04x}'.encode() + value


def refs():
    return (packet(b'# service=git-upload-pack\n') + b'0000' +
            packet(b'a' * 40 + b' HEAD\0symref=HEAD:refs/heads/main\n') +
            packet(b'a' * 40 + b' refs/heads/main\n') + b'0000')


def archive(files, link=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        if link:
            info = tarfile.TarInfo('root/link.py')
            info.type = link
            info.linkname = '../../escape'
            tar.addfile(info)
    return output.getvalue()


@unittest.skipUnless(SERVER_AVAILABLE, 'install the optional server extra')
class PublicTests(unittest.TestCase):
    def test_config(self):
        s = Settings.from_env({'SCA_MODE': 'public'})
        self.assertFalse(s.github_configured)
        self.assertIsNone(s.operator_token)
        self.assertIsNone(s.webhook_secret)
        s = Settings.from_env({'SCA_MODE': 'public', 'SCA_PUBLIC_REPOSITORIES': 'Owner/Repo', 'SCA_DASHBOARD_TOKEN': 't'*32})
        self.assertTrue(s.github_configured)
        self.assertEqual(s.public_repositories, ('owner/repo',))
        for name in ['../repo', 'owner/../../evil', 'https://github.com/a/b', 'a/b?x', ','.join(f'a/r{i}' for i in range(11))]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                Settings.from_env({'SCA_MODE': 'public', 'SCA_PUBLIC_REPOSITORIES': name})
        with self.assertRaises(ValueError):
            Settings.from_env({'SCA_MODE': 'public', 'SCA_ALLOW_LOOPBACK_ORIGINS': '1'})

    def test_refs(self):
        self.assertEqual(parse_refs(refs()), ({'main': 'a'*40}, 'main'))
        for value in [b'', b'zzzz', b'0003', refs()[:-6], refs().replace(b'a'*40, b'z'*40)]:
            with self.subTest(value=value), self.assertRaises(ScanError):
                parse_refs(value)

    def test_tar(self):
        for link in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            tree, blobs = parse_tarball(archive({'root/a.py': b'print(1)'}, link))
            self.assertEqual(tree[1]['mode'], '120000')
            sha = hashlib.sha1(b'blob 8\0print(1)').hexdigest()
            self.assertEqual(blobs[sha], b'print(1)')
        for path in ['../evil', '/root/a', 'root/../evil', 'root/./a', 'root//a', 'root/evil\\a']:
            with self.subTest(path=path), self.assertRaises(ScanError):
                parse_tarball(archive({path: b'x'}))
        for data in (b'', b'not gzip', archive({}) , archive({'root/a': b'x'})[:30]):
            with self.assertRaises(ScanError):
                parse_tarball(data)
        for cap in ['MAX_COMPRESSED', 'MAX_UNCOMPRESSED', 'MAX_ENTRIES']:
            with patch('sca_reachability.server.public_github.' + cap, 1), self.assertRaises(ScanError):
                parse_tarball(archive({'root/a': b'abc', 'root/b': b'def'}))

    def test_adapter_bounds_and_scope(self):
        def handler(request):
            return httpx.Response(302, headers={'Location': 'https://evil.invalid/payload'})
        p = PublicGitHubAdapter(('owner/repo',), httpx.Client(transport=httpx.MockTransport(handler)))
        with self.assertRaises(ScanError):
            p.list_repositories(9003)
        with self.assertRaises(ScanError):
            p.get_tree(9003, p.repository_id('owner/repo'), 'owner/repo', '../bad')
        with self.assertRaises(ScanError):
            p.get_blob(1, 1, 'evil/repo', 'a'*40)
        with self.assertRaises(ScanError):
            p.get_blob(9003, p.repository_id('owner/repo'), 'owner/repo', 'a'*40)
        p._client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b'abc')))
        with self.assertRaises(ScanError):
            p._download('https://github.com/owner/repo', 2)

    def test_worker_public_pipeline(self):
        snapshot = archive({
            'root/requirements.txt': b'PyYAML==5.3\n',
            'root/main.py': b'import yaml\nyaml.load("hi")\n',
            'root/package-lock.json': json.dumps({'lockfileVersion': 3, 'packages': {
                '': {}, 'node_modules/lodash': {'version': '4.17.20', 'dev': True},
            }}).encode(),
            'root/main.js': b'const p = require("lodash");\np.template();\nrequire(path.resolve(__dirname + "/config/" + env + ".js"));\n',
        })
        requests = []
        def handler(request):
            requests.append(str(request.url))
            if request.url.host == 'github.com':
                return httpx.Response(200, content=refs())
            if request.url.host == 'codeload.github.com':
                self.assertTrue(request.url.path.endswith('a'*40))
                return httpx.Response(200, content=snapshot)
            if request.url.path == '/v1/querybatch':
                return httpx.Response(200, json={'results': [
                    {'vulns': [{'id': 'GHSA-test-1234-abcd'}]} for _ in json.loads(request.content)['queries']
                ]})
            return httpx.Response(200, json={'affected': [
                {'package': {'name': 'PyYAML', 'ecosystem': 'PyPI'}, 'ecosystem_specific': {'imports': [{'symbols': ['load']}]}},
                {'package': {'name': 'lodash', 'ecosystem': 'npm'}, 'ecosystem_specific': {'imports': [{'symbols': ['template']}]}},
            ]})
        transport = httpx.MockTransport(handler)
        p = PublicGitHubAdapter(('owner/repo',), httpx.Client(transport=transport))
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings.from_env({'SCA_MODE': 'public', 'SCA_PUBLIC_REPOSITORIES': 'owner/repo', 'SCA_DASHBOARD_TOKEN': 't'*32, 'SCA_DATABASE_PATH': str(Path(directory)/'db.sqlite3')})
            app = create_app(settings, github_adapter=p, osv_adapter=OsvClient(httpx.Client(transport=transport)), worker_enabled=False)
            with patch('httpx.HTTPTransport.handle_request', side_effect=AssertionError('network forbidden')), TestClient(app) as c:
                headers = {'Authorization': 'Bearer ' + 't'*32}
                self.assertEqual(c.get('/api/meta').json()['mode'], 'public')
                self.assertEqual(c.post('/api/webhooks/github').status_code, 404)
                self.assertEqual(c.post('/api/demo/push', headers=headers).status_code, 404)
                self.assertEqual(c.post('/api/installations/sync', headers=headers).status_code, 200)
                scope = f'/api/installations/9003/repositories/{p.repository_id("owner/repo")}'
                self.assertTrue(c.get(scope+'/branches', headers=headers).json()['items'][0]['selected'])
                scan = c.post(scope+'/scan', headers=headers, json={'branch': 'main'}).json()['scan_id']
                app.state.worker.run_once()
                result = c.get('/api/scans/'+scan, headers=headers).json()
                self.assertEqual(result['status'], 'completed', result)
                self.assertEqual(result['source'], 'github')
                self.assertEqual(result['findings'][0]['reachability'], 'reachable')
                self.assertTrue(result['findings'][0]['reachability_evidence'])
                findings = {item['package_name']: item for item in result['findings']}
                self.assertEqual(findings['pyyaml']['reachability_scope'], 'production')
                self.assertEqual(findings['lodash']['reachability_scope'], 'dev_tooling')
                self.assertTrue(findings['lodash']['reachability_analysis']['dependency_dev'])
                self.assertEqual(findings['lodash']['reachability_analysis']['notes'][0]['line'], 3)
                listed = c.get('/api/scans', headers=headers).json()['items'][0]
                self.assertEqual(listed['reachability_scope_counts'],
                                 {'production': 1, 'test_only': 0, 'dev_tooling': 1, 'unreported': 0})
                with app.state.database.transaction() as connection:
                    connection.execute("UPDATE scan_findings SET reachability_analysis_json = '{}' WHERE scan_id = ?", (scan,))
                legacy = c.get('/api/scans/'+scan, headers=headers).json()
                self.assertTrue(all(item['reachability_scope'] is None for item in legacy['findings']))
                self.assertEqual(c.get('/api/scans', headers=headers).json()['items'][0]['reachability_scope_counts']['unreported'], 2)
        self.assertFalse(any('api.github.com' in url for url in requests))
