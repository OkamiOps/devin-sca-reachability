import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_server import SERVER_AVAILABLE
from test_public_github import archive, refs

if SERVER_AVAILABLE:
    import httpx
    from fastapi.testclient import TestClient
    from sca_reachability.server.app import create_app
    from sca_reachability.server.config import Settings
    from sca_reachability.server.errors import PublicError
    from sca_reachability.server.osv_client import OsvClient
    from sca_reachability.server.public_github import PublicGitHubAdapter, normalize_repository, parse_tarball


@unittest.skipUnless(SERVER_AVAILABLE, 'install the optional server extra')
class PublicByURLTests(unittest.TestCase):
    def test_normalization(self):
        for value, expected in [('Owner/Repo', ('owner/repo', None)), ('Owner/.github', ('owner/.github', None)),
            ('https://github.com/Owner/Repo.git/', ('owner/repo', None)),
            ('https://github.com/o/r/tree/feature/auth', ('o/r', 'feature/auth')),
            ('https://github.com/o/r/tree/main', ('o/r', 'main'))]:
            self.assertEqual(normalize_repository(value), expected)
        for value in (None, '', 'a/..', 'a-/.github', 'a--b/repo', '../a', 'a/b/blob/main/a.py', 'https://evil.test/a/b',
            'http://github.com/a/b', 'https://github.com@evil.test/a/b', 'https://user@github.com/a/b',
            'https://github.com:443/a/b', 'https://github.com/a/b?x=1', 'https://github.com/a/b#x',
            'https://[', 'https://github.com/a/b/tree/../x', 'a/b/tree/main//x', 'a/b/tree/main%20x'):
            with self.subTest(value=value), self.assertRaises(PublicError) as error:
                normalize_repository(value)
            self.assertEqual(error.exception.code, 'invalid_url')

    def test_private_missing_network_and_size_limits(self):
        for status in (401, 404):
            with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(status))) as client:
                adapter = PublicGitHubAdapter((), client)
                with self.assertRaises(PublicError) as error:
                    adapter._refs('a/b')
                self.assertEqual(error.exception.code, 'private_or_missing')
        def timeout(request):
            raise httpx.ReadTimeout('private upstream diagnostics')
        with httpx.Client(transport=httpx.MockTransport(timeout)) as client:
            with self.assertRaises(PublicError) as error:
                PublicGitHubAdapter((), client)._refs('a/b')
            self.assertEqual(error.exception.code, 'network')
            self.assertNotIn('diagnostics', str(error.exception))
        class Chunks(httpx.SyncByteStream):
            def __iter__(self):
                yield b'ab'
                yield b'cd'
        for response in (lambda: httpx.Response(200, headers={'content-length': '999'}, stream=Chunks()),
                         lambda: httpx.Response(200, stream=Chunks())):
            with httpx.Client(transport=httpx.MockTransport(lambda request: response())) as client:
                with self.assertRaises(PublicError) as error:
                    PublicGitHubAdapter((), client)._download('https://codeload.github.com/a/b', 3)
                self.assertEqual(error.exception.code, 'too_large')
        with self.assertRaises(PublicError) as error:
            parse_tarball(archive({'root/a': b'a', 'root/b': b'b'}), max_entries=1)
        self.assertEqual(error.exception.code, 'too_large')

    def app(self, directory, files=None, refs_status=200):
        snapshot = archive(files if files is not None else {
            'root/requirements.txt': b'PyYAML==5.3\n',
            'root/main.py': b'import yaml\nyaml.load("hi")\n'})
        def handler(request):
            if request.url.host == 'github.com':
                return httpx.Response(refs_status, content=refs())
            if request.url.host == 'codeload.github.com':
                return httpx.Response(200, content=snapshot)
            if request.url.path == '/v1/querybatch':
                return httpx.Response(200, json={'results': [{'vulns': [{'id': 'GHSA-test-1234-abcd'}]}]})
            return httpx.Response(200, json={'affected': [{'package': {'name': 'PyYAML', 'ecosystem': 'PyPI'},
                'ecosystem_specific': {'imports': [{'symbols': ['load']}]}}]})
        transport = httpx.MockTransport(handler)
        settings = Settings.from_env({'SCA_MODE': 'public', 'SCA_DASHBOARD_TOKEN': 't'*32,
            'SCA_DATABASE_PATH': str(Path(directory)/'db.sqlite3'), 'SCA_PUBLIC_ORIGIN': 'https://testserver'})
        adapter = PublicGitHubAdapter((), httpx.Client(transport=transport))
        return create_app(settings, github_adapter=adapter, osv_adapter=OsvClient(httpx.Client(transport=transport)), worker_enabled=False)

    def test_pipeline_registration_progress_restart_and_unknown_not_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            app = self.app(directory)
            with TestClient(app, base_url='https://testserver') as client:
                self.assertEqual(client.get('/api/meta').json()['github_configured'], True)
                self.assertEqual(client.post('/api/public/repositories', json={'url': 'a/b'}).status_code, 401)
                self.assertEqual(client.post('/api/session', headers={'Origin': 'https://testserver', 'X-SCA-Request': '1'}, json={'token': 't'*32}).status_code, 200)
                self.assertEqual(client.post('/api/public/repositories', headers={'Origin': 'https://evil.test'}, json={'url': 'a/b'}).status_code, 403)
                headers = {'Origin': 'https://testserver', 'X-SCA-Request': '1'}
                registration = client.post('/api/public/repositories', json={'url': 'https://github.com/a/b/tree/main'}, headers=headers)
                self.assertEqual(registration.status_code, 200, registration.text)
                result = registration.json()
                self.assertEqual(result['default_branch'], 'main')
                self.assertEqual(result['selected_branch'], 'main')
                endpoint = f"/api/public/repositories/{result['repository']['id']}/scan"
                response = client.post(endpoint, json={'branch': 'main'}, headers=headers)
                self.assertEqual(response.status_code, 202, response.text)
                scan_id = response.json()['scan_id']
                stages = []
                original = app.state.worker._progress
                def progress(job, stage, *args, **kwargs):
                    stages.append(stage)
                    return original(job, stage, *args, **kwargs)
                with patch.object(app.state.worker, '_progress', side_effect=progress):
                    app.state.worker.run_once()
                report = client.get('/api/scans/'+scan_id).json()
                self.assertEqual(report['status'], 'completed', report)
                self.assertEqual(report['findings'][0]['reachability'], 'reachable')
                self.assertEqual(list(dict.fromkeys(stages)), ['fetching_snapshot', 'inventory', 'osv', 'reachability', 'persisting', 'completed'])
                self.assertEqual(report['progress']['stage'], 'completed')
                self.assertEqual(report['progress']['completed'], report['progress']['total'])
            with TestClient(self.app(directory), base_url='https://testserver') as client:
                headers = {'Authorization': 'Bearer '+'t'*32}
                response = client.post('/api/installations/sync', headers=headers)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(client.get('/api/installations/9003/repositories', headers=headers).json()['items'][0]['full_name'], 'a/b')

    def test_no_manifest_failure_is_not_empty_success_and_retry_clears_progress(self):
        with tempfile.TemporaryDirectory() as directory, TestClient(self.app(directory, {'root/README.md': b'hello'})) as client:
            headers = {'Authorization': 'Bearer '+'t'*32}
            repo = client.post('/api/public/repositories', json={'url': 'a/b'}, headers=headers).json()['repository']
            scan_id = client.post(f"/api/public/repositories/{repo['id']}/scan", json={'branch': 'main'}, headers=headers).json()['scan_id']
            client.app.state.worker.run_once()
            report = client.get('/api/scans/'+scan_id, headers=headers).json()
            self.assertEqual(report['status'], 'failed')
            self.assertEqual(report['error_code'], 'unsupported_no_manifests')
            self.assertEqual(report['findings'], [])
            self.assertEqual(client.post('/api/scans/'+scan_id+'/retry', headers=headers).status_code, 202)
            self.assertEqual(client.get('/api/scans/'+scan_id, headers=headers).json()['progress']['stage'], 'queued')

    def test_sync_isolates_missing_and_network_failures(self):
        headers = {'Authorization': 'Bearer '+'t'*32}
        with tempfile.TemporaryDirectory() as directory, TestClient(self.app(directory)) as client:
            for name in ('a/missing', 'a/healthy', 'a/timeout'):
                self.assertEqual(client.post('/api/public/repositories', json={'url': name}, headers=headers).status_code, 200)
            def changed_refs(name):
                if name == 'a/missing':
                    raise PublicError('private_or_missing', 'Unavailable', 404)
                if name == 'a/timeout':
                    raise PublicError('network', 'Unavailable', 503)
                return {'main': 'a'*40, 'release': 'b'*40}, 'main'
            with patch.object(client.app.state.worker.github, '_refs', side_effect=changed_refs):
                response = client.post('/api/installations/sync', headers=headers)
            self.assertEqual(response.status_code, 200, response.text)
            repos = client.get('/api/installations/9003/repositories', headers=headers).json()['items']
            self.assertEqual({r['full_name'] for r in repos}, {'a/healthy', 'a/timeout'})
            healthy = next(r for r in repos if r['full_name'] == 'a/healthy')
            branches = client.get(f"/api/installations/9003/repositories/{healthy['id']}/branches", headers=headers).json()['items']
            self.assertEqual({b['name'] for b in branches}, {'main', 'release'})

    def test_rate_cap_invalid_branch_and_errors(self):
        headers = {'Authorization': 'Bearer '+'t'*32}
        with tempfile.TemporaryDirectory() as directory, TestClient(self.app(directory)) as client:
            with patch('sca_reachability.server.public_repositories.MAX_REPOSITORIES', 2):
                for name in ('a/one', 'a/two'):
                    self.assertEqual(client.post('/api/public/repositories', json={'url': name}, headers=headers).status_code, 200)
                self.assertEqual(client.post('/api/public/repositories', json={'url': 'a/three'}, headers=headers).json()['code'], 'repository_cap')
                self.assertEqual(client.post('/api/public/repositories', json={'url': 'a/one'}, headers=headers).status_code, 200)
            self.assertEqual(client.post('/api/public/repositories', json={'url': 'a/one/tree/main/file'}, headers=headers).json()['code'], 'invalid_url')
            with patch('sca_reachability.server.public_repositories.ATTEMPTS_PER_MINUTE', 5):
                self.assertEqual(client.post('/api/public/repositories', json={'url': 'a/one'}, headers=headers).json()['code'], 'rate_limit')
        for status in (401, 404):
            with tempfile.TemporaryDirectory() as directory, TestClient(self.app(directory, refs_status=status)) as client:
                response = client.post('/api/public/repositories', json={'url': 'a/b'}, headers=headers)
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.json()['code'], 'private_or_missing')
