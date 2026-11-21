import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

try:
    import httpx
    import jwt
    from fastapi.testclient import TestClient
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from sca_reachability.server.app import create_app
    from sca_reachability.server.config import Settings
    from sca_reachability.server.errors import RetryableError, ScanError
    from sca_reachability.server.github import GitHubAppClient
    from sca_reachability.server.manifests import (
        LockedComponent, inventory_manifests, _parse_package_lock, _parse_requirements,
    )
    from sca_reachability.server.osv_client import DemoOsvAdapter, OsvClient
    SERVER_AVAILABLE = True
except ModuleNotFoundError as error:
    if error.name.split(".")[0] not in {"httpx", "jwt", "fastapi", "cryptography", "packaging"}:
        raise
    SERVER_AVAILABLE = False


TOKEN = "t" * 32
AUTH = {"Authorization": "Bearer " + TOKEN}
CSRF = {"Origin": "http://testserver", "X-SCA-Request": "1"}
SCOPE = "/api/installations/1/repositories/10"


class FakeGitHub:
    def __init__(self):
        self.tree_commits = []
        self.failures = 0
        self.truncated = False
        self.cleared = []
        self.content = json.dumps({
            "lockfileVersion": 3,
            "packages": {"": {}, "node_modules/fictional-demo-package": {"version": "1.0.0"}},
        }).encode()

    def list_installations(self):
        return [{"id": value, "account": "fictional", "status": "active"} for value in (1, 2)]

    def list_repositories(self, installation_id):
        return [{"id": installation_id * 10, "full_name": f"fictional/repo{installation_id}",
                 "default_branch": "main"}]

    def list_branches(self, installation_id, repository_id, repository):
        return ["main", "release", "feature/test"]

    def resolve_commit_sha(self, installation_id, repository_id, repository, branch):
        return "a" * 40

    def get_tree(self, installation_id, repository_id, repository, commit_sha):
        self.tree_commits.append(commit_sha)
        if self.failures:
            self.failures -= 1
            raise RetryableError("Temporary fixture failure")
        return [{"path": "package-lock.json", "mode": "100644", "type": "blob",
                 "sha": "b" * 40}], self.truncated

    def get_blob(self, installation_id, repository_id, repository, sha):
        return self.content

    def clear_installation(self, installation_id):
        self.cleared.append(installation_id)

    def close(self):
        pass


@unittest.skipUnless(SERVER_AVAILABLE, "install the optional server extra")
class ServerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.settings = Settings.from_env({
            "SCA_DATABASE_PATH": str(Path(self.directory.name) / "server.sqlite3"),
            "SCA_DASHBOARD_TOKEN": TOKEN,
            "SCA_ALLOWED_INSTALLATION_IDS": "1",
            "SCA_GITHUB_WEBHOOK_SECRET": "fixture-signing-key",
        })
        self.github = FakeGitHub()
        self.network = patch("httpx.HTTPTransport.handle_request",
                             side_effect=AssertionError("Live network is forbidden in tests"))
        self.network.start()
        self.addCleanup(self.network.stop)

    def client(self, *, demo=False, github=True, **kwargs):
        settings = replace(self.settings, mode="demo") if demo else self.settings
        app = create_app(
            settings, github_adapter=self.github if github and not demo else None,
            osv_adapter=None if demo else DemoOsvAdapter(), worker_enabled=False, **kwargs,
        )
        client = self.enterContext(TestClient(app))
        if github and not demo:
            self.assertEqual(client.post("/api/installations/sync", headers=AUTH).status_code, 200)
        return app, client

    def select(self, client, names=("main",)):
        result = client.put(SCOPE + "/branches", json={"branches": list(names)}, headers=AUTH)
        self.assertEqual(result.status_code, 200, result.text)
        return result

    def push(self, client, delivery="fixture-1", *, branch="main", sha="c" * 40,
             deleted=False, ref=None, installation=1, repository=10, event="push", payload=None):
        if payload is None:
            payload = {"installation": {"id": installation},
                       "repository": {"id": repository, "full_name": "fictional/repo1"},
                       "ref": ref or "refs/heads/" + branch, "after": sha, "deleted": deleted}
        raw = json.dumps(payload, separators=(",", ":")).encode()
        signature = "sha256=" + hmac.new(
            b"fixture-signing-key", raw, hashlib.sha256
        ).hexdigest()
        return client.post("/api/webhooks/github", content=raw, headers={
            "X-GitHub-Delivery": delivery, "X-GitHub-Event": event,
            "X-Hub-Signature-256": signature,
        })

    def test_demo_offline_login_selection_push_and_release(self):
        self.settings = replace(self.settings, ai_enabled=True, ai_api_key="fixture", ai_model="fixture")
        with patch("sca_reachability.server.app.create_provider_from_env") as factory:
            app, client = self.client(demo=True)
            factory.assert_not_called()
        meta = client.get("/api/meta").json()
        self.assertFalse(meta["ai_configured"])
        self.assertFalse(meta["github_configured"])
        self.assertEqual(client.get("/api/dashboard").status_code, 401)
        response = client.post("/api/session", json={"token": "local-demo"}, headers=CSRF)
        self.assertEqual(response.json(), {"authenticated": True})
        self.assertIn("HttpOnly", response.headers["set-cookie"])
        self.assertIn("SameSite=strict", response.headers["set-cookie"])
        initial = client.get("/api/scans").json()["items"][0]
        detail = client.get("/api/scans/" + initial["id"]).json()
        self.assertEqual((detail["component_count"], detail["finding_count"]), (1, 1))
        self.assertEqual(detail["findings"][0]["reachability"], "unknown")
        self.assertIn("Aviso sintético", detail["findings"][0]["summary"])
        self.assertEqual(detail["explanation"]["source"], "deterministic")
        path = "/api/installations/9001/repositories/9002/branches"
        self.assertEqual(client.put(path, json={"branches": ["main", "release"]}).status_code, 403)
        self.assertEqual(client.put(
            path, json={"branches": ["main"]},
            headers={**CSRF, "Origin": "https://foreign.invalid"},
        ).status_code, 403)
        self.assertEqual(client.put(path, json={"branches": ["main", "release"]},
                                    headers=CSRF).status_code, 200)
        result = client.post("/api/demo/push", json={"repository_id": 9002, "branch": "release"},
                             headers=CSRF)
        self.assertEqual(result.status_code, 202, result.text)
        self.assertTrue(app.state.worker.run_once())
        release = client.get("/api/scans/" + result.json()["scan_id"]).json()
        self.assertEqual(release["components"][0]["version"], "1.1.0")
        self.assertEqual(release["finding_count"], 0)
        ignored = client.post("/api/demo/push", json={"repository_id": 9002, "branch": "develop"},
                              headers=CSRF)
        self.assertEqual(ignored.status_code, 400)
        self.assertEqual(client.post("/api/demo/push", json={"repository_id": 9002, "branch": ""},
                                     headers=CSRF).status_code, 400)

    def test_deliveries_expose_current_linked_scan_status_without_changing_event_outcome(self):
        app, client = self.client()
        self.assertTrue(client.get("/api/meta").json()["github_configured"])
        self.select(client)
        scan_id = self.push(client).json()["scan_id"]
        def delivery():
            return client.get("/api/deliveries", headers=AUTH).json()["items"][0]
        self.assertEqual((delivery()["status"], delivery()["scan_id"], delivery()["scan_status"]),
                         ("queued", scan_id, "queued"))
        app.state.worker.run_once()
        self.assertEqual((delivery()["status"], delivery()["scan_status"]), ("queued", "completed"))
        self.push(client, "ignored", branch="release")
        self.assertIsNone(delivery()["scan_id"])
        self.assertIsNone(delivery()["scan_status"])
        self.assertEqual(delivery()["status"], "ignored")

    def test_scan_list_includes_compact_advisory_and_package_search_metadata(self):
        app, client = self.client()
        self.assertEqual(client.get("/api/scans", headers=AUTH).json()["items"], [])
        self.select(client)
        self.push(client)
        queued = client.get("/api/scans", headers=AUTH).json()["items"][0]
        self.assertEqual(queued["advisory_ids"], [])
        self.assertEqual(queued["package_names"], [])
        app.state.worker.run_once()
        completed = client.get("/api/scans", headers=AUTH).json()["items"][0]
        self.assertEqual(completed["advisory_ids"], ["DEMO-0001"])
        self.assertEqual(completed["package_names"], ["fictional-demo-package"])
        self.github.content = self.github.content.replace(b"1.0.0", b"1.1.0")
        self.push(client, "clean", sha="d" * 40)
        app.state.worker.run_once()
        clean = client.get("/api/scans", headers=AUTH).json()["items"][0]
        self.assertEqual(clean["advisory_ids"], [])
        self.assertEqual(clean["package_names"], ["fictional-demo-package"])

    def test_explicit_failed_scan_retry_is_scoped_pinned_and_fences_old_jobs(self):
        app, client = self.client()
        self.select(client)
        self.github.truncated = True
        scan_id = self.push(client).json()["scan_id"]
        app.state.worker.run_once()
        with app.state.database.connection() as connection:
            old_job = dict(connection.execute("SELECT * FROM jobs WHERE scan_id = ?", (scan_id,)).fetchone())
        path = "/api/scans/" + scan_id + "/retry"
        self.assertEqual(client.post(path).status_code, 401)
        result = client.post(path, headers=AUTH)
        self.assertEqual(result.status_code, 202, result.text)
        self.assertEqual(result.json()["scan_id"], scan_id)
        with app.state.database.connection() as connection:
            job = connection.execute("SELECT * FROM jobs WHERE scan_id = ?", (scan_id,)).fetchone()
            self.assertGreater(job["id"], old_job["id"])
            self.assertEqual((job["commit_sha"], job["attempts"]), ("c" * 40, 0))
        app.state.worker._fail(old_job, "stale")
        self.assertEqual(client.get("/api/scans/" + scan_id, headers=AUTH).json()["status"], "queued")
        self.assertEqual(client.post(path, headers=AUTH).status_code, 409)
        self.github.truncated = False
        app.state.worker.run_once()
        detail = client.get("/api/scans/" + scan_id, headers=AUTH).json()
        self.assertEqual(detail["status"], "completed")
        self.assertEqual(self.github.tree_commits, ["c" * 40, "c" * 40])
        self.assertEqual(client.post(path, headers=AUTH).status_code, 409)
        self.assertEqual(client.post("/api/scans/missing/retry", headers=AUTH).status_code, 404)
        self.github.truncated = True
        failed = self.push(client, "other-failed", sha="d" * 40).json()["scan_id"]
        app.state.worker.run_once()
        self.select(client, ())
        self.assertEqual(client.post("/api/scans/" + failed + "/retry", headers=AUTH).status_code, 400)

    def test_sessions_origin_hash_expiry_logout(self):
        app, client = self.client(demo=True)
        self.assertEqual(client.post("/api/session", json={"token": "local-demo"}).status_code, 403)
        self.assertEqual(client.post("/api/session", json={"token": "local-demo"},
                                    headers={**CSRF, "Origin": "https://foreign.invalid"}).status_code, 403)
        self.assertEqual(client.post("/api/session", json={"token": "wrong"},
                                    headers=CSRF).status_code, 401)
        client.post("/api/session", json={"token": "local-demo"}, headers=CSRF)
        raw_cookie = client.cookies.get("sca_session")
        with app.state.database.connection() as connection:
            stored = connection.execute("SELECT token_hash FROM sessions").fetchone()[0]
        self.assertNotEqual(raw_cookie, stored)
        self.assertEqual(client.delete("/api/session", headers=CSRF).status_code, 204)
        self.assertEqual(client.get("/api/installations").status_code, 401)
        client.post("/api/session", json={"token": "local-demo"}, headers=CSRF)
        with app.state.database.transaction() as connection:
            connection.execute("UPDATE sessions SET expires_at = 0")
        self.assertEqual(client.get("/api/installations").status_code, 401)

    def test_live_unconfigured_starts_and_fails_closed(self):
        _, client = self.client(github=False)
        self.assertFalse(client.get("/api/meta").json()["github_configured"])
        self.assertEqual(client.get("/api/dashboard", headers=AUTH).json()["repositories"], 0)
        self.assertEqual(client.post("/api/installations/sync", headers=AUTH).status_code, 503)
        self.assertEqual(client.post("/api/demo/push", headers=AUTH, json={}).status_code, 404)

    def test_branches_validate_exact_names_and_empty(self):
        _, client = self.client()
        self.select(client, ["main", "feature/test"])
        self.assertEqual(client.put(SCOPE + "/branches", headers=AUTH,
                                    json={"branches": ["Main"]}).status_code, 400)
        self.assertEqual(client.put(SCOPE + "/branches", headers=AUTH,
                                    json={"branches": ["main"] * 21}).status_code, 400)
        self.assertFalse(any(item["selected"] for item in self.select(client, []).json()["items"]))
        self.assertEqual(client.get("/api/installations/2/repositories", headers=AUTH).status_code, 404)
        self.assertEqual(client.get("/api/installations", headers=AUTH).json()["items"][0]["id"], 1)

    def test_signed_push_pinned_sha_duplicate_and_changed_digest(self):
        app, client = self.client()
        self.select(client, ["feature/test"])
        result = self.push(client, branch="feature/test")
        self.assertEqual(result.status_code, 200, result.text)
        scan_id = result.json()["scan_id"]
        self.assertTrue(self.push(client, branch="feature/test").json()["duplicate"])
        self.assertEqual(self.push(client, branch="feature/test", sha="d" * 40).status_code, 409)
        app.state.worker.run_once()
        self.assertEqual(self.github.tree_commits, ["c" * 40])
        detail = client.get("/api/scans/" + scan_id, headers=AUTH).json()
        self.assertEqual(detail["branch"], "feature/test")
        self.assertEqual(detail["status"], "completed")

    def test_manual_scan_resolves_commit_requires_selection_and_deduplicates(self):
        app, client = self.client()
        self.select(client)
        self.assertEqual(client.post(SCOPE + "/scan", headers=AUTH, json={}).status_code, 400)
        self.assertEqual(client.post(
            SCOPE + "/scan", headers=AUTH, json={"branch": "release"}
        ).status_code, 400)
        response = client.post(SCOPE + "/scan", headers=AUTH, json={"branch": "main"})
        self.assertEqual(response.status_code, 202, response.text)
        scan_id = response.json()["scan_id"]
        repeated = self.push(client, "same-sha", sha="A" * 40)
        self.assertEqual(repeated.json()["scan_id"], scan_id)
        app.state.worker.run_once()
        self.assertEqual(self.github.tree_commits, ["a" * 40])
        with patch.object(self.github, "resolve_commit_sha", side_effect=RetryableError("private")):
            failure = client.post(SCOPE + "/scan", headers=AUTH, json={"branch": "main"})
        self.assertEqual(failure.status_code, 503)
        self.assertNotIn("private", failure.text)

    def test_webhook_rejects_bad_signature_and_malformed_before_storage(self):
        app, client = self.client()
        self.assertEqual(client.post("/api/webhooks/github", content=b"{}").status_code, 400)
        headers = {"X-GitHub-Delivery": "bad", "X-GitHub-Event": "push",
                   "X-Hub-Signature-256": "sha256=" + "0" * 64}
        self.assertEqual(client.post("/api/webhooks/github", content=b"{}", headers={
            "X-GitHub-Delivery": "missing", "X-GitHub-Event": "push",
        }).status_code, 401)
        self.assertEqual(client.post("/api/webhooks/github", content=b"{}", headers=headers).status_code, 401)
        self.assertEqual(self.push(client, payload={}).status_code, 400)
        with app.state.database.connection() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0], 0)

    def test_push_ignored_cases_have_audit_reason(self):
        app, client = self.client()
        self.select(client)
        for index, kwargs in enumerate((
            {"branch": "release"}, {"deleted": True}, {"ref": "refs/tags/v1"},
            {"installation": 2, "repository": 20}, {"repository": 99},
        )):
            self.assertEqual(self.push(client, str(index), **kwargs).json()["status"], "ignored")
        with app.state.database.connection() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 0)
            self.assertTrue(all(row[0] for row in connection.execute("SELECT reason FROM deliveries")))

    def test_concurrent_delivery_transaction_enqueues_once(self):
        app, client = self.client()
        self.select(client)
        raw = json.dumps({
            "installation": {"id": 1}, "repository": {"id": 10, "full_name": "fictional/repo1"},
            "ref": "refs/heads/main", "after": "c" * 40, "deleted": False,
        }).encode()
        signature = "sha256=" + hmac.new(b"fixture-signing-key", raw, hashlib.sha256).hexdigest()
        def ingest(_):
            return app.state.webhooks.ingest(delivery_id="concurrent", event="push",
                                            signature=signature, raw_body=raw)
        with ThreadPoolExecutor(max_workers=6) as executor:
            results = list(executor.map(ingest, range(6)))
        self.assertEqual(sum(not result.duplicate for result in results), 1)
        with app.state.database.connection() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 1)

    def test_repository_removal_cancels_and_hides_history(self):
        app, client = self.client()
        self.select(client)
        first = self.push(client).json()["scan_id"]
        app.state.worker.run_once()
        queued = self.push(client, "second", sha="d" * 40).json()["scan_id"]
        response = self.push(client, "remove", event="installation_repositories", payload={
            "installation": {"id": 1}, "action": "removed",
            "repositories_removed": [{"id": 10, "full_name": "fictional/repo1"}],
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(client.get("/api/scans/" + first, headers=AUTH).status_code, 404)
        remaining = client.get("/api/deliveries", headers=AUTH).json()["items"]
        self.assertEqual([item["delivery_id"] for item in remaining], ["remove"])
        self.assertTrue(all(item["repository"] is None for item in remaining))
        self.assertFalse(app.state.worker.run_once())
        with app.state.database.connection() as connection:
            self.assertEqual(connection.execute("SELECT status FROM scans WHERE id = ?", (queued,)).fetchone()[0], "failed")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM branches").fetchone()[0], 0)
        self.assertIn(1, self.github.cleared)

    def test_suspension_cancels_and_denies_scope(self):
        app, client = self.client()
        self.select(client)
        self.push(client)
        self.push(client, "suspend", event="installation", payload={
            "action": "suspend", "installation": {"id": 1, "account": {"login": "fixture"}},
        })
        self.assertEqual(client.get(SCOPE + "/branches", headers=AUTH).status_code, 404)
        self.assertFalse(app.state.worker.run_once())

    def test_retry_limit_and_restart_lease_recovery(self):
        app, client = self.client()
        self.select(client)
        scan_id = self.push(client).json()["scan_id"]
        self.github.failures = 10
        for attempt in range(3):
            self.assertTrue(app.state.worker.run_once())
            with app.state.database.transaction() as connection:
                connection.execute("UPDATE jobs SET available_at = 0")
        self.assertEqual(client.get("/api/scans/" + scan_id, headers=AUTH).json()["status"], "failed")
        self.assertEqual(len(self.github.tree_commits), 3)
        second = self.push(client, "lease", sha="e" * 40).json()["scan_id"]
        with app.state.database.transaction() as connection:
            connection.execute("UPDATE jobs SET status='running',attempts=1,lease_until=0 WHERE scan_id=?", (second,))
            connection.execute("UPDATE scans SET status='running' WHERE id=?", (second,))
        self.github.failures = 0
        app2, client2 = self.client()
        app2.state.worker.recover_expired_leases()
        with app2.state.database.transaction() as connection:
            connection.execute("UPDATE jobs SET available_at=0")
        app2.state.worker.run_once()
        self.assertEqual(client2.get("/api/scans/" + second, headers=AUTH).json()["status"], "completed")

    def test_dashboard_counts_latest_completed_branch_not_history(self):
        app, client = self.client()
        self.select(client)
        for index, sha in enumerate(("c" * 40, "d" * 40)):
            self.push(client, str(index), sha=sha)
            app.state.worker.run_once()
        dashboard = client.get("/api/dashboard", headers=AUTH).json()
        self.assertEqual((dashboard["scans"], dashboard["findings"]), (2, 1))

    def test_truncated_tree_fails_not_clean(self):
        app, client = self.client()
        self.select(client)
        self.github.truncated = True
        scan_id = self.push(client).json()["scan_id"]
        app.state.worker.run_once()
        detail = client.get("/api/scans/" + scan_id, headers=AUTH).json()
        self.assertEqual(detail["status"], "failed")
        self.assertIn("truncated", detail["error"])

    def test_request_limit_static_aliases_and_bearer_unicode(self):
        _, client = self.client()
        self.assertEqual(client.post("/api/webhooks/github", content=b"x" * (1024 * 1024 + 1)).status_code, 413)
        self.assertEqual(client.post(
            "/api/webhooks/github", content=iter([b"x" * 600000, b"x" * 600000])
        ).status_code, 413)
        for path in ("/", "/index.html", "/app.js", "/model.js", "/styles.css", "/static/model.js"):
            self.assertEqual(client.get(path).status_code, 200)
        self.assertIn("import", client.get("/app.js?name=../../pyproject.toml").text)

    def test_ai_provider_once_per_scan_and_close(self):
        class Provider:
            def __init__(self):
                self.calls = []
                self.closed = False
            def __call__(self, metadata):
                self.calls.append(metadata)
                return "Resumo fictício."
            def close(self):
                self.closed = True
        provider = Provider()
        self.addCleanup(lambda: self.assertTrue(provider.closed))
        app, client = self.client(ai_provider=provider)
        self.select(client)
        scan_id = self.push(client).json()["scan_id"]
        app.state.worker.run_once()
        for _ in range(2):
            detail = client.get("/api/scans/" + scan_id, headers=AUTH).json()
            self.assertEqual(detail["explanation"]["source"], "ai")
        self.assertEqual(len(provider.calls), 1)
        self.assertNotIn("fictional-demo-package", json.dumps(provider.calls))

    def test_demo_persisted_push_survives_adapter_restart(self):
        app, client = self.client(demo=True)
        auth = {"Authorization": "Bearer local-demo"}
        client.put("/api/installations/9001/repositories/9002/branches",
                   json={"branches": ["main", "release"]}, headers=auth)
        scan_id = client.post("/api/demo/push", headers=auth,
                              json={"repository_id": 9002, "branch": "release"}).json()["scan_id"]
        app2, client2 = self.client(demo=True)
        detail = client2.get("/api/scans/" + scan_id, headers=auth).json()
        self.assertEqual(detail["status"], "completed")
        self.assertEqual(detail["components"][0]["version"], "1.1.0")

    def test_empty_inventory_completes_with_incomplete_coverage_warning(self):
        app, client = self.client()
        self.github.content = b"{}"
        self.select(client)
        scan_id = self.push(client).json()["scan_id"]
        app.state.worker.run_once()
        detail = client.get("/api/scans/" + scan_id, headers=AUTH).json()
        self.assertEqual(detail["status"], "completed")
        self.assertEqual(detail["components"], [])
        self.assertTrue(detail["warnings"])

    def test_live_session_secure_and_login_rate_limit(self):
        app, client = self.client()
        response = client.post("/api/session", json={"token": TOKEN}, headers=CSRF)
        self.assertIn("Secure", response.headers["set-cookie"])
        for _ in range(10):
            response = client.post("/api/session", json={"token": "wrong"}, headers=CSRF)
        self.assertEqual(response.status_code, 429)


@unittest.skipUnless(SERVER_AVAILABLE, "install the optional server extra")
class MetadataTests(unittest.TestCase):
    def test_npm_v2_v3_scoped_transitive_and_unsupported_versions(self):
        for version in (2, 3):
            components, warnings = _parse_package_lock(json.dumps({
                "lockfileVersion": version, "packages": {
                    "": {}, "node_modules/@scope/pkg": {"version": "1.2.3", "resolved": "private"},
                    "node_modules/a/node_modules/b": {"version": "2.0.0"},
                    "node_modules/no": {"version": "git+ssh://example.invalid"},
                },
            }).encode(), "package-lock.json")
            self.assertEqual([item.name for item in components], ["@scope/pkg", "b"])
            self.assertEqual(components[0].purl, "pkg:npm/%40scope/pkg@1.2.3")
            self.assertTrue(warnings)
        self.assertTrue(_parse_package_lock(b"{}", "package-lock.json")[1])
        self.assertTrue(_parse_package_lock(b"invalid", "package-lock.json")[1])

    def test_requirements_pins_markers_urls_options_and_empty(self):
        components, warnings = _parse_requirements(
            b"Foo_Bar==1.2.3\nother>=2\n-r private.txt\nx @ https://example.invalid/x\n"
            b"conditional==2.0; python_version>'3'\n", "requirements.txt"
        )
        self.assertEqual([item.name for item in components], ["foo-bar", "conditional"])
        self.assertEqual(len(warnings), 4)
        self.assertEqual(_parse_requirements(b"# comment\n", "requirements.txt"), ([], []))

    def test_inventory_empty_symlink_and_limits(self):
        self.assertTrue(inventory_manifests([], lambda _: b"").warnings)
        symlink = [{"path": "requirements.txt", "type": "blob", "mode": "120000", "sha": "a" * 40}]
        result = inventory_manifests(symlink, lambda _: self.fail("must not read symlinks"))
        self.assertFalse(result.components)
        self.assertTrue(result.warnings)
        tree = [{"path": f"{index}/requirements.txt", "type": "blob", "mode": "100644",
                 "sha": "a" * 40} for index in range(51)]
        result = inventory_manifests(tree, lambda _: b"demo==1.0.0")
        self.assertEqual(len(result.components), 50)
        self.assertTrue(any("incomplete" in item for item in result.warnings))

    def component(self):
        return LockedComponent("fictional-demo-package", "1.0.0", "npm",
                               "pkg:npm/fictional-demo-package@1.0.0", "package-lock.json")

    def test_osv_exact_query_details_and_matching_fixes(self):
        requests = []
        def handler(request):
            requests.append(request)
            self.assertEqual(request.url.host, "api.osv.dev")
            if request.url.path.endswith("querybatch"):
                self.assertEqual(json.loads(request.content), {"queries": [{
                    "package": {"name": "fictional-demo-package", "ecosystem": "npm"},
                    "version": "1.0.0",
                }]})
                return httpx.Response(200, json={"results": [{"vulns": [{"id": "DEMO-0001"}]}]})
            return httpx.Response(200, json={"summary": "fixture", "affected": [
                {"package": {"name": "other", "ecosystem": "npm"},
                 "ranges": [{"events": [{"fixed": "99"}]}]},
                {"package": {"name": "fictional-demo-package", "ecosystem": "npm"},
                 "ranges": [{"events": [{"fixed": "1.1.0"}]}]},
            ]})
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            result = OsvClient(client).query([self.component()])
        self.assertEqual(result[0][0].fixed_versions, ("1.1.0",))
        self.assertEqual(len(requests), 2)

    def test_osv_errors_pagination_count_redirect_and_empty(self):
        for payload in ({"results": [{"error": {"message": "fixture"}}]},
                        {"results": [{"next_page_token": "more"}]}, {"results": []}):
            with self.subTest(payload=payload), httpx.Client(
                transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))
            ) as client:
                with self.assertRaises(ScanError):
                    OsvClient(client).query([self.component()])
        with httpx.Client(transport=httpx.MockTransport(
            lambda _: httpx.Response(302, headers={"Location": "https://foreign.invalid"})
        )) as client:
            with self.assertRaises(ScanError):
                OsvClient(client).query([self.component()])
        with httpx.Client(transport=httpx.MockTransport(
            lambda _: self.fail("empty inventory must not query OSV")
        )) as client:
            self.assertEqual(OsvClient(client).query([]), [])

    def test_osv_batches_at_100_and_rejects_unrelated_details(self):
        sizes = []
        def handler(request):
            queries = json.loads(request.content)["queries"]
            sizes.append(len(queries))
            return httpx.Response(200, json={"results": [{} for _ in queries]})
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            self.assertEqual(len(OsvClient(client).query([self.component()] * 101)), 101)
        self.assertEqual(sizes, [100, 1])
        def wrong_package(request):
            if request.method == "POST":
                return httpx.Response(200, json={"results": [{"vulns": [{"id": "DEMO-1"}]}]})
            return httpx.Response(200, json={"affected": [
                {"package": {"name": "other", "ecosystem": "npm"}}
            ]})
        with httpx.Client(transport=httpx.MockTransport(wrong_package)) as client:
            with self.assertRaises(ScanError):
                OsvClient(client).query([self.component()])

    def test_github_jwt_readonly_scoped_token_pinned_tree_and_blob(self):
        with tempfile.TemporaryDirectory() as directory:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            keypath = Path(directory) / "fixture.pem"
            keypath.write_bytes(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            settings = Settings.from_env({
                "SCA_GITHUB_APP_ID": "123", "SCA_GITHUB_PRIVATE_KEY_PATH": str(keypath),
                "SCA_ALLOWED_INSTALLATION_IDS": "1",
            })
            paths = []
            def handler(request):
                self.assertEqual(request.url.host, "api.github.com")
                paths.append(request.url.path)
                if request.url.path.endswith("access_tokens"):
                    claims = jwt.decode(request.headers["authorization"][7:], key.public_key(), algorithms=["RS256"])
                    self.assertLessEqual(claims["exp"] - time.time(), 600)
                    self.assertEqual(json.loads(request.content), {
                        "permissions": {"contents": "read", "metadata": "read"}, "repository_ids": [10],
                    })
                    return httpx.Response(201, json={"token": "fixture-only",
                                                   "expires_at": "2099-01-01T00:00:00Z"})
                if "/git/commits/" in request.url.path:
                    self.assertTrue(request.url.path.endswith("a" * 40))
                    return httpx.Response(200, json={"tree": {"sha": "b" * 40}})
                if "/git/trees/" in request.url.path:
                    return httpx.Response(200, json={"tree": [], "truncated": False})
                return httpx.Response(200, json={"encoding": "base64",
                                               "content": "ZGVt\n bw==\n"})
            with httpx.Client(transport=httpx.MockTransport(handler)) as client:
                adapter = GitHubAppClient(settings, client)
                self.assertEqual(adapter.get_tree(1, 10, "fictional/repo1", "a" * 40), ([], False))
                self.assertEqual(adapter.get_blob(1, 10, "fictional/repo1", "c" * 40), b"demo")
                self.assertEqual(len([path for path in paths if path.endswith("access_tokens")]), 1)
                adapter.clear_installation(1)
                self.assertFalse(adapter._tokens)
            pages = []
            def paginated(request):
                self.assertEqual(request.url.host, "api.github.com")
                pages.append(request.url.params["page"])
                headers = {"Link": '<https://foreign.invalid/steal>; rel="next"'} if len(pages) == 1 else {}
                return httpx.Response(200, json=[{
                    "id": len(pages), "account": {"login": "fixture"},
                }], headers=headers)
            with httpx.Client(transport=httpx.MockTransport(paginated)) as client:
                self.assertEqual(len(GitHubAppClient(settings, client).list_installations()), 2)
            self.assertEqual(pages, ["1", "2"])
