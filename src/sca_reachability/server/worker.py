import json
import threading
import time

from sca_reachability.explanation import explain_report
from sca_reachability.server.config import Settings
from sca_reachability.server.db import Database, iso_now
from sca_reachability.server.errors import RetryableError, ScanError
from sca_reachability.server.github import DemoGitHubAdapter, GitHubAdapter
from sca_reachability.server.manifests import inventory_manifests
from sca_reachability.server.osv_client import Advisory, OsvAdapter
from sca_reachability.server.service import authorized_scope


MAX_ATTEMPTS = 3
LEASE_SECONDS = 90
POLL_SECONDS = 0.25


class ScanWorker:
    def __init__(
        self,
        database: Database,
        settings: Settings,
        github: GitHubAdapter,
        osv: OsvAdapter,
        ai_provider=None,
    ):
        self.database = database
        self.settings = settings
        self.github = github
        self.osv = osv
        self.ai_provider = ai_provider
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stopping.clear()
        self.recover_expired_leases()
        self._thread = threading.Thread(
            target=self._run,
            name="sca-scan-worker",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stopping.set()
        if self._thread and self._thread.is_alive():
            self._thread.join()

    def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                worked = self.run_once()
            except Exception:
                worked = False
            if not worked:
                self._stopping.wait(POLL_SECONDS)

    def recover_expired_leases(self) -> None:
        now = time.time()
        with self.database.transaction() as connection:
            expired = connection.execute(
                """
                SELECT id, scan_id, attempts FROM jobs
                WHERE status = 'running' AND lease_until <= ?
                """,
                (now,),
            ).fetchall()
            for job in expired:
                if job["attempts"] >= MAX_ATTEMPTS:
                    self._mark_failed(
                        connection,
                        job["id"],
                        job["scan_id"],
                        "Analysis could not be completed after the retry limit.",
                        job["attempts"],
                    )
                else:
                    delay = 2 ** job["attempts"]
                    connection.execute(
                        """
                        UPDATE jobs SET status = 'retry', lease_until = NULL,
                            available_at = ?, updated_at = ? WHERE id = ?
                        """,
                        (now + delay, iso_now(), job["id"]),
                    )
                    connection.execute(
                        "UPDATE scans SET status = 'queued' WHERE id = ? AND status = 'running'",
                        (job["scan_id"],),
                    )

    def run_once(self) -> bool:
        self.recover_expired_leases()
        now = time.time()
        with self.database.transaction() as connection:
            job = connection.execute(
                """
                SELECT j.*, s.repository, s.source FROM jobs j JOIN scans s ON s.id = j.scan_id
                WHERE j.status IN ('queued', 'retry') AND j.available_at <= ?
                ORDER BY j.id LIMIT 1
                """,
                (now,),
            ).fetchone()
            if not job:
                return False
            connection.execute(
                """
                UPDATE jobs SET status = 'running', attempts = attempts + 1,
                    lease_until = ?, updated_at = ? WHERE id = ?
                """,
                (now + LEASE_SECONDS, iso_now(), job["id"]),
            )
            connection.execute(
                "UPDATE scans SET status = 'running', error = NULL WHERE id = ?",
                (job["scan_id"],),
            )
            connection.execute(
                "DELETE FROM scan_demo_sources WHERE scan_id = ?", (job["scan_id"],)
            )
            job_data = dict(job)
            job_data["attempts"] += 1
            if not authorized_scope(
                connection,
                self.settings,
                job_data["installation_id"],
                job_data["repository_id"],
                job_data["branch"],
            ):
                self._cancel(connection, job_data)
                return True

        heartbeat_stop = threading.Event()
        heartbeat = threading.Thread(
            target=self._heartbeat, args=(job_data, heartbeat_stop), daemon=True
        )
        heartbeat.start()
        try:
            inventory, advisories_by_component, demo_sources = self._analyze(job_data)
            self._save_results(job_data, inventory, advisories_by_component, demo_sources)
        except RetryableError:
            self._retry_or_fail(job_data)
        except ScanError as error:
            self._fail(job_data, str(error))
        except Exception:
            self._fail(job_data, "Analysis failed due to an internal service error.")
        finally:
            heartbeat_stop.set()
            heartbeat.join()
        return True

    def _heartbeat(self, job: dict, stopping: threading.Event) -> None:
        while not stopping.wait(20):
            try:
                with self.database.transaction() as connection:
                    connection.execute(
                        """
                        UPDATE jobs SET lease_until = ?
                        WHERE id = ? AND status = 'running' AND attempts = ?
                        """,
                        (time.time() + LEASE_SECONDS, job["id"], job["attempts"]),
                    )
            except Exception:
                continue

    def _authorized(self, job: dict) -> bool:
        with self.database.connection() as connection:
            status = connection.execute(
                "SELECT status, attempts FROM jobs WHERE id = ?",
                (job["id"],),
            ).fetchone()
            return bool(
                status
                and status["status"] == "running"
                and status["attempts"] == job["attempts"]
                and authorized_scope(
                    connection,
                    self.settings,
                    job["installation_id"],
                    job["repository_id"],
                    job["branch"],
                )
            )

    def _ensure_authorized(self, job: dict) -> None:
        if not self._authorized(job):
            raise ScanError("Authorization scope was revoked while the scan was running.")

    def _analyze(self, job: dict):
        self._ensure_authorized(job)
        tree, truncated = self.github.get_tree(
            job["installation_id"],
            job["repository_id"],
            job["repository"],
            job["commit_sha"],
        )
        if truncated:
            raise ScanError("GitHub returned a truncated dependency tree; the scan is incomplete.")
        self._ensure_authorized(job)
        demo_sources = []
        capture_demo_sources = (
            self.settings.mode == "demo"
            and job.get("source") == "demo"
            and type(self.github) is DemoGitHubAdapter
        )
        inventory = inventory_manifests(
            tree,
            lambda blob_sha: self._read_blob(job, blob_sha),
            on_manifest=(
                lambda path, blob_sha, content: demo_sources.append(
                    {"manifest_path": path, "blob_sha": blob_sha, "content": bytes(content)}
                )
                if capture_demo_sources else None
            ),
        )
        self._ensure_authorized(job)
        if inventory.components:
            advisories = self.osv.query(inventory.components)
        else:
            advisories = []
        if not isinstance(advisories, list) or len(advisories) != len(inventory.components):
            raise ScanError("OSV results did not match the component inventory.")
        if any(
            not isinstance(items, list)
            or any(not isinstance(item, Advisory) for item in items)
            for items in advisories
        ):
            raise ScanError("OSV returned malformed advisory data.")
        self._ensure_authorized(job)
        return inventory, advisories, demo_sources

    def _read_blob(self, job: dict, blob_sha: str) -> bytes:
        self._ensure_authorized(job)
        return self.github.get_blob(
            job["installation_id"],
            job["repository_id"],
            job["repository"],
            blob_sha,
        )

    @staticmethod
    def _explanation_report(inventory, advisories_by_component) -> dict:
        findings = []
        for component, advisories in zip(
            inventory.components, advisories_by_component, strict=True
        ):
            for advisory in advisories:
                findings.append(
                    {
                        "advisory_id": advisory.id,
                        "severity": advisory.severity,
                        "reachability": "unknown",
                        "ecosystem": component.ecosystem,
                        "purl": component.purl,
                    }
                )
        return {"findings": findings}

    def _save_results(self, job: dict, inventory, advisories_by_component, demo_sources=()) -> None:
        self._ensure_authorized(job)
        report = self._explanation_report(inventory, advisories_by_component)
        explanation = explain_report(report, provider=self.ai_provider)
        now = iso_now()
        component_count = len(inventory.components)
        finding_count = sum(len(items) for items in advisories_by_component)
        with self.database.transaction() as connection:
            job_status = connection.execute(
                "SELECT status, attempts FROM jobs WHERE id = ?",
                (job["id"],),
            ).fetchone()
            if (
                not job_status
                or job_status["status"] != "running"
                or job_status["attempts"] != job["attempts"]
                or not authorized_scope(
                    connection,
                    self.settings,
                    job["installation_id"],
                    job["repository_id"],
                    job["branch"],
                )
            ):
                return
            connection.execute(
                "DELETE FROM scan_demo_sources WHERE scan_id = ?", (job["scan_id"],)
            )
            for ordinal, component in enumerate(inventory.components):
                connection.execute(
                    """
                    INSERT INTO scan_components(
                        scan_id, ordinal, name, version, ecosystem, purl, manifest_path
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        job["scan_id"],
                        ordinal,
                        component.name,
                        component.version,
                        component.ecosystem,
                        component.purl,
                        component.manifest_path,
                    ),
                )
            finding_ordinal = 0
            for component, advisories in zip(
                inventory.components, advisories_by_component, strict=True
            ):
                for advisory in advisories:
                    fixed_versions = [
                        version[:128]
                        for version in advisory.fixed_versions[:100]
                        if isinstance(version, str) and version
                    ]
                    summary = advisory.summary[:2000] if advisory.summary else None
                    severity = (
                        advisory.severity[:32]
                        if isinstance(advisory.severity, str)
                        else None
                    )
                    connection.execute(
                        """
                        INSERT INTO scan_findings(
                            scan_id, ordinal, id, package_name, version, ecosystem, purl,
                            advisory_id, summary, severity, fixed_versions_json, reachability
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unknown')
                        """,
                        (
                            job["scan_id"],
                            finding_ordinal,
                            advisory.id[:128],
                            component.name,
                            component.version,
                            component.ecosystem,
                            component.purl,
                            advisory.id[:128],
                            summary,
                            severity,
                            json.dumps(fixed_versions, ensure_ascii=False),
                        ),
                    )
                    finding_ordinal += 1
            for ordinal, warning in enumerate(inventory.warnings):
                connection.execute(
                    "INSERT INTO scan_warnings(scan_id, ordinal, warning) VALUES (?, ?, ?)",
                    (job["scan_id"], ordinal, warning[:2000]),
                )
            if (
                self.settings.mode == "demo"
                and job.get("source") == "demo"
                and type(self.github) is DemoGitHubAdapter
            ):
                for ordinal, source in enumerate(demo_sources):
                    connection.execute(
                        """INSERT INTO scan_demo_sources(
                            scan_id, ordinal, manifest_path, blob_sha, content
                        ) VALUES (?, ?, ?, ?, ?)""",
                        (
                            job["scan_id"], ordinal, source["manifest_path"],
                            source["blob_sha"], source["content"],
                        ),
                    )
            connection.execute(
                """
                UPDATE scans SET status = 'completed', completed_at = ?,
                    component_count = ?, finding_count = ?, error = NULL,
                    explanation_json = ? WHERE id = ?
                """,
                (
                    now,
                    component_count,
                    finding_count,
                    json.dumps(explanation, ensure_ascii=False),
                    job["scan_id"],
                ),
            )
            connection.execute(
                """
                UPDATE jobs SET status = 'done', lease_until = NULL,
                    last_error = NULL, updated_at = ? WHERE id = ?
                """,
                (now, job["id"]),
            )

    def _cancel(self, connection, job: dict) -> None:
        now = iso_now()
        connection.execute(
            """
            UPDATE jobs SET status = 'cancelled', lease_until = NULL,
                last_error = 'Authorization scope is no longer active.', updated_at = ?
            WHERE id = ?
            """,
            (now, job["id"]),
        )
        connection.execute(
            """
            UPDATE scans SET status = 'failed', completed_at = ?,
                error = 'Authorization scope is no longer active.'
            WHERE id = ? AND status IN ('queued', 'running')
            """,
            (now, job["scan_id"]),
        )
        connection.execute(
            "DELETE FROM scan_demo_sources WHERE scan_id = ?", (job["scan_id"],)
        )

    def _retry_or_fail(self, job: dict) -> None:
        now = iso_now()
        if job["attempts"] >= MAX_ATTEMPTS:
            with self.database.transaction() as connection:
                self._mark_failed(
                    connection,
                    job["id"],
                    job["scan_id"],
                    "A temporary service error persisted after the retry limit.",
                    job["attempts"],
                )
            return
        delay = 2 ** job["attempts"]
        with self.database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE jobs SET status = 'retry', lease_until = NULL,
                    available_at = ?, last_error = 'Temporary service error.',
                    updated_at = ? WHERE id = ? AND status = 'running' AND attempts = ?
                """,
                (time.time() + delay, now, job["id"], job["attempts"]),
            )
            if updated.rowcount:
                connection.execute(
                    "UPDATE scans SET status = 'queued' WHERE id = ? AND status = 'running'",
                    (job["scan_id"],),
                )

    def _fail(self, job: dict, message: str) -> None:
        with self.database.transaction() as connection:
            self._mark_failed(
                connection, job["id"], job["scan_id"], message[:1000], job["attempts"]
            )

    @staticmethod
    def _mark_failed(connection, job_id: int, scan_id: str, message: str, attempts: int) -> None:
        now = iso_now()
        updated = connection.execute(
            """
            UPDATE jobs SET status = 'failed', lease_until = NULL,
                last_error = ?, updated_at = ? WHERE id = ?
                AND status = 'running' AND attempts = ?
            """,
            (message, now, job_id, attempts),
        )
        if not updated.rowcount:
            return
        connection.execute(
            "DELETE FROM scan_demo_sources WHERE scan_id = ?", (scan_id,)
        )
        connection.execute(
            """
            UPDATE scans SET status = 'failed', completed_at = ?, error = ?
            WHERE id = ? AND status IN ('queued', 'running')
            """,
            (now, message, scan_id),
        )
