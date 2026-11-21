import time
import uuid

from sca_reachability.server.config import Settings
from sca_reachability.server.db import iso_now


DEMO_INSTALLATION_ID = 9001
DEMO_REPOSITORY_ID = 9002


def allowed_installation_ids(settings: Settings) -> frozenset[int]:
    if settings.mode == "demo":
        return frozenset({DEMO_INSTALLATION_ID})
    return settings.allowed_installation_ids


def installation_allowed(settings: Settings, installation_id: int) -> bool:
    return installation_id in allowed_installation_ids(settings)


def authorized_scope(
    connection,
    settings: Settings,
    installation_id: int,
    repository_id: int,
    branch: str | None = None,
) -> bool:
    if not installation_allowed(settings, installation_id):
        return False
    row = connection.execute(
        """
        SELECT i.status, r.active
        FROM installations i
        JOIN repositories r ON r.installation_id = i.id
        WHERE i.id = ? AND r.id = ?
        """,
        (installation_id, repository_id),
    ).fetchone()
    if not row or row["status"] != "active" or not row["active"]:
        return False
    if branch is None:
        return True
    selected = connection.execute(
        """
        SELECT selected FROM branches
        WHERE installation_id = ? AND repository_id = ? AND name = ?
        """,
        (installation_id, repository_id, branch),
    ).fetchone()
    return bool(selected and selected["selected"])


def enqueue_scan(
    connection,
    *,
    installation_id: int,
    repository_id: int,
    repository: str,
    branch: str,
    commit_sha: str,
    source: str,
) -> tuple[str, bool]:
    commit_sha = commit_sha.lower()
    existing = connection.execute(
        """
        SELECT id FROM scans
        WHERE installation_id = ? AND repository_id = ? AND branch = ? AND commit_sha = ?
        """,
        (installation_id, repository_id, branch, commit_sha),
    ).fetchone()
    if existing:
        return existing["id"], False

    scan_id = uuid.uuid4().hex
    created_at = iso_now()
    connection.execute(
        """
        INSERT INTO scans(
            id, installation_id, repository_id, repository, branch, commit_sha,
            status, source, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)
        """,
        (
            scan_id,
            installation_id,
            repository_id,
            repository,
            branch,
            commit_sha.lower(),
            source,
            created_at,
        ),
    )
    connection.execute(
        """
        INSERT INTO jobs(
            scan_id, installation_id, repository_id, branch, commit_sha,
            status, available_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?)
        """,
        (
            scan_id,
            installation_id,
            repository_id,
            branch,
            commit_sha.lower(),
            time.time(),
            created_at,
            created_at,
        ),
    )
    return scan_id, True


def cancel_scope(
    connection,
    *,
    installation_id: int,
    repository_id: int | None = None,
) -> None:
    now = iso_now()
    predicate = "installation_id = ?"
    params: list[object] = [installation_id]
    if repository_id is not None:
        predicate += " AND repository_id = ?"
        params.append(repository_id)
    job_rows = connection.execute(
        f"SELECT scan_id FROM jobs WHERE {predicate} AND status IN ('queued', 'retry', 'running')",
        params,
    ).fetchall()
    scan_ids = [row["scan_id"] for row in job_rows]
    connection.execute(
        f"""
        UPDATE jobs SET status = 'cancelled', lease_until = NULL,
            last_error = 'Authorization scope is no longer active.', updated_at = ?
        WHERE {predicate} AND status IN ('queued', 'retry', 'running')
        """,
        [now, *params],
    )
    if scan_ids:
        placeholders = ",".join("?" for _ in scan_ids)
        connection.execute(
            f"""
            UPDATE scans SET status = 'failed', completed_at = ?,
                error = 'Authorization scope is no longer active.'
            WHERE id IN ({placeholders}) AND status IN ('queued', 'running')
            """,
            [now, *scan_ids],
        )


def cancel_branch(connection, installation_id: int, repository_id: int, branch: str) -> None:
    now = iso_now()
    scan_ids = connection.execute(
        """
        SELECT scan_id FROM jobs
        WHERE installation_id = ? AND repository_id = ? AND branch = ?
            AND status IN ('queued', 'retry', 'running')
        """,
        (installation_id, repository_id, branch),
    ).fetchall()
    connection.execute(
        """
        UPDATE jobs SET status = 'cancelled', lease_until = NULL,
            last_error = 'Authorization scope is no longer active.', updated_at = ?
        WHERE installation_id = ? AND repository_id = ? AND branch = ?
            AND status IN ('queued', 'retry', 'running')
        """,
        (now, installation_id, repository_id, branch),
    )
    if scan_ids:
        placeholders = ",".join("?" for _ in scan_ids)
        connection.execute(
            f"""
            UPDATE scans SET status = 'failed', completed_at = ?,
                error = 'Authorization scope is no longer active.'
            WHERE id IN ({placeholders}) AND status IN ('queued', 'running')
            """,
            [now, *(row["scan_id"] for row in scan_ids)],
        )


def revoke_installation(connection, installation_id: int) -> None:
    disable_installation(connection, installation_id, "deleted")


def suspend_installation(connection, installation_id: int) -> None:
    disable_installation(connection, installation_id, "suspended")


def disable_installation(connection, installation_id: int, status: str) -> None:
    connection.execute(
        "UPDATE installations SET status = ?, updated_at = ? WHERE id = ?",
        (status, iso_now(), installation_id),
    )
    connection.execute(
        "UPDATE repositories SET active = 0, updated_at = ? WHERE installation_id = ?",
        (iso_now(), installation_id),
    )
    connection.execute(
        "DELETE FROM branches WHERE installation_id = ?",
        (installation_id,),
    )
    cancel_scope(connection, installation_id=installation_id)


def revoke_repository(connection, installation_id: int, repository_id: int) -> None:
    connection.execute(
        """
        UPDATE repositories SET active = 0, updated_at = ?
        WHERE installation_id = ? AND id = ?
        """,
        (iso_now(), installation_id, repository_id),
    )
    connection.execute(
        "DELETE FROM branches WHERE installation_id = ? AND repository_id = ?",
        (installation_id, repository_id),
    )
    cancel_scope(
        connection,
        installation_id=installation_id,
        repository_id=repository_id,
    )
