from sca_reachability.server.config import Settings
from sca_reachability.server.db import Database, iso_now
from sca_reachability.server.errors import ServiceError
from sca_reachability.server.github import GitHubAdapter
from sca_reachability.server.service import (
    allowed_installation_ids,
    cancel_branch,
    revoke_installation,
    revoke_repository,
    suspend_installation,
)


def _valid_repository(item: object) -> bool:
    return bool(
        isinstance(item, dict)
        and isinstance(item.get("id"), int)
        and not isinstance(item.get("id"), bool)
        and item["id"] > 0
        and isinstance(item.get("full_name"), str)
        and 0 < len(item["full_name"]) <= 255
        and item["full_name"].count("/") == 1
        and isinstance(item.get("default_branch"), str)
        and len(item["default_branch"]) <= 255
    )


def _collect(github: GitHubAdapter, allowed: frozenset[int]) -> list[dict]:
    raw_installations = github.list_installations()
    if not isinstance(raw_installations, list):
        raise ServiceError(503, "GitHub installation sync returned an invalid response.")
    collected = []
    for installation in raw_installations:
        if not isinstance(installation, dict):
            continue
        installation_id = installation.get("id")
        if (
            not isinstance(installation_id, int)
            or isinstance(installation_id, bool)
            or installation_id not in allowed
        ):
            continue
        account = installation.get("account")
        status = installation.get("status")
        if (
            not isinstance(account, str)
            or not account
            or len(account) > 255
            or status not in {"active", "suspended", "deleted"}
        ):
            continue
        record = {
            "id": installation_id,
            "account": account,
            "status": status,
            "repositories": [],
        }
        if status == "active":
            repositories = github.list_repositories(installation_id)
            if not isinstance(repositories, list):
                raise ServiceError(503, "GitHub repository sync returned an invalid response.")
            for repository in repositories:
                if not _valid_repository(repository):
                    continue
                branches = github.list_branches(
                    installation_id,
                    repository["id"],
                    repository["full_name"],
                )
                if not isinstance(branches, list):
                    raise ServiceError(503, "GitHub branch sync returned an invalid response.")
                valid_branches = sorted(
                    {
                        branch
                        for branch in branches
                        if isinstance(branch, str)
                        and 0 < len(branch) <= 255
                        and not any(ord(character) < 32 for character in branch)
                    }
                )
                record["repositories"].append(
                    {**repository, "branches": valid_branches}
                )
        collected.append(record)
    return collected


def _apply(database: Database, settings: Settings, installations: list[dict], *, partial: bool = False) -> None:
    allowed = allowed_installation_ids(settings)
    present = {item["id"] for item in installations}
    now = iso_now()
    with database.transaction() as connection:
        existing_ids = {
            row["id"]
            for row in connection.execute("SELECT id FROM installations").fetchall()
            if row["id"] in allowed
        }
        for installation_id in existing_ids - present:
            revoke_installation(connection, installation_id)

        for installation in installations:
            installation_id = installation["id"]
            connection.execute(
                """
                INSERT OR IGNORE INTO installations(id, account, status, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (installation_id, installation["account"], installation["status"], now),
            )
            if installation["status"] == "deleted":
                revoke_installation(connection, installation_id)
                continue
            if installation["status"] == "suspended":
                suspend_installation(connection, installation_id)
                connection.execute(
                    "UPDATE installations SET account = ? WHERE id = ?",
                    (installation["account"], installation_id),
                )
                continue

            connection.execute(
                """
                INSERT INTO installations(id, account, status, updated_at)
                VALUES (?, ?, 'active', ?)
                ON CONFLICT(id) DO UPDATE SET
                    account = excluded.account, status = 'active',
                    updated_at = excluded.updated_at
                """,
                (installation_id, installation["account"], now),
            )
            repository_ids = {repo["id"] for repo in installation["repositories"]}
            previous = connection.execute(
                "SELECT id FROM repositories WHERE installation_id = ?",
                (installation_id,),
            ).fetchall()
            for row in previous:
                if row["id"] not in repository_ids and not partial:
                    revoke_repository(connection, installation_id, row["id"])

            for repository in installation["repositories"]:
                repository_id = repository["id"]
                connection.execute(
                    """
                    INSERT INTO repositories(
                        installation_id, id, full_name, default_branch, active, updated_at
                    ) VALUES (?, ?, ?, ?, 1, ?)
                    ON CONFLICT(installation_id, id) DO UPDATE SET
                        full_name = excluded.full_name,
                        default_branch = excluded.default_branch,
                        active = 1, updated_at = excluded.updated_at
                    """,
                    (
                        installation_id,
                        repository_id,
                        repository["full_name"],
                        repository["default_branch"],
                        now,
                    ),
                )
                branch_names = set(repository["branches"])
                previous_branches = connection.execute(
                    """
                    SELECT name FROM branches
                    WHERE installation_id = ? AND repository_id = ?
                    """,
                    (installation_id, repository_id),
                ).fetchall()
                for branch_row in previous_branches:
                    if branch_row["name"] not in branch_names:
                        cancel_branch(
                            connection,
                            installation_id,
                            repository_id,
                            branch_row["name"],
                        )
                        connection.execute(
                            """
                            DELETE FROM branches
                            WHERE installation_id = ? AND repository_id = ? AND name = ?
                            """,
                            (installation_id, repository_id, branch_row["name"]),
                        )
                for branch in repository["branches"]:
                    select_default = (
                        settings.mode == 'public' and branch == repository['default_branch']
                        and connection.execute(
                            'SELECT count(*) FROM branches WHERE installation_id = ? AND repository_id = ? AND selected = 1',
                            (installation_id, repository_id),
                        ).fetchone()[0] < 20
                    )
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO branches(
                            installation_id, repository_id, name, selected, updated_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (installation_id, repository_id, branch,
                         int(select_default), now),
                    )
                    connection.execute(
                        """
                        UPDATE branches SET updated_at = ?
                        WHERE installation_id = ? AND repository_id = ? AND name = ?
                        """,
                        (now, installation_id, repository_id, branch),
                    )


def sync_installations(
    database: Database,
    settings: Settings,
    github: GitHubAdapter,
    *,
    github_configured: bool,
) -> list[dict]:
    if settings.mode == "demo":
        return _read_installations(database, settings)
    if not github_configured:
        raise ServiceError(503, "GitHub App is not configured.")
    try:
        installations = _collect(github, allowed_installation_ids(settings))
        _apply(database, settings, installations)
        clear = getattr(github, "clear_installation", None)
        if callable(clear):
            for installation_id in allowed_installation_ids(settings):
                clear(installation_id)
    except ServiceError:
        raise
    except Exception as error:
        raise ServiceError(503, "GitHub inventory could not be synchronized.") from error
    return _read_installations(database, settings)


def _read_installations(database: Database, settings: Settings) -> list[dict]:
    allowed = allowed_installation_ids(settings)
    if not allowed:
        return []
    placeholders = ",".join("?" for _ in allowed)
    with database.connection() as connection:
        rows = connection.execute(
            f"""
            SELECT id, account, status FROM installations
            WHERE id IN ({placeholders}) ORDER BY id
            """,
            tuple(sorted(allowed)),
        ).fetchall()
    return [dict(row) for row in rows]
