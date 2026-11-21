from sca_reachability.server.config import Settings
from sca_reachability.server.db import Database, iso_now
from sca_reachability.server.github import GitHubAdapter
from sca_reachability.server.service import (
    DEMO_INSTALLATION_ID,
    DEMO_REPOSITORY_ID,
    enqueue_scan,
)


DEMO_ACCOUNT = "Fictional Demo"
DEMO_REPOSITORY = "okamiops/fictional-sca-demo"
DEMO_BRANCHES = ("main", "develop", "release")


def seed_demo_catalog(database: Database) -> None:
    now = iso_now()
    with database.transaction() as connection:
        connection.execute(
            """
            INSERT INTO installations(id, account, status, updated_at)
            VALUES (?, ?, 'active', ?)
            ON CONFLICT(id) DO UPDATE SET
                account = excluded.account, status = 'active', updated_at = excluded.updated_at
            """,
            (DEMO_INSTALLATION_ID, DEMO_ACCOUNT, now),
        )
        connection.execute(
            """
            INSERT INTO repositories(
                installation_id, id, full_name, default_branch, active, updated_at
            ) VALUES (?, ?, ?, 'main', 1, ?)
            ON CONFLICT(installation_id, id) DO UPDATE SET
                full_name = excluded.full_name, default_branch = 'main',
                active = 1, updated_at = excluded.updated_at
            """,
            (DEMO_INSTALLATION_ID, DEMO_REPOSITORY_ID, DEMO_REPOSITORY, now),
        )
        for branch in DEMO_BRANCHES:
            connection.execute(
                """
                INSERT OR IGNORE INTO branches(
                    installation_id, repository_id, name, selected, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    DEMO_INSTALLATION_ID,
                    DEMO_REPOSITORY_ID,
                    branch,
                    int(branch == "main"),
                    now,
                ),
            )


def seed_initial_scan(
    database: Database,
    settings: Settings,
    github: GitHubAdapter,
) -> str | None:
    with database.connection() as connection:
        existing = connection.execute(
            """
            SELECT id FROM scans
            WHERE installation_id = ? AND repository_id = ? AND branch = 'main'
            ORDER BY created_at LIMIT 1
            """,
            (DEMO_INSTALLATION_ID, DEMO_REPOSITORY_ID),
        ).fetchone()
    if existing:
        return existing["id"]

    commit_sha = github.resolve_commit_sha(
        DEMO_INSTALLATION_ID,
        DEMO_REPOSITORY_ID,
        DEMO_REPOSITORY,
        "main",
    )
    with database.transaction() as connection:
        scan_id, _ = enqueue_scan(
            connection,
            installation_id=DEMO_INSTALLATION_ID,
            repository_id=DEMO_REPOSITORY_ID,
            repository=DEMO_REPOSITORY,
            branch="main",
            commit_sha=commit_sha,
            source="demo",
        )
    return scan_id
