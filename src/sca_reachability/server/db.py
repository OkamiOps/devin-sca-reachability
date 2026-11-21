from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
from typing import Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS installations (
    id INTEGER PRIMARY KEY,
    account TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'deleted')),
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS repositories (
    installation_id INTEGER NOT NULL,
    id INTEGER NOT NULL,
    full_name TEXT NOT NULL,
    default_branch TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (installation_id, id),
    FOREIGN KEY (installation_id) REFERENCES installations(id)
);
CREATE TABLE IF NOT EXISTS branches (
    installation_id INTEGER NOT NULL,
    repository_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    selected INTEGER NOT NULL DEFAULT 0 CHECK (selected IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (installation_id, repository_id, name),
    FOREIGN KEY (installation_id, repository_id)
        REFERENCES repositories(installation_id, id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    installation_id INTEGER NOT NULL,
    repository_id INTEGER NOT NULL,
    repository TEXT NOT NULL,
    branch TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    source TEXT NOT NULL CHECK (source IN ('demo', 'github')),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    component_count INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    explanation_json TEXT NOT NULL DEFAULT '{"status":"disabled","text":null,"source":null}',
    UNIQUE (installation_id, repository_id, branch, commit_sha)
);
CREATE INDEX IF NOT EXISTS scans_scope_recent
    ON scans(installation_id, repository_id, created_at DESC);
CREATE TABLE IF NOT EXISTS scan_components (
    scan_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    purl TEXT NOT NULL,
    manifest_path TEXT NOT NULL,
    PRIMARY KEY (scan_id, ordinal),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS scan_findings (
    scan_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    purl TEXT NOT NULL,
    advisory_id TEXT NOT NULL,
    summary TEXT,
    severity TEXT,
    fixed_versions_json TEXT NOT NULL,
    reachability TEXT NOT NULL DEFAULT 'unknown' CHECK (reachability = 'unknown'),
    PRIMARY KEY (scan_id, ordinal),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS scan_warnings (
    scan_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    warning TEXT NOT NULL,
    PRIMARY KEY (scan_id, ordinal),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS deliveries (
    delivery_id TEXT PRIMARY KEY,
    payload_sha256 TEXT NOT NULL,
    event TEXT NOT NULL,
    installation_id INTEGER,
    repository TEXT,
    branch TEXT,
    status TEXT NOT NULL,
    received_at TEXT NOT NULL,
    scan_id TEXT,
    reason TEXT
);
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL UNIQUE,
    installation_id INTEGER NOT NULL,
    repository_id INTEGER NOT NULL,
    branch TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'retry', 'done', 'failed', 'cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at REAL NOT NULL,
    lease_until REAL,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS jobs_due ON jobs(status, available_at, id);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    expires_at REAL NOT NULL,
    created_at TEXT NOT NULL
);
"""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")


class Database:
    def __init__(self, path: Path):
        self.path = path

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=5,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(SCHEMA)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
