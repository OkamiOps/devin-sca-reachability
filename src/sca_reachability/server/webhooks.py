from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

from sca_reachability.server.config import Settings
from sca_reachability.server.db import Database, iso_now
from sca_reachability.server.errors import ServiceError
from sca_reachability.server.github import SHA_RE, GitHubAdapter
from sca_reachability.server.security import verify_webhook_signature
from sca_reachability.server.service import (
    enqueue_scan,
    installation_allowed,
    revoke_installation,
    revoke_repository,
    suspend_installation,
)


DELIVERY_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SUPPORTED_EVENTS = {"push", "installation", "installation_repositories"}


@dataclass(frozen=True)
class WebhookResult:
    delivery_id: str
    status: str
    scan_id: str | None
    duplicate: bool = False


def _positive_id(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _installation_id(payload: dict) -> int:
    installation = payload.get("installation")
    if not isinstance(installation, dict) or not _positive_id(installation.get("id")):
        raise ServiceError(400, "Webhook installation metadata is malformed.")
    return installation["id"]


def _validate_repository(value: Any) -> dict:
    if not isinstance(value, dict):
        raise ServiceError(400, "Webhook repository metadata is malformed.")
    repository_id = value.get("id")
    full_name = value.get("full_name")
    default_branch = value.get("default_branch", "")
    if (
        not _positive_id(repository_id)
        or not isinstance(full_name, str)
        or not full_name
        or len(full_name) > 255
        or full_name.count("/") != 1
        or not isinstance(default_branch, str)
        or len(default_branch) > 255
    ):
        raise ServiceError(400, "Webhook repository metadata is malformed.")
    return {
        "id": repository_id,
        "full_name": full_name,
        "default_branch": default_branch,
    }


def _validate_payload(event: str, payload: Any) -> dict:
    if event not in SUPPORTED_EVENTS:
        raise ServiceError(400, "Unsupported GitHub webhook event.")
    if not isinstance(payload, dict):
        raise ServiceError(400, "Webhook JSON must be an object.")

    if event == "push":
        installation_id = _installation_id(payload)
        repository = _validate_repository(payload.get("repository"))
        ref = payload.get("ref")
        after = payload.get("after")
        deleted = payload.get("deleted")
        if (
            not isinstance(ref, str)
            or not ref
            or len(ref) > 1024
            or not isinstance(after, str)
            or not SHA_RE.fullmatch(after)
            or not isinstance(deleted, bool)
        ):
            raise ServiceError(400, "Webhook push metadata is malformed.")
        return {
            "installation_id": installation_id,
            "repository": repository,
            "ref": ref,
            "commit_sha": after.lower(),
            "deleted": deleted,
        }

    installation_id = _installation_id(payload)
    action = payload.get("action")
    if not isinstance(action, str) or not action or len(action) > 64:
        raise ServiceError(400, "Webhook action metadata is malformed.")
    if event == "installation":
        installation = payload["installation"]
        account = installation.get("account")
        login = account.get("login") if isinstance(account, dict) else None
        return {
            "installation_id": installation_id,
            "action": action,
            "account": login[:255] if isinstance(login, str) else None,
        }

    added = payload.get("repositories_added", [])
    removed = payload.get("repositories_removed", [])
    if not isinstance(added, list) or not isinstance(removed, list):
        raise ServiceError(400, "Webhook repository changes are malformed.")
    return {
        "installation_id": installation_id,
        "action": action,
        "added": [_validate_repository(item) for item in added],
        "removed": [_validate_repository(item) for item in removed],
    }


class WebhookProcessor:
    def __init__(
        self,
        database: Database,
        settings: Settings,
        github: GitHubAdapter,
    ):
        self.database = database
        self.settings = settings
        self.github = github

    def ingest(
        self,
        *,
        delivery_id: str,
        event: str,
        signature: str | None,
        raw_body: bytes,
    ) -> WebhookResult:
        if not isinstance(delivery_id, str) or not DELIVERY_ID_RE.fullmatch(delivery_id):
            raise ServiceError(400, "GitHub delivery identifier is missing or malformed.")
        if event not in SUPPORTED_EVENTS:
            raise ServiceError(400, "Unsupported GitHub webhook event.")
        secret = self.settings.webhook_secret
        if not secret:
            raise ServiceError(503, "GitHub webhook signing is not configured.")
        if not verify_webhook_signature(secret, signature, raw_body):
            raise ServiceError(401, "GitHub webhook signature is invalid.")
        try:
            decoded = json.loads(raw_body)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ServiceError(400, "Webhook body is not valid JSON.") from error
        payload = _validate_payload(event, decoded)
        digest = hashlib.sha256(raw_body).hexdigest()
        now = iso_now()
        clear_installation = None

        with self.database.transaction() as connection:
            existing = connection.execute(
                "SELECT payload_sha256 FROM deliveries WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
            if existing:
                if existing["payload_sha256"] != digest:
                    raise ServiceError(409, "GitHub delivery identifier was reused with different content.")
                return WebhookResult(delivery_id, "duplicate", None, duplicate=True)

            result = self._process(connection, event, payload)
            connection.execute(
                """
                INSERT INTO deliveries(
                    delivery_id, payload_sha256, event, installation_id,
                    repository, branch, status, received_at, scan_id, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    delivery_id,
                    digest,
                    event,
                    result["installation_id"],
                    result["repository"],
                    result["branch"],
                    result["status"],
                    now,
                    result["scan_id"],
                    result["reason"],
                ),
            )
            if result["clear_installation"]:
                clear_installation = result["installation_id"]
            result_status = result["status"]
            scan_id = result["scan_id"]

        if clear_installation is not None:
            clear = getattr(self.github, "clear_installation", None)
            if callable(clear):
                clear(clear_installation)
        return WebhookResult(delivery_id, result_status, scan_id)

    def _process(self, connection, event: str, payload: dict) -> dict:
        base = {
            "installation_id": payload["installation_id"],
            "repository": None,
            "branch": None,
            "status": "ignored",
            "scan_id": None,
            "reason": None,
            "clear_installation": False,
        }
        installation_id = payload["installation_id"]
        if not installation_allowed(self.settings, installation_id):
            base["reason"] = "installation_outside_allowlist"
            return base

        if event == "push":
            return self._process_push(connection, payload, base)
        if event == "installation":
            return self._process_installation(connection, payload, base)
        return self._process_repository_changes(connection, payload, base)

    def _process_push(self, connection, payload: dict, result: dict) -> dict:
        installation_id = payload["installation_id"]
        repository_id = payload["repository"]["id"]
        repository_row = connection.execute(
            """
            SELECT r.full_name, r.active, i.status
            FROM repositories r
            JOIN installations i ON i.id = r.installation_id
            WHERE r.installation_id = ? AND r.id = ?
            """,
            (installation_id, repository_id),
        ).fetchone()
        if not repository_row or not repository_row["active"] or repository_row["status"] != "active":
            result["reason"] = "repository_not_associated_or_installation_inactive"
            return result
        result["repository"] = repository_row["full_name"]

        if not payload["ref"].startswith("refs/heads/"):
            result["reason"] = "not_a_branch_push"
            return result
        branch = payload["ref"][len("refs/heads/") :]
        if not branch or len(branch) > 255:
            result["reason"] = "malformed_branch_name"
            return result
        result["branch"] = branch
        if payload["deleted"]:
            result["reason"] = "branch_deleted"
            return result
        selected = connection.execute(
            """
            SELECT selected FROM branches
            WHERE installation_id = ? AND repository_id = ? AND name = ?
            """,
            (installation_id, repository_id, branch),
        ).fetchone()
        if not selected or not selected["selected"]:
            result["reason"] = "branch_not_selected"
            return result

        scan_id, created = enqueue_scan(
            connection,
            installation_id=installation_id,
            repository_id=repository_id,
            repository=repository_row["full_name"],
            branch=branch,
            commit_sha=payload["commit_sha"],
            source="demo" if self.settings.mode == "demo" else "github",
        )
        result["scan_id"] = scan_id
        result["status"] = "queued" if created else "processed"
        result["reason"] = None if created else "scan_already_exists"
        return result

    def _process_installation(self, connection, payload: dict, result: dict) -> dict:
        installation_id = payload["installation_id"]
        action = payload["action"]
        account = payload["account"] or "Unknown account"
        now = iso_now()
        if action == "created":
            connection.execute(
                """
                INSERT INTO installations(id, account, status, updated_at)
                VALUES (?, ?, 'active', ?)
                ON CONFLICT(id) DO UPDATE SET
                    account = excluded.account, status = 'active',
                    updated_at = excluded.updated_at
                """,
                (installation_id, account, now),
            )
            result["status"] = "processed"
        elif action in {"suspend", "suspended"}:
            suspend_installation(connection, installation_id)
            result["status"] = "processed"
            result["clear_installation"] = True
        elif action in {"delete", "deleted"}:
            revoke_installation(connection, installation_id)
            result["status"] = "processed"
            result["clear_installation"] = True
        elif action in {"unsuspend", "unsuspended"}:
            connection.execute(
                """
                UPDATE installations SET status = 'active', account = ?, updated_at = ?
                WHERE id = ?
                """,
                (account, now, installation_id),
            )
            result["status"] = "processed"
        else:
            result["reason"] = "unsupported_installation_action"
        return result

    def _process_repository_changes(self, connection, payload: dict, result: dict) -> dict:
        installation_id = payload["installation_id"]
        action = payload["action"]
        if action not in {"added", "removed"}:
            result["reason"] = "unsupported_repository_action"
            return result
        installation = connection.execute(
            "SELECT status FROM installations WHERE id = ?",
            (installation_id,),
        ).fetchone()
        if not installation or installation["status"] != "active":
            result["reason"] = "installation_not_active"
            return result
        now = iso_now()
        for repository in payload["added"]:
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
                    repository["id"],
                    repository["full_name"],
                    repository["default_branch"],
                    now,
                ),
            )
        for repository in payload["removed"]:
            revoke_repository(connection, installation_id, repository["id"])
        result["status"] = "processed"
        result["clear_installation"] = bool(payload["removed"])
        return result
