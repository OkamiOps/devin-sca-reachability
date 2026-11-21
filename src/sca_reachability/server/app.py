from contextlib import asynccontextmanager
import hashlib
import hmac
import json
import time
from pathlib import Path
import uuid

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from sca_reachability.explanation import create_provider_from_env
from sca_reachability.server.config import Settings
from sca_reachability.server.db import Database, iso_now
from sca_reachability.server.demo import DEMO_REPOSITORY, seed_demo_catalog, seed_initial_scan
from sca_reachability.server.errors import ServiceError
from sca_reachability.server.github import DemoGitHubAdapter, GitHubAppClient, SHA_RE
from sca_reachability.server.osv_client import DemoOsvAdapter, OsvClient
from sca_reachability.server.security import (
    SESSION_COOKIE,
    SESSION_TTL_SECONDS,
    RateLimitMiddleware,
    RequestBodyLimitMiddleware,
    authenticate_request,
    create_session,
    require_mutation_protection,
    revoke_session,
    validate_login_request,
)
from sca_reachability.server.service import (
    DEMO_INSTALLATION_ID,
    DEMO_REPOSITORY_ID,
    allowed_installation_ids,
    authorized_scope,
    cancel_branch,
    enqueue_scan,
    installation_allowed,
)
from sca_reachability.server.sync import _read_installations, sync_installations
from sca_reachability.server.webhooks import WebhookProcessor
from sca_reachability.server.worker import ScanWorker


SCAN_FIELDS = (
    "id", "repository_id", "repository", "branch", "commit_sha", "status", "source",
    "created_at", "completed_at", "component_count", "finding_count", "error",
)


async def _json_object(request: Request) -> dict:
    try:
        value = json.loads(await request.body())
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ServiceError(400, "Request body must contain valid JSON.") from error
    if not isinstance(value, dict):
        raise ServiceError(400, "Request JSON must be an object.")
    return value


def create_app(
    settings: Settings | None = None,
    *,
    github_adapter=None,
    osv_adapter=None,
    ai_provider=None,
    worker_enabled: bool = True,
) -> FastAPI:
    settings = settings or Settings.from_env()
    database = Database(settings.database_path)
    github_configured = github_adapter is not None or settings.github_configured
    github = github_adapter or (
        DemoGitHubAdapter() if settings.mode == "demo" else GitHubAppClient(settings)
    )
    osv = osv_adapter or (DemoOsvAdapter() if settings.mode == "demo" else OsvClient())

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        database.initialize()
        provider = None
        if settings.mode == "live":
            provider = ai_provider
            if provider is None:
                provider = create_provider_from_env(
                    {
                        "SCA_AI_ENABLED": "true" if settings.ai_enabled else "false",
                        "SCA_AI_API_KEY": settings.ai_api_key or "",
                        "SCA_AI_MODEL": settings.ai_model or "",
                    }
                )
        app.state.ai_configured = provider is not None
        worker = ScanWorker(database, settings, github, osv, ai_provider=provider)
        app.state.worker = worker
        try:
            if settings.mode == "demo":
                seed_demo_catalog(database)
                record = getattr(github, "record_synthetic_push", None)
                if callable(record):
                    with database.connection() as connection:
                        for row in connection.execute(
                            """
                            SELECT branch, commit_sha FROM scans WHERE installation_id = 9001
                                AND repository_id = 9002 AND source = 'demo' ORDER BY rowid
                            """
                        ):
                            record(row["branch"], row["commit_sha"])
                seed_initial_scan(database, settings, github)
                worker.run_once()
            if worker_enabled:
                worker.start()
            yield
        finally:
            worker.stop()
            close_provider = getattr(provider, "close", None)
            if callable(close_provider):
                close_provider()
            github.close()
            osv.close()

    app = FastAPI(title="SCA Reachability", lifespan=lifespan)
    app.state.database = database
    app.state.settings = settings
    app.state.ai_configured = False
    processor = WebhookProcessor(database, settings, github)
    app.state.webhooks = processor
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(RequestBodyLimitMiddleware)

    @app.exception_handler(ServiceError)
    async def service_error_handler(request, error: ServiceError):
        return JSONResponse({"detail": error.public_message}, status_code=error.status_code)

    def operator(request: Request):
        return authenticate_request(request, settings, database)

    def mutation(request: Request, context=Depends(operator)):
        require_mutation_protection(request, context, settings)
        return context

    def installation_scope(connection, installation_id: int):
        if not installation_allowed(settings, installation_id):
            raise HTTPException(404, "Installation not found")
        row = connection.execute(
            "SELECT * FROM installations WHERE id = ? AND status = 'active'",
            (installation_id,),
        ).fetchone()
        if not row:
            raise HTTPException(404, "Installation not found")
        return row

    def repository_scope(connection, installation_id: int, repository_id: int):
        if not authorized_scope(connection, settings, installation_id, repository_id):
            raise HTTPException(404, "Repository not found")
        return connection.execute(
            "SELECT * FROM repositories WHERE installation_id = ? AND id = ?",
            (installation_id, repository_id),
        ).fetchone()

    def scope_predicate(alias: str = "s") -> tuple[str, list]:
        allowed = sorted(allowed_installation_ids(settings))
        if not allowed:
            return "0", []
        placeholders = ",".join("?" for _ in allowed)
        return (
            f"""
            {alias}.installation_id IN ({placeholders})
            AND EXISTS (
                SELECT 1 FROM installations i JOIN repositories r ON r.installation_id = i.id
                WHERE i.id = {alias}.installation_id AND r.id = {alias}.repository_id
                    AND i.status = 'active' AND r.active = 1
            )
            """,
            allowed,
        )

    def branch_items(connection, installation_id, repository_id):
        rows = connection.execute(
            """
            SELECT name, selected FROM branches
            WHERE installation_id = ? AND repository_id = ? ORDER BY name
            """,
            (installation_id, repository_id),
        ).fetchall()
        return [{"name": row["name"], "selected": bool(row["selected"])} for row in rows]

    @app.get("/api/meta")
    def meta():
        return {
            "mode": settings.mode,
            "github_configured": bool(github_configured) if settings.mode == "live" else False,
            "ai_configured": bool(app.state.ai_configured) if settings.mode == "live" else False,
            "auth_required": True,
        }

    @app.post("/api/session")
    async def login(request: Request):
        validate_login_request(request, settings)
        body = await _json_object(request)
        token = body.get("token")
        expected = settings.operator_token
        if expected is None:
            raise ServiceError(503, "A dashboard operator token of at least 32 characters is required.")
        if not isinstance(token, str) or len(token) > 4096 or not hmac.compare_digest(token.encode(), expected.encode()):
            raise HTTPException(401, "Authentication required")
        session = create_session(database)
        response = JSONResponse({"authenticated": True})
        response.set_cookie(
            SESSION_COOKIE, session, max_age=SESSION_TTL_SECONDS,
            httponly=True, secure=settings.mode == "live", samesite="strict", path="/api",
        )
        return response

    @app.delete("/api/session", status_code=204)
    def logout(context=Depends(mutation)):
        revoke_session(database, context)
        response = Response(status_code=204)
        response.delete_cookie(
            SESSION_COOKIE, path="/api", httponly=True,
            secure=settings.mode == "live", samesite="strict",
        )
        return response

    @app.get("/api/installations", dependencies=[Depends(operator)])
    def installations():
        return {"items": _read_installations(database, settings)}

    @app.post("/api/installations/sync", dependencies=[Depends(mutation)])
    def synchronize():
        return {"items": sync_installations(
            database, settings, github, github_configured=github_configured
        )}

    @app.get("/api/installations/{installation_id}/repositories", dependencies=[Depends(operator)])
    def repositories(installation_id: int):
        with database.connection() as connection:
            installation_scope(connection, installation_id)
            rows = connection.execute(
                """
                SELECT id, full_name, default_branch FROM repositories
                WHERE installation_id = ? AND active = 1 ORDER BY full_name
                """,
                (installation_id,),
            ).fetchall()
            items = []
            for row in rows:
                selected = connection.execute(
                    """
                    SELECT name FROM branches WHERE installation_id = ?
                        AND repository_id = ? AND selected = 1 ORDER BY name
                    """,
                    (installation_id, row["id"]),
                ).fetchall()
                last_scan = connection.execute(
                    """
                    SELECT MAX(completed_at) AS value FROM scans
                    WHERE installation_id = ? AND repository_id = ? AND status = 'completed'
                    """,
                    (installation_id, row["id"]),
                ).fetchone()
                items.append({
                    **dict(row), "selected_branches": [branch["name"] for branch in selected],
                    "last_scan_at": last_scan["value"],
                })
        return {"items": items}

    @app.get(
        "/api/installations/{installation_id}/repositories/{repository_id}/branches",
        dependencies=[Depends(operator)],
    )
    def branches(installation_id: int, repository_id: int):
        with database.connection() as connection:
            repository_scope(connection, installation_id, repository_id)
            return {"items": branch_items(connection, installation_id, repository_id)}

    @app.put(
        "/api/installations/{installation_id}/repositories/{repository_id}/branches",
        dependencies=[Depends(mutation)],
    )
    async def select_branches(installation_id: int, repository_id: int, request: Request):
        body = await _json_object(request)
        names = body.get("branches")
        if (
            not isinstance(names, list) or len(names) > 20
            or any(not isinstance(name, str) or not name or len(name) > 255 for name in names)
            or len(set(names)) != len(names)
        ):
            raise ServiceError(400, "Select at most 20 distinct existing branch names.")
        with database.transaction() as connection:
            repository_scope(connection, installation_id, repository_id)
            previous = branch_items(connection, installation_id, repository_id)
            existing = {branch["name"] for branch in previous}
            if not set(names).issubset(existing):
                raise ServiceError(400, "A selected branch does not exist in this repository.")
            for branch in previous:
                if branch["selected"] and branch["name"] not in names:
                    cancel_branch(connection, installation_id, repository_id, branch["name"])
            connection.execute(
                """
                UPDATE branches SET selected = 0, updated_at = ?
                WHERE installation_id = ? AND repository_id = ?
                """,
                (iso_now(), installation_id, repository_id),
            )
            for name in names:
                connection.execute(
                    """
                    UPDATE branches SET selected = 1, updated_at = ?
                    WHERE installation_id = ? AND repository_id = ? AND name = ?
                    """,
                    (iso_now(), installation_id, repository_id, name),
                )
            return {"items": branch_items(connection, installation_id, repository_id)}

    @app.post(
        "/api/installations/{installation_id}/repositories/{repository_id}/scan",
        dependencies=[Depends(mutation)], status_code=202,
    )
    async def scan(installation_id: int, repository_id: int, request: Request):
        body = await _json_object(request)
        branch = body.get("branch")
        if not isinstance(branch, str) or not branch or len(branch) > 255:
            raise ServiceError(400, "An existing selected branch is required.")
        if not github_configured:
            raise ServiceError(503, "GitHub App is not configured.")
        with database.connection() as connection:
            repository = repository_scope(connection, installation_id, repository_id)
            if not authorized_scope(connection, settings, installation_id, repository_id, branch):
                raise ServiceError(400, "The branch is not selected for monitoring.")
            full_name = repository["full_name"]
        try:
            commit_sha = await run_in_threadpool(
                github.resolve_commit_sha, installation_id, repository_id, full_name, branch
            )
        except Exception as error:
            raise ServiceError(503, "The selected branch commit could not be resolved.") from error
        if not isinstance(commit_sha, str) or not SHA_RE.fullmatch(commit_sha):
            raise ServiceError(503, "GitHub did not return a full commit SHA.")
        with database.transaction() as connection:
            if not authorized_scope(connection, settings, installation_id, repository_id, branch):
                raise HTTPException(404, "Repository or selected branch not found")
            scan_id, _ = enqueue_scan(
                connection, installation_id=installation_id, repository_id=repository_id,
                repository=full_name, branch=branch, commit_sha=commit_sha,
                source="demo" if settings.mode == "demo" else "github",
            )
        return {"scan_id": scan_id, "status": "queued"}

    @app.get("/api/scans", dependencies=[Depends(operator)])
    def scans(installation_id: int | None = None, repository_id: int | None = None):
        predicate, params = scope_predicate()
        with database.connection() as connection:
            if installation_id is not None:
                installation_scope(connection, installation_id)
                predicate += " AND s.installation_id = ?"
                params.append(installation_id)
            if repository_id is not None:
                if installation_id is not None:
                    repository_scope(connection, installation_id, repository_id)
                predicate += " AND s.repository_id = ?"
                params.append(repository_id)
            rows = connection.execute(
                f"SELECT s.* FROM scans s WHERE {predicate} ORDER BY s.created_at DESC, s.rowid DESC LIMIT 100",
                params,
            ).fetchall()
            results = [
                {**{key: row[key] for key in SCAN_FIELDS}, "advisory_ids": [], "package_names": []}
                for row in rows
            ]
            if results:
                by_id = {item["id"]: item for item in results}
                placeholders = ",".join("?" for _ in results)
                for item in connection.execute(
                    f"""SELECT DISTINCT scan_id, advisory_id FROM scan_findings
                    WHERE scan_id IN ({placeholders}) ORDER BY advisory_id""", list(by_id),
                ):
                    by_id[item["scan_id"]]["advisory_ids"].append(item["advisory_id"])
                for item in connection.execute(
                    f"""SELECT DISTINCT scan_id, name FROM scan_components
                    WHERE scan_id IN ({placeholders}) ORDER BY name""", list(by_id),
                ):
                    by_id[item["scan_id"]]["package_names"].append(item["name"])
        return {"items": results}

    @app.get("/api/scans/{scan_id}", dependencies=[Depends(operator)])
    def scan_details(scan_id: str):
        predicate, params = scope_predicate()
        with database.connection() as connection:
            row = connection.execute(
                f"SELECT s.* FROM scans s WHERE s.id = ? AND {predicate}",
                [scan_id, *params],
            ).fetchone()
            if not row:
                raise HTTPException(404, "Scan not found")
            result = {key: row[key] for key in SCAN_FIELDS}
            result["components"] = [dict(item) for item in connection.execute(
                """
                SELECT name, version, ecosystem, purl, manifest_path FROM scan_components
                WHERE scan_id = ? ORDER BY ordinal
                """, (scan_id,),
            ).fetchall()]
            findings = []
            for item in connection.execute(
                """
                SELECT id, package_name, version, ecosystem, purl, advisory_id,
                    summary, severity, fixed_versions_json, reachability
                FROM scan_findings WHERE scan_id = ? ORDER BY ordinal
                """, (scan_id,),
            ).fetchall():
                finding = dict(item)
                finding["fixed_versions"] = json.loads(finding.pop("fixed_versions_json"))
                findings.append(finding)
            result["findings"] = findings
            result["warnings"] = [item["warning"] for item in connection.execute(
                "SELECT warning FROM scan_warnings WHERE scan_id = ? ORDER BY ordinal", (scan_id,),
            ).fetchall()]
            result["explanation"] = json.loads(row["explanation_json"])
        return result

    @app.get("/api/deliveries", dependencies=[Depends(operator)])
    def deliveries():
        allowed = sorted(allowed_installation_ids(settings))
        if not allowed:
            return {"items": []}
        placeholders = ",".join("?" for _ in allowed)
        with database.connection() as connection:
            rows = connection.execute(
                f"""
                SELECT d.delivery_id, d.event, d.installation_id, d.repository,
                    d.branch, d.status, d.received_at, s.id AS scan_id,
                    s.status AS scan_status FROM deliveries d
                JOIN installations i ON i.id = d.installation_id
                LEFT JOIN scans s ON s.id = d.scan_id
                    AND s.installation_id = d.installation_id AND s.repository = d.repository
                WHERE i.status = 'active' AND d.installation_id IN ({placeholders})
                    AND (d.repository IS NULL OR EXISTS (
                        SELECT 1 FROM repositories r WHERE r.installation_id = d.installation_id
                            AND r.full_name = d.repository AND r.active = 1
                    ))
                ORDER BY d.received_at DESC, d.rowid DESC LIMIT 100
                """, allowed,
            ).fetchall()
        return {"items": [dict(row) for row in rows]}

    @app.post("/api/scans/{scan_id}/retry", dependencies=[Depends(mutation)], status_code=202)
    def retry_scan(scan_id: str):
        predicate, params = scope_predicate()
        with database.transaction() as connection:
            scan = connection.execute(
                f"SELECT s.* FROM scans s WHERE s.id = ? AND {predicate}",
                [scan_id, *params],
            ).fetchone()
            if not scan:
                raise HTTPException(404, "Scan not found")
            if not authorized_scope(connection, settings, scan["installation_id"],
                                    scan["repository_id"], scan["branch"]):
                raise ServiceError(400, "The branch is not selected for monitoring.")
            if scan["status"] != "failed":
                raise HTTPException(409, "Only failed scans can be retried")
            for table in ("scan_components", "scan_findings", "scan_warnings", "jobs"):
                connection.execute(f"DELETE FROM {table} WHERE scan_id = ?", (scan_id,))
            connection.execute(
                """UPDATE scans SET status = 'queued', completed_at = NULL, error = NULL,
                component_count = 0, finding_count = 0,
                explanation_json = '{"status":"disabled","text":null,"source":null}' WHERE id = ?""",
                (scan_id,),
            )
            now = iso_now()
            connection.execute(
                """INSERT INTO jobs(scan_id, installation_id, repository_id, branch, commit_sha,
                status, available_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?)""",
                (scan_id, scan["installation_id"], scan["repository_id"], scan["branch"],
                 scan["commit_sha"], time.time(), now, now),
            )
        return {"scan_id": scan_id, "status": "queued"}

    @app.get("/api/dashboard", dependencies=[Depends(operator)])
    def dashboard():
        predicate, params = scope_predicate()
        with database.connection() as connection:
            repository_count = 0
            selected_count = 0
            for installation_id in allowed_installation_ids(settings):
                repository_count += connection.execute(
                    """
                    SELECT COUNT(*) AS value FROM repositories r JOIN installations i
                        ON i.id = r.installation_id
                    WHERE i.status = 'active' AND r.active = 1 AND r.installation_id = ?
                    """, (installation_id,),
                ).fetchone()["value"]
                selected_count += connection.execute(
                    """
                    SELECT COUNT(*) AS value FROM branches b
                    JOIN repositories r ON r.installation_id = b.installation_id AND r.id = b.repository_id
                    JOIN installations i ON i.id = r.installation_id
                    WHERE i.status = 'active' AND r.active = 1
                        AND b.selected = 1 AND b.installation_id = ?
                    """, (installation_id,),
                ).fetchone()["value"]
            rows = connection.execute(
                f"""
                SELECT s.* FROM scans s WHERE {predicate}
                ORDER BY s.created_at DESC, s.rowid DESC
                """, params,
            ).fetchall()
        latest = {}
        for row in rows:
            if row["status"] == "completed":
                latest.setdefault((row["installation_id"], row["repository_id"], row["branch"]), row)
        return {
            "repositories": repository_count, "selected_branches": selected_count,
            "scans": len(rows), "findings": sum(row["finding_count"] for row in latest.values()),
            "last_scan_at": max((row["completed_at"] for row in rows if row["completed_at"]), default=None),
            "mode": settings.mode,
        }

    @app.post("/api/webhooks/github")
    async def github_webhook(request: Request):
        result = processor.ingest(
            delivery_id=request.headers.get("x-github-delivery", ""),
            event=request.headers.get("x-github-event", ""),
            signature=request.headers.get("x-hub-signature-256"),
            raw_body=await request.body(),
        )
        return {"delivery_id": result.delivery_id, "status": result.status,
                "scan_id": result.scan_id, "duplicate": result.duplicate}

    @app.post("/api/demo/push", dependencies=[Depends(mutation)], status_code=202)
    async def demo_push(request: Request):
        if settings.mode != "demo":
            raise HTTPException(404, "Not found")
        body = await _json_object(request)
        repository_id, branch = body.get("repository_id"), body.get("branch")
        if repository_id != DEMO_REPOSITORY_ID or not isinstance(branch, str):
            raise ServiceError(400, "A demo repository and existing branch are required.")
        with database.connection() as connection:
            repository_scope(connection, DEMO_INSTALLATION_ID, DEMO_REPOSITORY_ID)
            existing = connection.execute(
                "SELECT name, selected FROM branches WHERE installation_id = ? AND repository_id = ? AND name = ?",
                (DEMO_INSTALLATION_ID, DEMO_REPOSITORY_ID, branch),
            ).fetchone()
            if not existing:
                raise ServiceError(400, "The demo branch does not exist.")
            if not existing["selected"]:
                raise ServiceError(400, "Select and save the demo branch before simulating a push.")
        delivery_id = "demo-" + uuid.uuid4().hex
        commit_sha = hashlib.sha1(delivery_id.encode()).hexdigest()
        record = getattr(github, "record_synthetic_push", None)
        if callable(record):
            record(branch, commit_sha)
        raw = json.dumps({
            "installation": {"id": DEMO_INSTALLATION_ID},
            "repository": {"id": DEMO_REPOSITORY_ID, "full_name": DEMO_REPOSITORY, "default_branch": "main"},
            "ref": f"refs/heads/{branch}", "after": commit_sha, "deleted": False,
        }, separators=(",", ":")).encode()
        signature = "sha256=" + hmac.new(settings.webhook_secret.encode(), raw, hashlib.sha256).hexdigest()
        result = processor.ingest(
            delivery_id=delivery_id, event="push", signature=signature, raw_body=raw
        )
        return {"delivery_id": delivery_id, "scan_id": result.scan_id, "status": result.status}

    static_directory = Path(__file__).resolve().parent.parent / "static"
    app.mount("/static", StaticFiles(directory=static_directory, check_dir=False), name="static")

    def asset_response(filename: str):
        return FileResponse(static_directory / filename, headers={"Cache-Control": "no-cache"})

    @app.get("/", include_in_schema=False)
    @app.get("/index.html", include_in_schema=False)
    def index():
        return asset_response("index.html")

    def asset_handler(filename):
        def asset():
            return asset_response(filename)
        return asset

    for filename in ("app.js", "model.js", "styles.css"):
        app.add_api_route(
            "/" + filename, asset_handler(filename), methods=["GET"], include_in_schema=False
        )

    return app
