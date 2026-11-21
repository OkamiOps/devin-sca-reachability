from dataclasses import dataclass
from hashlib import sha256
import hmac
import ipaddress
import json
import logging
import re
import secrets
import threading
import time
from typing import Callable
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import HTTPException, Request
from starlette.responses import JSONResponse

from sca_reachability.server.config import Settings
from sca_reachability.server.db import Database, iso_now


SESSION_COOKIE = "sca_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
SIGNATURE_RE = re.compile(r"^sha256=[0-9a-fA-F]{64}$")
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuthContext:
    kind: str
    session_hash: str | None = None


def digest_secret(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def create_session(database: Database, ttl_seconds: int = SESSION_TTL_SECONDS) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = digest_secret(token)
    expires_at = time.time() + ttl_seconds
    with database.transaction() as connection:
        connection.execute(
            "DELETE FROM sessions WHERE expires_at <= ?",
            (time.time(),),
        )
        connection.execute(
            "INSERT INTO sessions(token_hash, expires_at, created_at) VALUES (?, ?, ?)",
            (token_hash, expires_at, iso_now()),
        )
    return token


def authenticate_request(
    request: Request, settings: Settings, database: Database
) -> AuthContext:
    authorization = request.headers.get("authorization", "")
    if authorization:
        scheme, _, value = authorization.partition(" ")
        expected = settings.operator_token
        if (
            scheme.lower() == "bearer"
            and value
            and expected is not None
            and hmac.compare_digest(value.encode(), expected.encode())
        ):
            return AuthContext("bearer")
        raise HTTPException(status_code=401, detail="Authentication required")

    token = request.cookies.get(SESSION_COOKIE)
    if token:
        token_hash = digest_secret(token)
        with database.connection() as connection:
            row = connection.execute(
                "SELECT token_hash, expires_at FROM sessions WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
        if (
            row
            and row["expires_at"] > time.time()
            and hmac.compare_digest(row["token_hash"], token_hash)
        ):
            return AuthContext("session", token_hash)
    raise HTTPException(status_code=401, detail="Authentication required")


def revoke_session(database: Database, context: AuthContext) -> None:
    if context.session_hash is None:
        return
    with database.transaction() as connection:
        connection.execute(
            "DELETE FROM sessions WHERE token_hash = ?",
            (context.session_hash,),
        )


def _origin_tuple(value: str) -> tuple[str, str] | None:
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            return None
        return parsed.scheme.lower(), parsed.netloc.lower()
    except ValueError:
        return None


def _diagnostic_authority(value: str) -> tuple[str, int | None] | None:
    try:
        parsed = urlsplit("//" + value)
        if (
            not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path or parsed.query or parsed.fragment
        ):
            return None
        return parsed.hostname.lower(), parsed.port
    except ValueError:
        return None


def _diagnostic_host_kind(
    authority: tuple[str, int | None] | None, configured_host: str | None
) -> str:
    if authority is None:
        return "other"
    host = authority[0]
    if host == configured_host:
        return "configured"
    if host.endswith(".devinapps.com"):
        return "devinapps_subdomain"
    if host == "devin.ai" or host.endswith(".devin.ai"):
        return "devin_ai"
    if host == "localhost":
        return "localhost_or_loopback"
    try:
        if ipaddress.ip_address(host).is_loopback:
            return "localhost_or_loopback"
    except ValueError:
        pass
    return "other"


def _origin_mismatch_diagnostics(
    request: Request, expected: tuple[str, str] | None
) -> str:
    actual = _origin_tuple(request.headers.get("origin", ""))
    actual_authority = _diagnostic_authority(actual[1]) if actual else None
    expected_authority = _diagnostic_authority(expected[1]) if expected else None
    configured_host = expected_authority[0] if expected_authority else None
    scheme = actual[0] if actual and actual[0] in {"http", "https"} else "other"
    scheme_match = bool(actual and expected and actual[0] == expected[0])
    host_match = bool(
        actual_authority and expected_authority
        and actual_authority[0] == expected_authority[0]
    )
    port_match = bool(
        actual_authority and expected_authority
        and actual_authority[1] == expected_authority[1]
    )
    host_kind = _diagnostic_host_kind(actual_authority, configured_host)
    host_header_kind = _diagnostic_host_kind(
        _diagnostic_authority(request.headers.get("host", "")), configured_host
    )
    fields = (
        f" scheme_match={str(scheme_match).lower()}"
        f" host_match={str(host_match).lower()} port_match={str(port_match).lower()}"
        f" origin_scheme={scheme} origin_host_kind={host_kind}"
        f" host_header_kind={host_header_kind}"
    )
    forwarded = request.headers.get("x-forwarded-host")
    if forwarded is not None:
        kind = _diagnostic_host_kind(_diagnostic_authority(forwarded), configured_host)
        fields += f" x_forwarded_host_kind={kind}"
    return fields


def demo_login_rejection_headers(
    settings: Settings, category: str, *, mismatch_request: Request | None = None,
    expected_origin: tuple[str, str] | None = None,
) -> dict[str, str] | None:
    if settings.mode != "demo":
        return None
    correlation_id = uuid4().hex
    diagnostics = (
        _origin_mismatch_diagnostics(mismatch_request, expected_origin)
        if category == "origin_mismatch" and mismatch_request is not None else ""
    )
    logger.warning(
        "demo_login_rejected category=%s correlation_id=%s%s",
        category,
        correlation_id,
        diagnostics,
    )
    return {"X-SCA-Diagnostic-ID": correlation_id}


def ensure_same_origin(
    request: Request,
    settings: Settings,
    *,
    required: bool = False,
    diagnose_login_rejection: bool = False,
) -> None:
    origin = request.headers.get("origin")
    if not origin:
        if required:
            headers = (
                demo_login_rejection_headers(settings, "origin_missing")
                if diagnose_login_rejection else None
            )
            raise HTTPException(
                status_code=403, detail="Origin validation failed", headers=headers
            )
        return
    actual = _origin_tuple(origin)
    if actual is None:
        headers = (
            demo_login_rejection_headers(settings, "origin_malformed")
            if diagnose_login_rejection else None
        )
        raise HTTPException(
            status_code=403, detail="Origin validation failed", headers=headers
        )
    configured = settings.public_origin
    if configured:
        expected = _origin_tuple(configured)
    else:
        expected = _origin_tuple(
            f"{request.url.scheme}://{request.headers.get('host', '')}"
        )
    if expected is None or actual != expected:
        headers = (
            demo_login_rejection_headers(
                settings, "origin_mismatch", mismatch_request=request,
                expected_origin=expected,
            )
            if diagnose_login_rejection else None
        )
        raise HTTPException(
            status_code=403, detail="Origin validation failed", headers=headers
        )


def require_mutation_protection(
    request: Request, context: AuthContext, settings: Settings
) -> None:
    if context.kind == "session":
        if request.headers.get("x-sca-request") != "1":
            raise HTTPException(status_code=403, detail="Request validation failed")
        ensure_same_origin(request, settings, required=True)
    else:
        ensure_same_origin(request, settings)


def validate_login_request(request: Request, settings: Settings) -> None:
    marker = request.headers.get("x-sca-request")
    if marker != "1":
        category = "request_marker_missing" if marker is None else "request_marker_invalid"
        headers = demo_login_rejection_headers(settings, category)
        raise HTTPException(
            status_code=403, detail="Request validation failed", headers=headers
        )
    ensure_same_origin(
        request, settings, required=True, diagnose_login_rejection=True
    )


def verify_webhook_signature(
    secret: str | None, signature: str | None, body: bytes
) -> bool:
    if not secret or not signature or not SIGNATURE_RE.fullmatch(signature):
        return False
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), body, sha256
    ).hexdigest()
    return hmac.compare_digest(signature.lower(), expected)


class RequestBodyLimitMiddleware:
    def __init__(
        self,
        app: Callable,
        *,
        default_limit: int = 64 * 1024,
        webhook_limit: int = 1024 * 1024,
    ):
        self.app = app
        self.default_limit = default_limit
        self.webhook_limit = webhook_limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        limit = self.webhook_limit if path == "/api/webhooks/github" else self.default_limit
        headers = dict(scope.get("headers", ()))
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > limit:
                    await self._too_large(scope, receive, send)
                    return
            except ValueError:
                await self._too_large(scope, receive, send)
                return

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await self._too_large(scope, receive, send)

    async def _too_large(self, scope, receive, send):
        response = JSONResponse(
            {"detail": "Request body exceeds the configured limit"},
            status_code=413,
        )
        await response(scope, receive, send)


class _BodyTooLarge(Exception):
    pass


class RateLimitMiddleware:
    def __init__(
        self,
        app: Callable,
        *,
        requests_per_minute: int = 120,
        login_requests_per_minute: int = 10,
        webhook_requests_per_minute: int = 600,
    ):
        self.app = app
        self.limits = {
            "default": requests_per_minute,
            "login": login_requests_per_minute,
            "webhook": webhook_requests_per_minute,
        }
        self._requests: dict[tuple[str, str], list[float]] = {}
        self._lock = threading.Lock()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith("/api/"):
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        address = client[0] if client else "unknown"
        path = scope.get("path", "")
        method = scope.get("method", "GET").upper()
        kind = (
            "login"
            if path == "/api/session" and method == "POST"
            else "webhook"
            if path == "/api/webhooks/github"
            else "default"
        )
        now = time.monotonic()
        key = (kind, address)
        with self._lock:
            recent = [stamp for stamp in self._requests.get(key, []) if now - stamp < 60]
            if len(recent) >= self.limits[kind]:
                self._requests[key] = recent
                limited = True
            else:
                recent.append(now)
                self._requests[key] = recent
                limited = False
            if len(self._requests) > 4096:
                self._requests = {
                    current_key: stamps
                    for current_key, stamps in self._requests.items()
                    if stamps and now - stamps[-1] < 60
                }
        if limited:
            response = JSONResponse(
                {"detail": "Too many requests"},
                status_code=429,
                headers={"Retry-After": "60"},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)
