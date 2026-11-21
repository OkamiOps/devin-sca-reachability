import base64
from datetime import datetime
import hashlib
import json
import re
import time
import threading
from typing import Protocol
from urllib.parse import quote

import httpx
import jwt

from sca_reachability.server.config import Settings
from sca_reachability.server.errors import RetryableError, ScanError


GITHUB_API = "https://api.github.com"
MAX_PAGES = 10
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_BLOB_BYTES = 2 * 1024 * 1024
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class GitHubAdapter(Protocol):
    def list_installations(self) -> list[dict]: ...

    def list_repositories(self, installation_id: int) -> list[dict]: ...

    def list_branches(
        self, installation_id: int, repository_id: int, repository: str
    ) -> list[str]: ...

    def resolve_commit_sha(
        self, installation_id: int, repository_id: int, repository: str, branch: str
    ) -> str: ...

    def get_tree(
        self, installation_id: int, repository_id: int, repository: str, commit_sha: str
    ) -> tuple[list[dict], bool]: ...

    def get_blob(
        self, installation_id: int, repository_id: int, repository: str, blob_sha: str
    ) -> bytes: ...

    def close(self) -> None: ...


class GitHubAppClient:
    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        self.settings = settings
        self._client = client or httpx.Client(
            base_url=GITHUB_API,
            timeout=httpx.Timeout(10, connect=3),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            follow_redirects=False,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "OkamiOps-SCA-Reachability",
            },
        )
        self._owns_client = client is None
        self._tokens: dict[tuple[int, int | None], tuple[str, float]] = {}
        self._token_lock = threading.RLock()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def clear_installation(self, installation_id: int) -> None:
        with self._token_lock:
            self._tokens = {
                key: value for key, value in self._tokens.items() if key[0] != installation_id
            }

    def _app_jwt(self) -> str:
        if not self.settings.github_app_id or not self.settings.github_private_key_path:
            raise RetryableError("GitHub App is not configured.")
        try:
            private_key = self.settings.github_private_key_path.read_text(
                encoding="utf-8"
            )
            now = int(time.time())
            token = jwt.encode(
                {"iat": now - 60, "exp": now + 540, "iss": self.settings.github_app_id},
                private_key,
                algorithm="RS256",
            )
            return token.decode("ascii") if isinstance(token, bytes) else token
        except (OSError, UnicodeError, jwt.PyJWTError, ValueError) as error:
            raise RetryableError("GitHub App credentials could not be loaded.") from error

    def _request(
        self,
        method: str,
        path: str,
        *,
        bearer: str,
        payload: dict | None = None,
        response_limit: int = MAX_RESPONSE_BYTES,
    ) -> tuple[dict | list, httpx.Headers]:
        if not path.startswith("/") or path.startswith("//"):
            raise ScanError("GitHub API path was not an internal API path.")
        headers = {"Authorization": f"Bearer {bearer}"}
        try:
            with self._client.stream(
                method, GITHUB_API + path, headers=headers, json=payload, follow_redirects=False
            ) as response:
                chunks = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > response_limit:
                        raise RetryableError("GitHub response exceeded the configured size limit.")
                    chunks.append(chunk)
                body = b"".join(chunks)
                status = response.status_code
                response_headers = response.headers
        except httpx.TimeoutException as error:
            raise RetryableError("GitHub request timed out.") from error
        except httpx.RequestError as error:
            raise RetryableError("GitHub request failed.") from error
        if 300 <= status < 400:
            raise ScanError("GitHub returned a redirect; authenticated redirects are not followed.")
        if status == 429 or status >= 500:
            raise RetryableError(f"GitHub returned HTTP {status}.")
        if status >= 400:
            raise ScanError(f"GitHub returned HTTP {status}.")
        try:
            data = json.loads(body)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ScanError("GitHub returned invalid JSON.") from error
        if not isinstance(data, (dict, list)):
            raise ScanError("GitHub returned an unsupported response shape.")
        return data, response_headers

    def _app_request(self, method: str, path: str, payload: dict | None = None):
        return self._request(
            method,
            path,
            bearer=self._app_jwt(),
            payload=payload,
        )

    def _installation_token(
        self, installation_id: int, repository_id: int | None = None
    ) -> str:
        with self._token_lock:
            return self._get_installation_token(installation_id, repository_id)

    def _get_installation_token(
        self, installation_id: int, repository_id: int | None = None
    ) -> str:
        if installation_id not in self.settings.allowed_installation_ids:
            raise ScanError("GitHub installation is outside the configured allowlist.")
        key = (installation_id, repository_id)
        cached = self._tokens.get(key)
        if cached and cached[1] > time.time() + 90:
            return cached[0]
        payload = {"permissions": {"contents": "read", "metadata": "read"}}
        if repository_id is not None:
            payload["repository_ids"] = [repository_id]
        data, _ = self._app_request(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            payload,
        )
        token = data.get("token") if isinstance(data, dict) else None
        expires = data.get("expires_at") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token or not isinstance(expires, str):
            raise RetryableError("GitHub did not return a usable installation token.")
        try:
            expiry = datetime.fromisoformat(expires.replace("Z", "+00:00")).timestamp()
        except ValueError as error:
            raise RetryableError("GitHub returned an invalid installation token expiry.") from error
        self._tokens[key] = (token, expiry)
        return token

    @staticmethod
    def _has_next(headers: httpx.Headers) -> bool:
        return bool(re.search(r'\brel="next"', headers.get("link", ""), re.I))

    def list_installations(self) -> list[dict]:
        results = []
        app_token = self._app_jwt()
        for page in range(1, MAX_PAGES + 1):
            data, headers = self._request(
                "GET",
                f"/app/installations?per_page=100&page={page}",
                bearer=app_token,
            )
            if not isinstance(data, list):
                raise ScanError("GitHub installation list had an unexpected shape.")
            for item in data:
                if not isinstance(item, dict):
                    continue
                account = item.get("account")
                if not isinstance(account, dict) or not isinstance(account.get("login"), str):
                    continue
                installation_id = item.get("id")
                if not isinstance(installation_id, int) or installation_id <= 0:
                    continue
                results.append(
                    {
                        "id": installation_id,
                        "account": account["login"],
                        "status": "suspended" if item.get("suspended_by") else "active",
                    }
                )
            if not self._has_next(headers):
                return results
        raise RetryableError("GitHub installation pagination exceeded the configured limit.")

    def list_repositories(self, installation_id: int) -> list[dict]:
        token = self._installation_token(installation_id)
        results = []
        for page in range(1, MAX_PAGES + 1):
            data, headers = self._request(
                "GET",
                f"/installation/repositories?per_page=100&page={page}",
                bearer=token,
            )
            repositories = data.get("repositories") if isinstance(data, dict) else None
            if not isinstance(repositories, list):
                raise ScanError("GitHub repository list had an unexpected shape.")
            for item in repositories:
                if not isinstance(item, dict):
                    continue
                repository_id = item.get("id")
                full_name = item.get("full_name")
                default_branch = item.get("default_branch")
                if (
                    isinstance(repository_id, int)
                    and repository_id > 0
                    and isinstance(full_name, str)
                    and isinstance(default_branch, str)
                    and full_name.count("/") == 1
                ):
                    results.append(
                        {
                            "id": repository_id,
                            "full_name": full_name,
                            "default_branch": default_branch,
                        }
                    )
            if not self._has_next(headers):
                return results
        raise RetryableError("GitHub repository pagination exceeded the configured limit.")

    def list_branches(
        self, installation_id: int, repository_id: int, repository: str
    ) -> list[str]:
        token = self._installation_token(installation_id, repository_id)
        encoded_repo = quote(repository, safe="/")
        results = []
        for page in range(1, MAX_PAGES + 1):
            data, headers = self._request(
                "GET",
                f"/repos/{encoded_repo}/branches?per_page=100&page={page}",
                bearer=token,
            )
            if not isinstance(data, list):
                raise ScanError("GitHub branch list had an unexpected shape.")
            for item in data:
                name = item.get("name") if isinstance(item, dict) else None
                if isinstance(name, str) and name and len(name) <= 255:
                    results.append(name)
            if not self._has_next(headers):
                return results
        raise RetryableError("GitHub branch pagination exceeded the configured limit.")

    def resolve_commit_sha(
        self, installation_id: int, repository_id: int, repository: str, branch: str
    ) -> str:
        token = self._installation_token(installation_id, repository_id)
        encoded_repo = quote(repository, safe="/")
        encoded_branch = quote(branch, safe="")
        data, _ = self._request(
            "GET",
            f"/repos/{encoded_repo}/commits/{encoded_branch}",
            bearer=token,
        )
        sha = data.get("sha") if isinstance(data, dict) else None
        if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
            raise ScanError("GitHub did not return a full commit SHA.")
        return sha.lower()

    def get_tree(
        self, installation_id: int, repository_id: int, repository: str, commit_sha: str
    ) -> tuple[list[dict], bool]:
        if not SHA_RE.fullmatch(commit_sha):
            raise ScanError("A full commit SHA is required to inspect a Git tree.")
        token = self._installation_token(installation_id, repository_id)
        encoded_repo = quote(repository, safe="/")
        commit, _ = self._request(
            "GET",
            f"/repos/{encoded_repo}/git/commits/{commit_sha}",
            bearer=token,
        )
        root = commit.get("tree") if isinstance(commit, dict) else None
        tree_sha = root.get("sha") if isinstance(root, dict) else None
        if not isinstance(tree_sha, str) or not SHA_RE.fullmatch(tree_sha):
            raise ScanError("GitHub commit did not identify a full tree SHA.")
        data, _ = self._request(
            "GET",
            f"/repos/{encoded_repo}/git/trees/{tree_sha}?recursive=1",
            bearer=token,
        )
        tree = data.get("tree") if isinstance(data, dict) else None
        if not isinstance(tree, list):
            raise ScanError("GitHub tree response had an unexpected shape.")
        return tree, bool(data.get("truncated"))

    def get_blob(
        self, installation_id: int, repository_id: int, repository: str, blob_sha: str
    ) -> bytes:
        if not SHA_RE.fullmatch(blob_sha):
            raise ScanError("A full Git blob SHA is required to read dependency metadata.")
        token = self._installation_token(installation_id, repository_id)
        encoded_repo = quote(repository, safe="/")
        data, _ = self._request(
            "GET",
            f"/repos/{encoded_repo}/git/blobs/{blob_sha}",
            bearer=token,
            response_limit=3 * 1024 * 1024,
        )
        encoded = data.get("content") if isinstance(data, dict) else None
        if not isinstance(encoded, str) or data.get("encoding") != "base64":
            raise ScanError("GitHub blob response had an unsupported encoding.")
        encoded = "".join(encoded.split())
        if len(encoded) > 4 * ((MAX_BLOB_BYTES + 2) // 3):
            raise ScanError("GitHub dependency metadata exceeds the 2 MiB limit.")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise ScanError("GitHub returned an invalid base64 blob.") from error
        if len(content) > MAX_BLOB_BYTES:
            raise ScanError("GitHub dependency metadata exceeds the 2 MiB limit.")
        return content


DEMO_SOURCE_FILES = {
    "requirements.txt": "fictional-yaml-parser==2.0.0\n",
    "src/server.js": (
        "import express from \"express\";\n"
        "import { renderTemplate } from \"fictional-demo-package\";\n"
        "\n"
        "const app = express();\n"
        "\n"
        "app.get(\"/welcome\", (request, response) => {\n"
        "  const html = renderTemplate(\"welcome\", { name: request.query.name });\n"
        "  response.send(html);\n"
        "});\n"
    ),
    "src/plugins.js": (
        "// Plugins are resolved at runtime from the deployment configuration.\n"
        "export function loadPlugin(name) {\n"
        "  return require(`fictional-plugin-host/plugins/${name}`);\n"
        "}\n"
    ),
    "worker/jobs.py": (
        "import fictional_yaml_parser as yaml_parser\n"
        "\n"
        "\n"
        "def load_job(document: str) -> dict:\n"
        "    return yaml_parser.safe_load(document)\n"
    ),
}


class DemoGitHubAdapter:
    installation_id = 9001
    repository_id = 9002
    repository_name = "okamiops/fictional-sca-demo"

    def __init__(self):
        self._blobs: dict[str, bytes] = {}
        self._branch_heads = {
            branch: hashlib.sha1(f"demo:{branch}:initial".encode()).hexdigest()
            for branch in ("main", "develop", "release")
        }
        self._pushed_branches = {
            sha: branch for branch, sha in self._branch_heads.items()
        }

    def close(self) -> None:
        return None

    def list_installations(self) -> list[dict]:
        return [{"id": self.installation_id, "account": "Fictional Demo", "status": "active"}]

    def list_repositories(self, installation_id: int) -> list[dict]:
        if installation_id != self.installation_id:
            return []
        return [
            {
                "id": self.repository_id,
                "full_name": self.repository_name,
                "default_branch": "main",
            }
        ]

    def list_branches(
        self, installation_id: int, repository_id: int, repository: str
    ) -> list[str]:
        if installation_id != self.installation_id or repository != self.repository_name:
            return []
        return ["main", "develop", "release"]

    def resolve_commit_sha(
        self, installation_id: int, repository_id: int, repository: str, branch: str
    ) -> str:
        if branch not in self.list_branches(installation_id, repository_id, repository):
            raise ScanError("Demo branch is not available.")
        return self._branch_heads[branch]

    def record_synthetic_push(self, branch: str, commit_sha: str) -> None:
        if branch not in {"main", "develop", "release"} or not SHA_RE.fullmatch(commit_sha):
            raise ScanError("Synthetic push did not identify a supported demo branch and commit.")
        self._pushed_branches[commit_sha.lower()] = branch
        self._branch_heads[branch] = commit_sha.lower()

    def get_tree(
        self, installation_id: int, repository_id: int, repository: str, commit_sha: str
    ) -> tuple[list[dict], bool]:
        branch = self._pushed_branches.get(commit_sha.lower())
        if branch is None:
            raise ScanError("Demo commit is not available.")
        version = "1.1.0" if branch == "release" else "1.0.0"
        lockfile = json.dumps(
            {
                "name": "fictional-demo-app",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "fictional-demo-app", "version": "1.0.0", "dependencies": {
                        "fictional-demo-package": version, "fictional-plugin-host": "0.3.0",
                    }},
                    "node_modules/fictional-demo-package": {"version": version},
                    "node_modules/fictional-plugin-host": {"version": "0.3.0"},
                },
            },
            separators=(",", ":"),
        )
        files = {"package-lock.json": lockfile, **DEMO_SOURCE_FILES}
        tree = []
        for path, text in files.items():
            content = text.encode("utf-8")
            blob_sha = hashlib.sha1(content).hexdigest()
            self._blobs[blob_sha] = content
            tree.append({"path": path, "mode": "100644", "type": "blob", "sha": blob_sha})
        return tree, False

    def get_blob(
        self, installation_id: int, repository_id: int, repository: str, blob_sha: str
    ) -> bytes:
        try:
            return self._blobs[blob_sha]
        except KeyError as error:
            raise ScanError("Demo dependency metadata is unavailable.") from error
