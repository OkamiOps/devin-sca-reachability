from dataclasses import dataclass
import json
import re
from typing import Protocol, Sequence
from urllib.parse import quote

import httpx
from packaging.utils import canonicalize_name

from sca_reachability.server.errors import RetryableError, ScanError
from sca_reachability.server.manifests import LockedComponent


OSV_API = "https://api.osv.dev"
QUERY_BATCH_SIZE = 100
MAX_ADVISORIES = 1000
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
ADVISORY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


@dataclass(frozen=True)
class Advisory:
    id: str
    summary: str | None
    severity: str | None
    fixed_versions: tuple[str, ...]


class OsvAdapter(Protocol):
    def query(self, components: Sequence[LockedComponent]) -> list[list[Advisory]]: ...

    def close(self) -> None: ...


class OsvClient:
    def __init__(self, client: httpx.Client | None = None):
        self._client = client or httpx.Client(
            base_url=OSV_API,
            timeout=httpx.Timeout(10, connect=3),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            follow_redirects=False,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "OkamiOps-SCA-Reachability",
            },
        )
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _request_json(
        self, method: str, path: str, payload: dict | None = None
    ) -> dict:
        try:
            with self._client.stream(
                method, OSV_API + path, json=payload, follow_redirects=False
            ) as response:
                chunks = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > MAX_RESPONSE_BYTES:
                        raise RetryableError("OSV response exceeded the configured size limit.")
                    chunks.append(chunk)
                body = b"".join(chunks)
                status = response.status_code
        except httpx.TimeoutException as error:
            raise RetryableError("OSV request timed out.") from error
        except httpx.RequestError as error:
            raise RetryableError("OSV request failed.") from error
        if 300 <= status < 400:
            raise ScanError("OSV returned a redirect; redirects are not followed.")
        if status == 429 or status >= 500:
            raise RetryableError(f"OSV returned HTTP {status}.")
        if status >= 400:
            raise ScanError(f"OSV returned HTTP {status}.")
        try:
            data = json.loads(body)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ScanError("OSV returned invalid JSON.") from error
        if not isinstance(data, dict):
            raise ScanError("OSV returned an unsupported response shape.")
        return data

    @staticmethod
    def _package_identity(component: LockedComponent) -> tuple[str, str]:
        ecosystem = component.ecosystem
        name = component.name
        return (
            ecosystem.lower(),
            canonicalize_name(name) if ecosystem.lower() in {"pypi", "python"} else name.lower(),
        )

    def _query_batch(self, components: Sequence[LockedComponent]) -> list[list[str]]:
        queries = [
            {
                "package": {"name": component.name, "ecosystem": component.ecosystem},
                "version": component.version,
            }
            for component in components
        ]
        # Do not include a versioned purl alongside version: OSV rejects that shape.
        data = self._request_json("POST", "/v1/querybatch", {"queries": queries})
        results = data.get("results")
        if not isinstance(results, list) or len(results) != len(components):
            raise ScanError("OSV querybatch returned a result count mismatch.")
        ids_by_component = []
        for index, result in enumerate(results):
            if not isinstance(result, dict):
                raise ScanError(f"OSV querybatch result {index} is malformed.")
            if "error" in result:
                raise ScanError(f"OSV querybatch result {index} contains an error.")
            if result.get("next_page_token"):
                raise ScanError(
                    f"OSV querybatch result {index} is paginated; the scan is incomplete."
                )
            vulns = result.get("vulns", [])
            if not isinstance(vulns, list):
                raise ScanError(f"OSV querybatch result {index} has malformed vulnerabilities.")
            ids = []
            for item in vulns:
                vulnerability_id = item.get("id") if isinstance(item, dict) else None
                if not isinstance(vulnerability_id, str) or not ADVISORY_ID_RE.fullmatch(
                    vulnerability_id
                ):
                    raise ScanError(f"OSV querybatch result {index} has an invalid advisory id.")
                ids.append(vulnerability_id)
            ids_by_component.append(ids)
        return ids_by_component

    def _vulnerability_details(self, vulnerability_id: str) -> dict:
        return self._request_json(
            "GET", f"/v1/vulns/{quote(vulnerability_id, safe='')}"
        )

    def _to_advisory(
        self,
        vulnerability_id: str,
        details: dict,
        component: LockedComponent,
        fallback_summary: str | None,
    ) -> Advisory:
        affected = details.get("affected", [])
        if not isinstance(affected, list):
            raise ScanError(f"OSV advisory {vulnerability_id} has malformed affected data.")
        expected = self._package_identity(component)
        matching = []
        for item in affected:
            package = item.get("package") if isinstance(item, dict) else None
            if not isinstance(package, dict):
                continue
            name = package.get("name")
            ecosystem = package.get("ecosystem")
            if not isinstance(name, str) or not isinstance(ecosystem, str):
                continue
            candidate = LockedComponent(
                name=name,
                version=component.version,
                ecosystem=ecosystem,
                purl=component.purl,
                manifest_path=component.manifest_path,
            )
            if self._package_identity(candidate) == expected:
                matching.append(item)
        if not matching:
            raise ScanError(
                f"OSV advisory {vulnerability_id} did not identify the queried package."
            )

        fixed_versions = []
        for item in matching:
            ranges = item.get("ranges", [])
            if not isinstance(ranges, list):
                continue
            for version_range in ranges:
                events = version_range.get("events", []) if isinstance(version_range, dict) else []
                if not isinstance(events, list):
                    continue
                for event in events:
                    fixed = event.get("fixed") if isinstance(event, dict) else None
                    if isinstance(fixed, str) and fixed and fixed not in fixed_versions:
                        fixed_versions.append(fixed)
        summary = details.get("summary")
        if not isinstance(summary, str) or not summary:
            summary = fallback_summary
        return Advisory(
            id=vulnerability_id,
            summary=summary,
            severity=None,
            fixed_versions=tuple(fixed_versions),
        )

    def query(self, components: Sequence[LockedComponent]) -> list[list[Advisory]]:
        results: list[list[Advisory]] = [[] for _ in components]
        details_cache: dict[str, dict] = {}
        total_advisories = 0
        for offset in range(0, len(components), QUERY_BATCH_SIZE):
            chunk = components[offset : offset + QUERY_BATCH_SIZE]
            ids_by_component = self._query_batch(chunk)
            for index, ids in enumerate(ids_by_component):
                for vulnerability_id in dict.fromkeys(ids):
                    total_advisories += 1
                    if total_advisories > MAX_ADVISORIES:
                        raise ScanError(
                            "OSV advisory result limit exceeded; the scan is incomplete."
                        )
                    if vulnerability_id not in details_cache:
                        details_cache[vulnerability_id] = self._vulnerability_details(
                            vulnerability_id
                        )
                    results[offset + index].append(
                        self._to_advisory(
                            vulnerability_id,
                            details_cache[vulnerability_id],
                            chunk[index],
                            None,
                        )
                    )
        return results


class DemoOsvAdapter:
    def query(self, components: Sequence[LockedComponent]) -> list[list[Advisory]]:
        results = []
        for component in components:
            if (
                component.name == "fictional-demo-package"
                and component.ecosystem == "npm"
                and component.version == "1.0.0"
            ):
                results.append(
                    [
                        Advisory(
                            id="DEMO-0001",
                            summary="Aviso sintético de demonstração; não representa uma vulnerabilidade real.",
                            severity=None,
                            fixed_versions=("1.1.0",),
                        )
                    ]
                )
            else:
                results.append([])
        return results

    def close(self) -> None:
        return None
