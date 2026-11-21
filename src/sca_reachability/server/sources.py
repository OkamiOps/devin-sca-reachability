"""Read source blobs for static reachability without executing them."""

from __future__ import annotations

import re
from typing import Callable, Sequence

from sca_reachability.server.errors import RetryableError, ScanError
from sca_reachability.server.manifests import LockedComponent
from sca_reachability.server.osv_client import Advisory
from sca_reachability.static_reachability import (
    MAX_SOURCE_BYTES,
    MAX_SOURCE_FILES,
    MAX_TOTAL_SOURCE_BYTES,
    SourceCoverage,
    SourceFile,
    analyze_package,
    is_source_path,
)
from sca_reachability.models import ReachabilityResult

SHA_PATTERN = re.compile(r"[0-9a-fA-F]{40}")


def _safe_path(path: object) -> bool:
    return (isinstance(path, str) and bool(path) and len(path) <= 1024 and "\0" not in path
            and "\\" not in path and not path.startswith("/")
            and ".." not in path.split("/"))


def collect_sources(tree: Sequence[dict], read_blob: Callable[[str], bytes]) -> SourceCoverage:
    coverage = SourceCoverage()
    candidates = sorted(
        (entry for entry in tree
         if isinstance(entry, dict) and isinstance(entry.get("path"), str)
         and is_source_path(entry["path"])),
        key=lambda entry: entry["path"],
    )
    if len(candidates) > MAX_SOURCE_FILES:
        coverage.gaps.append(f"Apenas {MAX_SOURCE_FILES} arquivos de código foram lidos.")
        candidates = candidates[:MAX_SOURCE_FILES]
    total = 0
    for entry in candidates:
        path = entry["path"]
        sha = entry.get("sha")
        if entry.get("mode") == "120000" or entry.get("type") != "blob" or not _safe_path(path) \
                or not isinstance(sha, str) or not SHA_PATTERN.fullmatch(sha):
            coverage.gaps.append(f"{path[:200]} não foi lido (link, submódulo ou caminho inválido).")
            continue
        size = entry.get("size")
        if isinstance(size, int) and size > MAX_SOURCE_BYTES:
            coverage.gaps.append(f"{path} excede o limite de leitura.")
            continue
        try:
            content = read_blob(sha)
        except (RetryableError, ScanError):
            raise
        except Exception as error:
            raise ScanError(f"Could not read source file at {path}.") from error
        if not isinstance(content, bytes) or len(content) > MAX_SOURCE_BYTES:
            coverage.gaps.append(f"{path} excede o limite de leitura.")
            continue
        total += len(content)
        if total > MAX_TOTAL_SOURCE_BYTES:
            coverage.gaps.append("O limite total de leitura de código foi atingido.")
            break
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            coverage.gaps.append(f"{path} não está em UTF-8.")
            continue
        coverage.files.append(SourceFile(path=path, content=text))
    return coverage


def reachability_for(
    components: Sequence[LockedComponent],
    advisories_by_component: Sequence[Sequence[Advisory]],
    coverage: SourceCoverage,
) -> list[list[ReachabilityResult]]:
    return [
        [
            analyze_package(
                ecosystem=component.ecosystem,
                package=component.name,
                coverage=coverage,
                symbols=advisory.symbols,
                manifest_path=component.manifest_path,
            )
            for advisory in advisories
        ]
        for component, advisories in zip(components, advisories_by_component, strict=True)
    ]
