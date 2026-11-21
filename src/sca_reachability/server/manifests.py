from dataclasses import dataclass
import json
import re
from typing import Callable, Iterable
from urllib.parse import quote

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from sca_reachability.server.errors import RetryableError, ScanError


MAX_MANIFEST_FILES = 50
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_COMPONENTS = 5000
SUPPORTED_MANIFESTS = {"package-lock.json", "requirements.txt"}
NPM_VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
NPM_NAME_RE = re.compile(
    r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$"
)


@dataclass(frozen=True)
class LockedComponent:
    name: str
    version: str
    ecosystem: str
    purl: str
    manifest_path: str


@dataclass(frozen=True)
class InventoryResult:
    components: tuple[LockedComponent, ...]
    warnings: tuple[str, ...]


def _npm_name_from_lock_path(path: str) -> str | None:
    marker = "node_modules/"
    if marker not in path:
        return None
    name_path = path.rsplit(marker, 1)[1]
    parts = name_path.split("/")
    if not parts or not parts[0]:
        return None
    if parts[0].startswith("@"):
        if len(parts) < 2 or not parts[1]:
            return None
        name = f"{parts[0]}/{parts[1]}"
    else:
        name = parts[0]
    if len(name) > 214 or not NPM_NAME_RE.fullmatch(name) or ".." in name.split("/"):
        return None
    return name


def _npm_purl(name: str, version: str) -> str:
    return f"pkg:npm/{quote(name, safe='/._~-')}@{version}"


def _parse_package_lock(
    content: bytes, manifest_path: str
) -> tuple[list[LockedComponent], list[str]]:
    warnings: list[str] = []
    try:
        data = json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        return [], [f"{manifest_path}: package-lock.json is not valid UTF-8 JSON."]
    if not isinstance(data, dict) or data.get("lockfileVersion") not in {2, 3}:
        return [], [f"{manifest_path}: only npm lockfile versions 2 and 3 are supported."]
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return [], [f"{manifest_path}: lockfile has no supported packages map."]

    components = []
    for lock_path, package in packages.items():
        if not isinstance(lock_path, str) or not lock_path:
            continue
        if not isinstance(package, dict):
            warnings.append(f"{manifest_path}: ignored malformed package entry.")
            continue
        name = _npm_name_from_lock_path(lock_path)
        if not name:
            warnings.append(f"{manifest_path}: ignored unsupported package path.")
            continue
        declared_name = package.get("name")
        if isinstance(declared_name, str) and declared_name.lower() != name:
            warnings.append(f"{manifest_path}: ignored a package whose name did not match its lock path.")
            continue
        version = package.get("version")
        if not isinstance(version, str) or len(version) > 128 or not NPM_VERSION_RE.fullmatch(version):
            warnings.append(f"{manifest_path}: ignored an unpinned or unsupported npm version.")
            continue
        components.append(
            LockedComponent(
                name=name,
                version=version,
                ecosystem="npm",
                purl=_npm_purl(name, version),
                manifest_path=manifest_path,
            )
        )
    return components, warnings


def _parse_requirements(
    content: bytes, manifest_path: str
) -> tuple[list[LockedComponent], list[str]]:
    try:
        text = content.decode("utf-8")
    except UnicodeError:
        return [], [f"{manifest_path}: requirements file is not valid UTF-8."]

    components = []
    warnings = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if (
            line.startswith("-")
            or line.startswith((".", "/", "git+", "http:", "https:", "file:"))
            or " @ " in line
        ):
            warnings.append(
                f"{manifest_path}:{line_number}: skipped a URL, VCS, or pip option requirement."
            )
            continue
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            warnings.append(f"{manifest_path}:{line_number}: skipped an unsupported requirement.")
            continue

        specifiers = tuple(requirement.specifier)
        if (
            requirement.url
            or len(specifiers) != 1
            or specifiers[0].operator != "=="
            or "*" in specifiers[0].version
        ):
            warnings.append(
                f"{manifest_path}:{line_number}: skipped a dependency without one exact == version pin."
            )
            continue
        version = specifiers[0].version
        if len(requirement.name) > 214 or len(version) > 128:
            warnings.append(f"{manifest_path}:{line_number}: dependency metadata exceeds supported limits.")
            continue
        try:
            Version(version)
        except InvalidVersion:
            warnings.append(f"{manifest_path}:{line_number}: skipped an invalid Python version pin.")
            continue
        name = canonicalize_name(requirement.name)
        purl = f"pkg:pypi/{quote(name, safe='._~-')}@{quote(version, safe='._+-')}"
        components.append(
            LockedComponent(
                name=name,
                version=version,
                ecosystem="PyPI",
                purl=purl,
                manifest_path=manifest_path,
            )
        )
        if requirement.marker is not None:
            warnings.append(
                f"{manifest_path}:{line_number}: environment marker was not evaluated; the exact pin was included conservatively."
            )
    return components, warnings


def inventory_manifests(
    tree: Iterable[dict],
    read_blob: Callable[[str], bytes],
    on_manifest: Callable[[str, str, bytes], None] | None = None,
) -> InventoryResult:
    warnings: list[str] = []
    candidates = []
    unsupported = []
    for entry in tree:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        if not isinstance(path, str) or not path or len(path) > 1024:
            continue
        if path.startswith("/") or "\\" in path or any(
            part in {"", ".", ".."} for part in path.split("/")
        ):
            continue
        basename = path.rsplit("/", 1)[-1]
        if basename in SUPPORTED_MANIFESTS:
            candidates.append((path, entry))
        elif (
            basename in {
                "package.json",
                "package-lock.json",
                "npm-shrinkwrap.json",
                "pnpm-lock.yaml",
                "yarn.lock",
                "pyproject.toml",
                "poetry.lock",
                "Pipfile",
                "Pipfile.lock",
            }
            or basename.startswith("requirements")
        ):
            unsupported.append(path)

    if unsupported:
        warnings.append(
            "Unsupported dependency metadata was found and was not parsed: "
            + ", ".join(sorted(unsupported)[:10])
            + (" (additional paths omitted)." if len(unsupported) > 10 else "")
        )
    candidates.sort(key=lambda item: item[0])
    if len(candidates) > MAX_MANIFEST_FILES:
        warnings.append(
            f"Only the first {MAX_MANIFEST_FILES} supported manifest files were inspected; coverage is incomplete."
        )
        candidates = candidates[:MAX_MANIFEST_FILES]

    components: list[LockedComponent] = []
    for path, entry in candidates:
        mode = entry.get("mode")
        entry_type = entry.get("type")
        sha = entry.get("sha")
        if mode == "120000" or entry_type == "commit":
            warnings.append(f"{path}: symlinks and submodules are not inspected.")
            continue
        if entry_type != "blob" or not isinstance(sha, str) or not re.fullmatch(
            r"[0-9a-fA-F]{40}", sha
        ):
            warnings.append(f"{path}: unsupported Git tree entry; manifest was not inspected.")
            continue
        try:
            content = read_blob(sha)
        except (RetryableError, ScanError):
            raise
        except Exception as error:
            raise ScanError(f"Could not read dependency metadata at {path}.") from error
        if not isinstance(content, bytes):
            raise ScanError(f"GitHub returned invalid metadata bytes for {path}.")
        if len(content) > MAX_MANIFEST_BYTES:
            warnings.append(
                f"{path}: exceeds the 2 MiB manifest limit and was not inspected."
            )
            continue
        if on_manifest:
            on_manifest(path, sha.lower(), content)
        if path.endswith("package-lock.json"):
            parsed, parse_warnings = _parse_package_lock(content, path)
        else:
            parsed, parse_warnings = _parse_requirements(content, path)
        components.extend(parsed)
        warnings.extend(parse_warnings)
        if len(components) > MAX_COMPONENTS:
            components = components[:MAX_COMPONENTS]
            warnings.append(
                f"Only the first {MAX_COMPONENTS} locked components were retained; coverage is incomplete."
            )
            break

    if not candidates:
        warnings.append(
            "No supported package-lock.json or requirements.txt manifest was found; no dependency scan was performed."
        )
    elif not components:
        warnings.append(
            "Supported manifests were found, but no exact pinned dependencies could be inventoried."
        )
    return InventoryResult(tuple(components), tuple(dict.fromkeys(warnings)))
