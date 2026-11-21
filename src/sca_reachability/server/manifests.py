from collections import deque
from dataclasses import dataclass, replace
import json
import posixpath
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
    dev: bool = False
    lock_path: str | None = None
    dependency_relation: str = "direct"
    dependency_via: tuple[tuple[str, ...], ...] = ()
    dependency_graph_complete: bool = True
    dependency_graph_reason: str | None = None
    entry_commands: tuple[str, ...] = ()


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


def _npm_resolve(packages: dict, parent: str, name: str) -> str | None:
    while True:
        if posixpath.basename(parent) != "node_modules":
            candidate = f"{parent}/node_modules/{name}" if parent else f"node_modules/{name}"
            if candidate in packages:
                return candidate
        if not parent:
            return None
        ancestor = posixpath.dirname(parent)
        if ancestor == parent:
            return None
        parent = ancestor


def _npm_graph(packages: dict, components: list[LockedComponent]) -> list[LockedComponent]:
    issues = []

    def issue(message: str) -> None:
        if len(issues) < 3:
            issues.append(message[:400])

    def dependencies(package: dict, *, root: bool = False) -> set[str]:
        names = set()
        fields = ("dependencies", "optionalDependencies", "peerDependencies")
        for field in fields + (("devDependencies",) if root else ()):
            values = package.get(field, {})
            if not isinstance(values, dict):
                issue(f"mapa {field} inválido")
                continue
            for name, version in values.items():
                if not NPM_NAME_RE.fullmatch(name) or not isinstance(version, str):
                    issue(f"entrada {field} inválida")
                    continue
                names.add(name)
        return names

    root = packages.get("")
    if not isinstance(root, dict):
        issue("metadados da raiz ausentes")
        root = {}
    declared = dependencies(root, root=True)
    direct = {name: _npm_resolve(packages, "", name) for name in sorted(declared)}
    for name, path in direct.items():
        if path is None:
            issue(f"dependência direta {name} não resolvida")
    nodes = {component.lock_path: component for component in components}
    if any(path.startswith("/") or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/"))
           for path in nodes):
        issue("caminho não canônico no lockfile")
    if set(packages) - {""} != set(nodes):
        issue("entradas não analisadas ou não suportadas no lockfile")
    edges = {}
    edge_count = 0
    if len(nodes) <= MAX_COMPONENTS:
        for path in nodes:
            edges[path] = []
            for name in sorted(dependencies(packages[path])):
                target = _npm_resolve(packages, path, name)
                if target not in nodes:
                    issue(f"{name} de {path} não resolvida")
                else:
                    edges[path].append(target)
                edge_count += 1
                if edge_count > 50_000:
                    issue("limite de arestas do grafo excedido")
                    break
            if edge_count > 50_000:
                break
    else:
        issue("limite de nós do grafo excedido")
    chains = {path: [] for path in nodes}
    visits = 0
    for name, start in direct.items():
        if start not in nodes:
            issue(f"dependência direta {name} não analisada")
            continue
        queue = deque([(start, (name,))])
        seen = {start}
        while queue:
            path, chain = queue.popleft()
            chains[path].append(chain)
            visits += 1
            if visits > 50_000 or len(chain) > 32:
                issue("limite de caminhos do grafo excedido")
                queue.clear()
                break
            for target in edges.get(path, ()):
                if target not in seen:
                    seen.add(target)
                    queue.append((target, chain + (nodes[target].name,)))
        if visits > 50_000:
            break
    direct_paths = set(direct.values()) - {None}
    reason = "Grafo npm incompleto: " + "; ".join(issues) + "." if issues else None
    return [replace(component,
                    dependency_relation="direct" if component.lock_path in direct_paths else "transitive",
                    dependency_via=tuple(chains[component.lock_path]),
                    dependency_graph_complete=not issues and bool(chains[component.lock_path]),
                    dependency_graph_reason=reason or (None if chains[component.lock_path] else
                        "Grafo npm incompleto: pacote sem caminho a partir das dependências diretas."))
            for component in components]


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
                dev=package.get("dev") is True,
                lock_path=lock_path,
                entry_commands=tuple(name for name in (
                    package.get("bin", {}).keys() if isinstance(package.get("bin"), dict)
                    else [name.rsplit("/", 1)[-1]] if isinstance(package.get("bin"), str) else []
                ) if re.fullmatch(r"[A-Za-z0-9._-]{1,214}", name)),
            )
        )
    return _npm_graph(packages, components), warnings


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
