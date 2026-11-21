"""Read source blobs for static reachability without executing them."""

from __future__ import annotations

import re
import json
import posixpath
from dataclasses import replace
from typing import Callable, Sequence

from sca_reachability.server.errors import RetryableError, ScanError
from sca_reachability.server.manifests import LockedComponent
from sca_reachability.server.osv_client import Advisory
from sca_reachability.static_reachability import (
    MAX_SOURCE_BYTES,
    MAX_SOURCE_FILES,
    MAX_TOTAL_SOURCE_BYTES,
    EXCLUDED_DIRECTORIES,
    SourceCoverage,
    SourceFile,
    analyze_package,
    is_source_path,
)
from sca_reachability.models import ReachabilityEvidence, ReachabilityResult, ReachabilityStatus

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
         and (is_source_path(entry["path"]) or (entry["path"].rsplit("/", 1)[-1] == "package.json"
              and not any(part in EXCLUDED_DIRECTORIES for part in entry["path"].split("/")[:-1])))),
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
    roots = {(component.manifest_path, component.name): component for component in components
             if component.ecosystem == "npm" and component.dependency_relation == "direct"}
    root_results = {}

    def script_entrypoint(component: LockedComponent, result: ReachabilityResult) -> ReachabilityResult:
        if component.ecosystem != "npm" or any(item.kind == "import" for item in result.evidence):
            return result
        path = posixpath.join(posixpath.dirname(component.manifest_path), "package.json")
        source = next((source for source in coverage.files if source.path == path), None)
        if source is None:
            return result
        try:
            data = json.loads(source.content)
            scripts = data.get("scripts", {})
            if not isinstance(scripts, dict) or any(not isinstance(command, str) for command in scripts.values()):
                raise ValueError()
        except (ValueError, AttributeError):
            return replace(result, status=ReachabilityStatus.UNKNOWN,
                           reason=f"Scripts de {path} não puderam ser interpretados. Desconhecido não significa seguro.")
        aliases = (component.name,) + component.entry_commands
        pattern = r"(?<![\w.-])(?:" + "|".join(re.escape(alias) for alias in aliases) + r")(?![\w.-])"
        for name, command in scripts.items():
            matched = re.search(pattern, command)
            dynamic = re.search(r"[$`]|\bnpm\s+(?:run|exec)\b|\bnpx\b", command)
            if not matched and not dynamic:
                continue
            if not matched:
                return replace(result, status=ReachabilityStatus.UNKNOWN,
                               reason=f"Script dinâmico em {path} impede excluir cargas de pacotes. Desconhecido não significa seguro.")
            line = next((i for i, text in enumerate(source.content.splitlines(), 1)
                         if json.dumps(name) in text), 1)
            note = f"Entrada CLI {component.name} no script {name} de {path}; o código do pacote não foi analisado."
            evidence = ReachabilityEvidence(path, line, "entrypoint", note, command[:160])
            return replace(result, status=ReachabilityStatus.UNKNOWN, scope="dev_tooling",
                           evidence=(evidence,) + result.evidence[:5],
                           reason=note + " Desconhecido não significa seguro.")
        return result

    def root_result(manifest: str, name: str) -> ReachabilityResult | None:
        key = (manifest, name)
        if key not in roots:
            return None
        if key not in root_results:
            root_results[key] = script_entrypoint(roots[key], analyze_package(
                ecosystem="npm", package=name, coverage=coverage,
                manifest_path=manifest, dependency_dev=roots[key].dev))
        return root_results[key]

    def contextualize(component: LockedComponent, result: ReachabilityResult) -> ReachabilityResult:
        result = script_entrypoint(component, result)
        result = replace(result, dependency_relation=component.dependency_relation,
                         dependency_via=component.dependency_via,
                         dependency_graph_complete=component.dependency_graph_complete,
                         lock_path=component.lock_path)
        direct = component.dependency_relation == "direct"
        if component.ecosystem != "npm" or (direct and result.status != ReachabilityStatus.UNREACHABLE):
            return result
        ancestors = [(chain[0], root_result(component.manifest_path, chain[0]))
                     for chain in component.dependency_via if chain and (not direct or len(chain) > 1)]
        imported = [(name, ancestor) for name, ancestor in ancestors if ancestor is not None
                    and any(item.kind in {"import", "entrypoint"} for item in ancestor.evidence)]
        if imported:
            imported.sort(key=lambda pair: pair[1].scope != "production")
            evidence = [next(item for item in ancestor.evidence if item.kind in {"import", "entrypoint"})
                        for _, ancestor in imported]
            locations = "; ".join(f"{name}, {'invocado por CLI' if item.kind == 'entrypoint' else 'importado'} em {item.path}:{item.line}"
                                  for (name, _), item in zip(imported[:6], evidence[:6]))
            if len(imported) > 6:
                locations += f"; e mais {len(imported) - 6} dependências diretas"
            relation = "direta também usada" if direct else "transitiva"
            note = (f"Dependência {relation} via {locations}; o código dos pacotes intermediários "
                    "não foi analisado.")
            if not component.dependency_graph_complete:
                note += " " + (component.dependency_graph_reason or "Grafo npm incompleto.")
            scope = imported[0][1].scope
            if component.dev and scope == "production":
                scope = "dev_tooling"
            return replace(result, status=ReachabilityStatus.UNKNOWN, scope=scope,
                           reason=note + " Desconhecido não significa seguro.",
                           evidence=tuple(replace(item, kind="transitive_entrypoint" if item.kind == "entrypoint" else "transitive_import") for item in evidence[:6]),
                           dependency_note=note, transitive_imported_via=not direct)
        if direct and component.dependency_graph_complete and not ancestors:
            return result
        if not component.dependency_graph_complete or not ancestors or any(ancestor is None for _, ancestor in ancestors):
            note = component.dependency_graph_reason or "Grafo npm incompleto: nenhum caminho direto completo foi comprovado."
        elif any(ancestor.status != ReachabilityStatus.UNREACHABLE for _, ancestor in ancestors):
            note = "Não foi possível excluir importações de todas as dependências diretas ancestrais."
        elif result.status != ReachabilityStatus.UNREACHABLE or any(item.kind == "import" for item in result.evidence):
            note = "Uso ou incerteza no pacote transitivo; a resolução da versão não foi comprovada nos fontes."
        else:
            names = ", ".join(name for name, _ in ancestors)
            note = (f"Todos os ancestrais diretos ({names}) não são importados nos fontes analisados; "
                    "grafo resolvido e cobertura completa, sem incerteza bloqueante. Não é garantia de segurança.")
            return replace(result, dependency_note=note, reason=note)
        return replace(result, status=ReachabilityStatus.UNKNOWN, dependency_note=note,
                       reason=note + " Desconhecido não significa seguro.")

    return [
        [
            contextualize(component, analyze_package(
                ecosystem=component.ecosystem,
                package=component.name,
                coverage=coverage,
                symbols=advisory.symbols,
                manifest_path=component.manifest_path,
                dependency_dev=component.dev,
            ))
            for advisory in advisories
        ]
        for component, advisories in zip(components, advisories_by_component, strict=True)
    ]
