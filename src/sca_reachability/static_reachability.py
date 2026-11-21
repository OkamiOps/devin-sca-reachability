"""Conservative static reachability for npm and Python sources.

Source files are only read and parsed (Python ``ast`` / a small JavaScript
lexer); monitored code is never imported, installed, or executed.
"""

from __future__ import annotations

import ast
import posixpath
import re
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .models import ReachabilityEvidence, ReachabilityResult, ReachabilityStatus

PYTHON_SUFFIXES = (".py",)
JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")
SOURCE_SUFFIXES = PYTHON_SUFFIXES + JS_SUFFIXES
EXCLUDED_DIRECTORIES = frozenset({
    "node_modules", ".git", ".venv", "venv", "site-packages", "__pycache__",
    "bower_components", ".tox", ".nox",
})
MAX_SOURCE_FILES = 2_000
MAX_SOURCE_BYTES = 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 20 * 1024 * 1024
MAX_EVIDENCE = 6
SNIPPET_LIMIT = 160

# Distributions whose import name differs from the normalized PyPI name.
PYTHON_IMPORT_NAMES = {
    "pyyaml": ("yaml",), "pillow": ("PIL",), "beautifulsoup4": ("bs4",),
    "python-dateutil": ("dateutil",), "scikit-learn": ("sklearn",),
    "opencv-python": ("cv2",), "opencv-python-headless": ("cv2",),
    "pyjwt": ("jwt",), "protobuf": ("google.protobuf",), "pycryptodome": ("Crypto",),
    "python-jose": ("jose",), "pymysql": ("pymysql",), "msgpack-python": ("msgpack",),
    "setuptools": ("setuptools", "pkg_resources"), "attrs": ("attr", "attrs"),
}


@dataclass(frozen=True)
class SourceFile:
    path: str
    content: str


@dataclass
class SourceCoverage:
    """Which sources were read; any gap prevents an ``unreachable`` verdict."""

    files: list[SourceFile] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


def is_source_path(path: str) -> bool:
    parts = path.split("/")
    if any(part in EXCLUDED_DIRECTORIES for part in parts[:-1]):
        return False
    name = parts[-1]
    return name.endswith(SOURCE_SUFFIXES) and not name.endswith((".d.ts", ".min.js"))


def python_import_names(package: str) -> tuple[str, ...]:
    normalized = re.sub(r"[-_.]+", "-", package).lower()
    return PYTHON_IMPORT_NAMES.get(normalized, (normalized.replace("-", "_"),))


def _snippet(line: str) -> str:
    text = " ".join(line.strip().split())
    return text if len(text) <= SNIPPET_LIMIT else text[: SNIPPET_LIMIT - 1] + "…"


def _evidence(source: SourceFile, line: int, kind: str, detail: str) -> ReachabilityEvidence:
    lines = source.content.splitlines()
    text = lines[line - 1] if 0 < line <= len(lines) else ""
    return ReachabilityEvidence(path=source.path, line=line, kind=kind,
                                detail=detail, snippet=_snippet(text))


@dataclass
class _FileFacts:
    imports: list[ReachabilityEvidence] = field(default_factory=list)
    calls: list[ReachabilityEvidence] = field(default_factory=list)
    uncertain: list[ReachabilityEvidence] = field(default_factory=list)


# --------------------------------------------------------------------- Python
def _python_matches(module: str, roots: tuple[str, ...]) -> bool:
    return any(module == root or module.startswith(root + ".") for root in roots)


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, source: SourceFile, roots: tuple[str, ...], symbols: frozenset[str]):
        self.source, self.roots, self.symbols = source, roots, symbols
        self.facts = _FileFacts()
        self.module_aliases: set[str] = set()
        self.symbol_aliases: dict[str, str] = {}
        self.attribute_bases: set[int] = set()
        self.call_targets: set[int] = set()
        self.symbol_references: list[ast.Attribute] = []

    def _add(self, bucket: list, node: ast.AST, kind: str, detail: str) -> None:
        bucket.append(_evidence(self.source, getattr(node, "lineno", 0), kind, detail))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if _python_matches(alias.name, self.roots):
                bound = alias.asname or alias.name.split(".")[0]
                self.module_aliases.add(bound)
                self._add(self.facts.imports, node, "import", f"import {alias.name}")

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level or not node.module or not _python_matches(node.module, self.roots):
            return
        for alias in node.names:
            if alias.name == "*":
                self._add(self.facts.uncertain, node, "dynamic",
                          f"from {node.module} import * oculta quais nomes são usados")
                continue
            bound = alias.asname or alias.name
            self.symbol_aliases[bound] = alias.name
            self._add(self.facts.imports, node, "import", f"from {node.module} import {alias.name}")

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name):
            self.attribute_bases.add(id(node.value))
            if (node.value.id in self.module_aliases and node.attr in self.symbols
                    and isinstance(node.ctx, ast.Load)):
                self.symbol_references.append(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        target = node.func
        self.call_targets.add(id(target))
        if isinstance(target, ast.Name) and target.id in self.symbol_aliases:
            name = self.symbol_aliases[target.id]
            if not self.symbols or name in self.symbols:
                self._add(self.facts.calls, node, "call", f"{name}()")
        elif isinstance(target, ast.Attribute):
            base = target.value
            dotted = []
            while isinstance(base, ast.Attribute):
                dotted.append(base.attr)
                base = base.value
            if isinstance(base, ast.Name) and (
                base.id in self.module_aliases or base.id in self.symbol_aliases
            ):
                if not self.symbols or target.attr in self.symbols or any(
                    part in self.symbols for part in dotted
                ):
                    self._add(self.facts.calls, node, "call",
                              f"{ast.unparse(target)}()")
        if isinstance(target, ast.Name) and target.id in {"__import__", "getattr"} or (
            isinstance(target, ast.Attribute) and target.attr == "import_module"
        ):
            first = node.args[0] if node.args else None
            if isinstance(target, ast.Name) and target.id == "getattr":
                if isinstance(first, ast.Name) and first.id in self.module_aliases:
                    self._add(self.facts.uncertain, node, "dynamic",
                              "getattr() no módulo impede saber qual função é chamada")
            elif not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                self._add(self.facts.uncertain, node, "dynamic",
                          "importação dinâmica com nome não literal")
            elif _python_matches(first.value, self.roots):
                self._add(self.facts.uncertain, node, "dynamic",
                          f"importação dinâmica de {first.value}")
        self.generic_visit(node)

    def finish(self, tree: ast.AST) -> _FileFacts:
        self.visit(tree)
        for node in self.symbol_references:
            if id(node) not in self.call_targets:
                self._add(self.facts.uncertain, node, "escape",
                          f"{node.attr} é referenciado sem chamada direta")
        if self.symbols:
            for node in ast.walk(tree):
                if (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                        and node.id in self.module_aliases and id(node) not in self.attribute_bases):
                    self._add(self.facts.uncertain, node, "escape",
                              f"o módulo {node.id} é repassado como valor")
                elif (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                        and self.symbol_aliases.get(node.id) in self.symbols
                        and id(node) not in self.call_targets):
                    self._add(self.facts.uncertain, node, "escape",
                              f"{self.symbol_aliases[node.id]} é referenciado sem chamada direta")
        return self.facts


def _python_facts(source: SourceFile, package: str, symbols: frozenset[str]) -> _FileFacts | None:
    try:
        tree = ast.parse(source.content, filename=source.path)
    except (SyntaxError, ValueError):
        return None
    return _PythonVisitor(source, python_import_names(package), symbols).finish(tree)


# ----------------------------------------------------------------- JavaScript
_JS_TOKEN = re.compile(
    r"//[^\n]*|/\*.*?\*/|`(?:\\.|[^`\\])*`|'(?:\\.|[^'\\\n])*'|\"(?:\\.|[^\"\\\n])*\"",
    re.S,
)


def _js_mask(content: str) -> str:
    """Blank comments and string bodies, keeping offsets and line numbers."""

    def replace(match: re.Match) -> str:
        text = match.group(0)
        if text.startswith(("//", "/*")):
            return re.sub(r"[^\n]", " ", text)
        if text[0] in "'\"" and len(text) >= 2:
            return text[0] + "\0" * (len(text) - 2) + text[-1]
        return re.sub(r"[^\n]", " ", text)

    return _JS_TOKEN.sub(replace, content)


def _line_at(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


_JS_IMPORT = re.compile(
    r"\bimport\s+(?P<clause>[\w$\s{},*]+?)\s+from\s*(?P<q1>['\"])(?P<spec>[^'\"\n]+)(?P=q1)"
    r"|\bimport\s*(?P<q2>['\"])(?P<bare>[^'\"\n]+)(?P=q2)"
    r"|\bexport\s+[\w$\s{},*]+?\s+from\s*(?P<q3>['\"])(?P<reexport>[^'\"\n]+)(?P=q3)"
)
_JS_REQUIRE = re.compile(
    r"(?:\b(?:const|let|var)\s+(?P<binding>[\w$]+|\{[^}]*\})\s*=\s*)?"
    r"\b(?P<fn>require|import)\s*\(\s*(?P<arg>[^)]*?)\s*\)"
)


def _js_package_of(spec: str) -> str:
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") else parts[0]


def _js_named(clause: str, *, destructure: bool) -> tuple[list[str], dict[str, str]]:
    namespaces, named = [], {}
    clause = clause.strip()
    braces = re.search(r"\{([^}]*)\}", clause)
    rest = re.sub(r"\{[^}]*\}", "", clause)
    for part in (braces.group(1).split(",") if braces else []):
        part = part.strip()
        if not part:
            continue
        pieces = re.split(r"\s*:\s*" if destructure else r"\s+as\s+", part)
        imported = pieces[0].strip().removeprefix("type ").strip()
        local = pieces[-1].strip()
        if re.fullmatch(r"[\w$]+", local):
            if imported == "default":
                namespaces.append(local)
            else:
                named[local] = imported
    star = re.search(r"\*\s*as\s+([\w$]+)", rest)
    if star:
        namespaces.append(star.group(1))
    default = re.match(r"\s*([\w$]+)", rest)
    if default and default.group(1) != "type":
        namespaces.append(default.group(1))
    return namespaces, named


def _js_facts(source: SourceFile, package: str, symbols: frozenset[str]) -> _FileFacts:
    facts = _FileFacts()
    masked = _js_mask(source.content)
    original = source.content
    namespaces: set[str] = set()
    named: dict[str, str] = {}

    def spec_at(match: re.Match, group: str) -> str | None:
        if match.group(group) is None:
            return None
        start, end = match.span(group)
        return original[start:end]

    for match in _JS_IMPORT.finditer(masked):
        for group in ("spec", "bare", "reexport"):
            spec = spec_at(match, group)
            if spec is None or _js_package_of(spec) != package:
                continue
            line = _line_at(masked, match.start())
            facts.imports.append(_evidence(source, line, "import", f"import '{spec}'"))
            if group == "spec":
                found_ns, found_named = _js_named(match.group("clause"), destructure=False)
                namespaces.update(found_ns)
                named.update(found_named)
            elif group == "reexport":
                facts.uncertain.append(_evidence(
                    source, line, "escape", f"'{spec}' é reexportado para outros módulos"))

    for match in _JS_REQUIRE.finditer(masked):
        arg = match.group("arg")
        line = _line_at(masked, match.start("fn"))
        literal = re.fullmatch(r"(['\"])\0*\1", arg or "")
        if not literal:
            facts.uncertain.append(_evidence(
                source, line, "dynamic", f"{match.group('fn')}() com nome não literal"))
            continue
        start = match.start("arg") + 1
        spec = original[start:start + len(arg) - 2]
        if _js_package_of(spec) != package:
            continue
        facts.imports.append(_evidence(source, line, "import", f"{match.group('fn')}('{spec}')"))
        binding = match.group("binding")
        if not binding:
            tail = masked[match.end():match.end() + 64]
            call = re.match(r"\s*(?:\.\s*([\w$]+)\s*)?\(", tail)
            if call and (not symbols or call.group(1) in symbols):
                facts.calls.append(_evidence(source, line, "call",
                                             f"require('{spec}'){'.' + call.group(1) if call.group(1) else ''}()"))
            elif re.match(r"\s*\.\s*([\w$]+)", tail) is None:
                facts.uncertain.append(_evidence(
                    source, line, "escape", f"o resultado de require('{spec}') não é atribuído a um nome"))
        elif binding.startswith("{"):
            _, found_named = _js_named(binding, destructure=True)
            named.update(found_named)
        else:
            namespaces.add(binding)

    import_lines = {item.line for item in facts.imports}
    for local, imported in named.items():
        if symbols and imported not in symbols:
            continue
        for use in re.finditer(r"(?<![\w$.])" + re.escape(local) + r"(?![\w$])(\s*\()?", masked):
            line = _line_at(masked, use.start())
            if use.group(1):
                facts.calls.append(_evidence(source, line, "call", f"{imported}()"))
            elif line not in import_lines:
                facts.uncertain.append(_evidence(
                    source, line, "escape", f"{imported} é referenciado sem chamada direta"))
    for local in namespaces:
        pattern = re.compile(r"(?<![\w$.])" + re.escape(local) + r"(?![\w$])(\s*\.\s*([\w$]+))?(\s*\()?")
        for use in pattern.finditer(masked):
            line = _line_at(masked, use.start())
            if line in import_lines and not use.group(3):
                continue
            member, called = use.group(2), use.group(3)
            if member and called and (not symbols or member in symbols):
                facts.calls.append(_evidence(source, line, "call", f"{local}.{member}()"))
            elif not member and called and (not symbols or "default" in symbols):
                facts.calls.append(_evidence(source, line, "call", f"{local}()"))
            elif not member and symbols and not called:
                if not re.match(r"\s*\[", masked[use.end():]):
                    facts.uncertain.append(_evidence(
                        source, line, "escape", f"o módulo {local} é repassado como valor"))
                else:
                    facts.uncertain.append(_evidence(
                        source, line, "dynamic", f"acesso computado em {local}[...]"))
    return facts


# ------------------------------------------------------------------- Analyzer
def _scope(sources: Iterable[SourceFile], manifest_path: str | None) -> list[SourceFile]:
    root = posixpath.dirname(manifest_path or "")
    if not root:
        return list(sources)
    prefix = root + "/"
    return [source for source in sources if source.path.startswith(prefix)]


def analyze_package(
    *,
    ecosystem: str,
    package: str,
    coverage: SourceCoverage,
    symbols: Sequence[str] = (),
    manifest_path: str | None = None,
) -> ReachabilityResult:
    """Classify whether project sources import and call a vulnerable package."""

    symbol_set = frozenset(
        re.split(r"[.:#]", symbol.strip())[-1] for symbol in symbols if symbol and symbol.strip()
    ) - {""}
    target = "símbolo " + ", ".join(sorted(symbol_set)) if symbol_set else "pacote"
    if ecosystem == "npm":
        suffixes, language = JS_SUFFIXES, "JavaScript/TypeScript"
    elif ecosystem == "PyPI":
        suffixes, language = PYTHON_SUFFIXES, "Python"
    else:
        return ReachabilityResult(ReachabilityStatus.UNKNOWN,
                                  f"O ecossistema {ecosystem} não tem análise estática suportada.")

    files = [source for source in _scope(coverage.files, manifest_path)
             if source.path.endswith(suffixes)]
    imports, calls, uncertain, parse_failures = [], [], [], []
    for source in files:
        if ecosystem == "PyPI":
            facts = _python_facts(source, package, symbol_set)
            if facts is None:
                parse_failures.append(source.path)
                continue
        else:
            facts = _js_facts(source, package, symbol_set)
        imports += facts.imports
        calls += facts.calls
        uncertain += facts.uncertain

    scanned = len(files)
    meta = dict(files_scanned=scanned, language=language,
                granularity="symbol" if symbol_set else "package",
                symbols=tuple(sorted(symbol_set)))
    if calls:
        first_call = calls[0]
        chain = [item for item in imports if item.path == first_call.path][:1] or imports[:1]
        evidence = tuple(chain + calls[: MAX_EVIDENCE - len(chain)])
        reason = (f"Chamada ao {target} encontrada em {first_call.path}:{first_call.line}."
                  if symbol_set else
                  f"O código importa e chama {package} ({first_call.path}:{first_call.line}); "
                  "o aviso não identifica a função vulnerável, então qualquer chamada ao pacote conta.")
        return ReachabilityResult(ReachabilityStatus.REACHABLE, reason, evidence, **meta)

    blockers = list(coverage.gaps) + [f"Não foi possível interpretar {path}." for path in parse_failures]
    if uncertain:
        blockers.append(uncertain[0].detail + ".")
    evidence = tuple((imports + uncertain)[:MAX_EVIDENCE])
    if not scanned:
        blockers.append(f"Nenhum arquivo {language} foi encontrado para analisar.")
    if blockers:
        return ReachabilityResult(
            ReachabilityStatus.UNKNOWN,
            "Não foi possível concluir: " + " ".join(blockers[:3]) +
            " Desconhecido não significa seguro.", evidence, **meta)
    if imports and not symbol_set:
        return ReachabilityResult(
            ReachabilityStatus.UNKNOWN,
            f"{package} é importado, mas nenhuma chamada foi encontrada e o aviso não informa a "
            "função vulnerável; importar já executa código do pacote. Desconhecido não significa seguro.",
            evidence, **meta)
    if imports:
        reason = (f"{package} é importado, mas nenhuma chamada ao {target} foi encontrada em "
                  f"{scanned} arquivo(s) {language}.")
    else:
        reason = f"Nenhuma importação de {package} foi encontrada em {scanned} arquivo(s) {language}."
    return ReachabilityResult(
        ReachabilityStatus.UNREACHABLE,
        reason + " Resultado da análise estática do commit; não é garantia de segurança.",
        evidence, **meta)
