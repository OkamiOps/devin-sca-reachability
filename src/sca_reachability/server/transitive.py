"""Static import paths through pinned npm sources; never executes package code."""

from collections import deque
from dataclasses import dataclass, replace
import json
import posixpath
import re
import shlex
from urllib.parse import quote

from sca_reachability.models import ReachabilityStatus
from sca_reachability.server.manifests import _npm_resolve
from sca_reachability.server.npm_sources import PackageUnknown
from sca_reachability.static_reachability import (
    JS_SUFFIXES, _JS_IMPORT, _JS_REQUIRE, _JS_TOKEN, _call_end, _js_mask,
    _js_package_of, _line_at, _scope, evidence_scope,
)

BUILTINS = set('assert async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel dns domain events fs http http2 https inspector module net os path perf_hooks process punycode querystring readline repl stream string_decoder sys timers tls trace_events tty url util v8 vm wasi worker_threads zlib'.split())


@dataclass(frozen=True)
class Load:
    specifier: str
    file: str
    line: int
    mode: str = 'require'
    entry: str | None = None
    kind: str = 'repository'
    scope: str | None = None
    label: str | None = None
    binary: str | None = None


def repository_entries(nodes, coverage, manifest):
    entries, issues = {}, []
    base = posixpath.dirname(manifest)
    for source in _scope(coverage.files, manifest):
        if posixpath.dirname(source.path) != base:
            continue
        if posixpath.basename(source.path).lower() == 'gruntfile.js':
            masked, _ = javascript_mask(source.content)
            if re.search(r'\b(?:var|let|const)\s+grunt\b|\bgrunt\s*=(?!=)', masked):
                issues.append('Objeto grunt reatribuído em ' + source.path)
                continue
            for match in re.finditer(r'\bgrunt\s*\.\s*loadNpmTasks\s*\(', masked):
                if match.start() and masked[match.start() - 1] in '.$':
                    issues.append('Chamada Grunt indireta em ' + source.path)
                    continue
                end = _call_end(masked, match.end())
                arg = source.content[match.end():end].strip() if end is not None else ''
                if not re.fullmatch(r"""(['"])[@a-zA-Z0-9_./~-]+\1""", arg):
                    issues.append('loadNpmTasks não literal em ' + source.path)
                    continue
                name = arg[1:-1]
                path = _npm_resolve(nodes, '', name)
                if path is None or nodes[path].name != name:
                    issues.append('Pacote Grunt ausente do lockfile: ' + name)
                    continue
                entries.setdefault(path, []).append(Load(name, source.path, _line_at(source.content, match.start()),
                    'grunt', kind='grunt', scope='dev_tooling', label='Gruntfile'))
        if posixpath.basename(source.path) != 'package.json':
            continue
        try:
            scripts = json.loads(source.content).get('scripts', {})
            if not isinstance(scripts, dict):
                raise ValueError()
        except (ValueError, AttributeError):
            issues.append('Scripts inválidos em ' + source.path)
            continue
        for name, command in scripts.items():
            if not isinstance(command, str):
                issues.append('Script não literal: ' + str(name))
                continue
            segments = re.split(r'&&|;', command)
            if ((("'" in command or '"' in command) and re.search(r'[;&]', command))
                    or any(re.search(r'[$\x60|&<>\\\n\r(){}*?~#]', segment) for segment in segments)):
                issues.append('Shell não modelado em scripts.' + name)
                continue
            for segment in segments:
                try:
                    tokens = shlex.split(segment)
                except ValueError:
                    issues.append('Aspas não resolvidas em scripts.' + name)
                    continue
                if not tokens:
                    issues.append('Comando vazio em scripts.' + name)
                    continue
                binary, explicit = tokens[0], None
                if binary == 'node' and len(tokens) > 1 and tokens[1].startswith('node_modules/'):
                    explicit = tokens[1]
                    candidates = [node for node in nodes.values()
                                  if explicit.startswith(node.lock_path + '/')]
                    candidates.sort(key=lambda node: -len(node.lock_path))
                    candidates = candidates[:1]
                else:
                    if not re.fullmatch(r'[\w.-]+', binary):
                        issues.append('Invocação não simples em scripts.' + name)
                        continue
                    candidates = [node for node in nodes.values()
                                  if node.lock_path == 'node_modules/' + node.name and binary in node.entry_commands]
                if len(candidates) != 1:
                    if candidates:
                        issues.append(f'Bin {binary} ambíguo em scripts.{name}: ' +
                                      ', '.join(node.name for node in candidates))
                    elif explicit:
                        issues.append('Bin explícito não resolvido em scripts.' + name)
                    continue
                node = candidates[0]
                positions = list(re.finditer(re.escape(json.dumps(name)) + r'\s*:', source.content))
                line = _line_at(source.content, positions[0].start()) if len(positions) == 1 else None
                entry = explicit[len(node.lock_path) + 1:] if explicit else None
                entries.setdefault(node.lock_path, []).append(Load(node.name, source.path, line, 'bin', entry,
                    'npm_script', 'test_only' if name == 'test' else 'dev_tooling', 'scripts.' + name,
                    None if explicit else binary))
    return entries, tuple(issues)


def expand_entry(component, load, sources):
    if load.mode not in ('grunt', 'bin'):
        return [load]
    source = sources.get(component)
    if load.mode == 'grunt':
        keywords = source.metadata.get('keywords') or ()
        if not isinstance(keywords, (list, tuple, str)):
            raise PackageUnknown('grunt_tasks', 'keywords Grunt inválido: ' + component.name)
        if 'gruntcollection' in keywords:
            raise PackageUnknown('grunt_collection', 'Coleção Grunt recursiva não modelada: ' + component.name)
        tasks = sorted(path for path in source.files if posixpath.dirname(path) == 'tasks'
                       and path.endswith('.js') and not posixpath.basename(path).startswith('.'))
        if not tasks:
            raise PackageUnknown('grunt_tasks', 'Diretório tasks sem entradas JavaScript modeladas: ' + component.name)
        return [replace(load, mode='file', entry=path) for path in tasks]
    bins = source.metadata.get('bin', {})
    if isinstance(bins, str):
        bins = {component.name.rsplit('/', 1)[-1]: bins}
    if not isinstance(bins, dict):
        raise PackageUnknown('bin', 'bin inválido: ' + component.name)
    if load.binary:
        target = bins.get(load.binary)
    else:
        target = load.entry if load.entry in [posixpath.normpath(value) for value in bins.values() if isinstance(value, str)] else None
    if not isinstance(target, str):
        raise PackageUnknown('bin', 'bin não resolvido inequivocamente: ' + component.name)
    return [replace(load, mode='bin_file', entry=target)]


def javascript_mask(content):
    tokens = re.compile(_JS_TOKEN.pattern + r'|(?P<regex>/(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/[\\\n])++/[a-z]*)', re.S)
    uncertain = False
    chars = list(content)
    for token in tokens.finditer(content):
        if token.group('regex'):
            uncertain |= bool(re.search(r'\b(?:require|import|eval)\b', token.group()))
            chars[token.start():token.end()] = re.sub(r'[^\n]', ' ', token.group())
        elif token.group().startswith('`') and '${' in token.group():
            uncertain = True
    return _js_mask(''.join(chars)), uncertain


def javascript_loads(content, path):
    masked, uncertain = javascript_mask(content)
    shadowed = bool(re.search(r'\b(?:var|let|const)\s+require\b|\brequire\s*=(?!=)|\bfunction[^\n{]*\([^)]*\brequire\b', masked))
    uncertain |= shadowed or bool(re.search(r'\b(?:eval|Function|createRequire|loadNpmTasks)\b|\bmodule\s*\.\s*(?:_load|require)\b', masked))
    loads, consumed = [], set()
    for match in _JS_REQUIRE.finditer(masked):
        start = match.start('fn')
        consumed.add(start)
        end = _call_end(masked, match.end())
        arg = content[match.end():end].strip() if end is not None else ''
        if shadowed or (start and masked[start - 1] in '.$') or not re.fullmatch(r"(['\"])\0*\1", _js_mask(arg)):
            uncertain = True
            continue
        if '\\' in arg or '\n' in arg:
            uncertain = True
            continue
        loads.append(Load(arg[1:-1], path, _line_at(content, start), match.group('fn')))
    for match in _JS_IMPORT.finditer(masked):
        for group in ('spec', 'bare', 'reexport'):
            if match.group(group) is not None:
                start, end = match.span(group)
                loads.append(Load(content[start:end], path, _line_at(content, match.start()), 'import'))
    uncertain |= any(match.start() not in consumed for match in re.finditer(r'\brequire\b', masked))
    return loads, uncertain


def _condition(value, mode, depth=0):
    if depth > 8:
        raise PackageUnknown('entry', 'exports recursivo ou acima do limite')
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key, target in value.items():
            if key in (mode, 'node', 'default'):
                return _condition(target, mode, depth + 1)
    raise PackageUnknown('entry', 'exports condicional não resolvido')


def resolve_file(source, path, depth=0):
    path = posixpath.normpath(path)
    if depth > 8 or path.startswith(('/', '../')) or path == '..' or '\\' in path:
        raise PackageUnknown('entry', 'caminho de entrada inválido ou recursivo')
    for candidate in (path, path + '.js', path + '.json'):
        if candidate in source.files:
            if not candidate.endswith(('.js', '.cjs', '.mjs', '.json')):
                raise PackageUnknown('entry', 'entrada nativa ou formato não suportado')
            return candidate
    metadata = source.files.get(posixpath.join(path, 'package.json'))
    if metadata:
        try:
            main = json.loads(metadata).get('main')
            if main:
                return resolve_file(source, posixpath.join(path, main), depth + 1)
        except (ValueError, AttributeError, TypeError, RecursionError):
            raise PackageUnknown('entry', 'package.json de diretório inválido') from None
    for name in ('index.js', 'index.json'):
        candidate = posixpath.join(path, name)
        if candidate in source.files:
            return candidate
    raise PackageUnknown('entry', 'arquivo de entrada ou require relativo não resolvido: ' + path[:120])


def resolve_entry(source, specifier, name, mode='require'):
    suffix = specifier[len(name):].lstrip('/')
    metadata = source.metadata
    if 'exports' in metadata:
        exports = metadata['exports']
        key = './' + suffix if suffix else '.'
        if isinstance(exports, dict) and any(key.startswith('.') for key in exports):
            exports = exports.get(key)
        elif suffix:
            raise PackageUnknown('entry', 'subpath não exportado')
        target = _condition(exports, mode)
        if not target.startswith('./'):
            raise PackageUnknown('entry', 'exports não aponta para arquivo local')
    else:
        target = suffix or metadata.get('main') or 'index.js'
    if not isinstance(target, str):
        raise PackageUnknown('entry', 'main inválido')
    return resolve_file(source, target)


def _hop(component, load, kind='dependency'):
    return {'package': component.name, 'version': component.version,
            'file': load.file, 'line': load.line, 'specifier': load.specifier, 'kind': kind,
            'url': f'https://www.npmjs.com/package/{quote(component.name, safe="@")}'+
                   f'/v/{quote(component.version, safe="")}?activeTab=code'}


class PackageTrace:
    def __init__(self, sources):
        self.sources = sources
        self.facts, self.walks = {}, {}

    def facts_for(self, component):
        key = (component.manifest_path, component.lock_path)
        if key in self.facts:
            return self.facts[key]
        source = self.sources.get(component)
        loads, uncertain = {}, bool(source.gaps)
        for path, data in source.files.items():
            if path.endswith(JS_SUFFIXES):
                if len(data) > 512 * 1024:
                    raise PackageUnknown('byte_limit', 'arquivo de código acima de 512 KiB')
                try:
                    loads[path], dynamic = javascript_loads(data.decode('utf-8'), path)
                except UnicodeError:
                    raise PackageUnknown('coverage', 'código de pacote não UTF-8') from None
                uncertain |= dynamic
            elif path.endswith(('.node', '.wasm', '.coffee', '.vue', '.svelte')):
                uncertain = True
        declared = {path.rsplit('node_modules/', 1)[-1] for path in component.dependency_edges}
        for file_loads in loads.values():
            for load in file_loads:
                if load.specifier.startswith('.'):
                    try:
                        resolve_file(source, posixpath.join(posixpath.dirname(load.file), load.specifier))
                    except PackageUnknown:
                        uncertain = True
                elif not load.specifier.startswith('node:') and _js_package_of(load.specifier) not in declared | BUILTINS:
                    uncertain = True
        self.facts[key] = source, loads, uncertain
        return self.facts[key]

    def walk(self, component, specifier, mode, forced_entry=None):
        key = (component.manifest_path, component.lock_path, specifier, mode, forced_entry)
        if key in self.walks:
            return self.walks[key]
        source, loads, uncertain = self.facts_for(component)
        if forced_entry is not None:
            entry = posixpath.normpath(forced_entry)
            if entry.startswith(('/', '../')) or entry == '..' or '\\' in entry or entry not in source.files:
                raise PackageUnknown('entry', 'Arquivo de entrada explícita ausente ou inseguro')
            data = source.files[entry]
            if len(data) > 512 * 1024:
                raise PackageUnknown('byte_limit', 'Entrada explícita acima de 512 KiB')
            if mode == 'bin_file' and data.startswith(b'#!') and not re.match(br'#![^\n]*\bnode(?:\s|$)', data):
                raise PackageUnknown('entry', 'Interpretador do bin não modelado')
            if entry not in loads:
                if not re.match(br'#![^\n]*\bnode(?:\s|$)', data):
                    raise PackageUnknown('entry', 'bin não JavaScript ou interpretador não modelado')
                try:
                    loads[entry], dynamic = javascript_loads(data.decode('utf-8'), entry)
                    uncertain |= dynamic
                except UnicodeError:
                    raise PackageUnknown('coverage', 'bin não UTF-8') from None
        else:
            entry = resolve_entry(source, specifier, component.name, mode)
        queue, seen, external, gaps = deque([(entry, ())]), {entry}, [], []
        while queue:
            path, trail = queue.popleft()
            if len(seen) > 800 or len(trail) > 64:
                gaps.append('limite de arquivos/caminho interno atingido')
                continue
            for load in loads.get(path, ()):
                if load.specifier.startswith('.'):
                    try:
                        target = resolve_file(source, posixpath.join(posixpath.dirname(path), load.specifier))
                    except PackageUnknown as error:
                        gaps.append(str(error))
                        continue
                    if target not in seen:
                        seen.add(target)
                        queue.append((target, trail + (_hop(component, load, 'relative'),)))
                elif not load.specifier.startswith(('/', '#', 'node:')) and _js_package_of(load.specifier) not in BUILTINS:
                    external.append((load, trail + (_hop(component, load),)))
                elif load.specifier.startswith(('/', '#')):
                    gaps.append('specifier absoluto ou imports # não resolvido')
        value = source, loads, uncertain or bool(gaps), external, entry
        self.walks[key] = value
        return value

    def chain(self, chain, entry_load, index=0):
        component = chain[index]
        source, all_loads, uncertain, external, entry = self.walk(component, entry_load.specifier, entry_load.mode, entry_load.entry)
        if index == len(chain) - 1:
            terminal = _hop(component, Load('', entry, None), 'entry')
            return 'reachable', (terminal,), None
        child = chain[index + 1]
        outcomes, reason = [], ('no_static_path', f'Nenhuma importação estática de {child.name} na entrada de {component.name}')
        for load, trail in external:
            if _js_package_of(load.specifier) != child.name:
                continue
            status, rest, blocked = self.chain(chain, load, index + 1)
            if status == 'reachable':
                return status, trail + rest, None
            outcomes.append(status)
            if blocked:
                reason = blocked
        if outcomes and all(status == 'unreachable' for status in outcomes):
            if uncertain or source.metadata.get('bin') or source.metadata.get('scripts'):
                return 'unknown', (), ('dynamic', f'Cobertura dinâmica/CLI impede excluir caminhos em {component.name}')
            return 'unreachable', (), None
        if outcomes:
            return 'unknown', (), reason
        if uncertain:
            return 'unknown', (), ('dynamic', f'Carga dinâmica ou cobertura incompleta em {component.name}@{component.version}')
        if source.metadata.get('bin') or source.metadata.get('scripts'):
            return 'unknown', (), ('cli', f'Entradas bin/scripts em {component.name}@{component.version} impedem prova negativa')
        if any(_js_package_of(load.specifier) == child.name for loads in all_loads.values() for load in loads):
            return 'unknown', (), reason
        return 'unreachable', (), None


def trace_transitives(components, results, coverage, sources):
    by_manifest = {}
    for component in components:
        if component.ecosystem == 'npm':
            by_manifest.setdefault(component.manifest_path, {})[component.lock_path] = component
    tracer = PackageTrace(sources)
    cache = {}
    for component, row in zip(components, results, strict=True):
        if component.ecosystem != 'npm' or component.dependency_relation != 'transitive' or not row:
            continue
        if row[0].status not in (ReachabilityStatus.UNKNOWN, ReachabilityStatus.UNREACHABLE):
            continue
        nodes = by_manifest[component.manifest_path]
        target = component.lock_path
        decision_key = (component.manifest_path, target)
        if decision_key not in cache:
            roots = [node for node in nodes.values() if node.dependency_relation == 'direct']
            reverse = {}
            for parent in nodes.values():
                for child in parent.dependency_edges:
                    reverse.setdefault(child, set()).add(parent.lock_path)
            ancestors, queue = {target}, [target]
            while queue:
                for parent in reverse.get(queue.pop(), ()):
                    if parent not in ancestors:
                        ancestors.add(parent)
                        queue.append(parent)
            extra_entries, entry_issues = repository_entries(nodes, coverage, component.manifest_path)
            entry_uncertain = bool(entry_issues)
            if row[0].status == ReachabilityStatus.UNREACHABLE and not entry_uncertain and not ancestors.intersection(extra_entries):
                continue
            roots.extend(node for key, node in nodes.items() if key in extra_entries and node not in roots)
            root_loads, repo_uncertain = {}, False
            for source in _scope(coverage.files, component.manifest_path):
                if source.path.endswith(JS_SUFFIXES):
                    loads, dynamic = javascript_loads(source.content, source.path)
                    repo_uncertain |= dynamic
                    for load in loads:
                        if _js_package_of(load.specifier) not in BUILTINS:
                            root_loads.setdefault(_js_package_of(load.specifier), []).append(load)
            repo_uncertain |= bool((set(root_loads) & {node.name for node in nodes.values()}) - {root.name for root in roots})
            roots.sort(key=lambda root: not any(evidence_scope(load.file) == 'production' and not root.dev
                                               for load in root_loads.get(root.name, ())))
            unknown = ('no_static_path', 'Não foi comprovado um caminho estático completo')
            decided, path, scope, tested, blocked = None, (), None, 0, entry_uncertain
            if entry_uncertain:
                unknown = ('entry_dynamic', '; '.join(entry_issues[:3]))

            def paths(node, trail):
                nonlocal tested, blocked
                if len(trail) > 16 or tested > 512:
                    raise PackageUnknown('path_limit', 'limite de caminhos transitivos atingido')
                if node.lock_path == target:
                    tested += 1
                    yield trail
                    return
                for child in node.dependency_edges:
                    if child not in ancestors:
                        continue
                    if child in {part.lock_path for part in trail}:
                        blocked = True
                        continue
                    yield from paths(nodes[child], trail + [nodes[child]])

            if not component.dependency_graph_complete:
                unknown, blocked = ('graph', 'Grafo npm incompleto impede resolução inequívoca dos caminhos'), True
            else:
                try:
                    for root in roots:
                        if root.lock_path not in ancestors:
                            continue
                        entries = sorted(root_loads.get(root.name, ()),
                                         key=lambda load: evidence_scope(load.file) != 'production')
                        entries += extra_entries.get(root.lock_path, [])
                        if not entries:
                            blocked = True
                            unknown = ('cli', f'Entrada Grunt/CLI ou ancestral sem importação literal modelada: {root.name}')
                            continue
                        for chain in paths(root, [root]):
                            expanded = []
                            for original in entries:
                                try:
                                    expanded.extend(expand_entry(root, original, sources))
                                except PackageUnknown as error:
                                    blocked, unknown = True, (error.code, str(error))
                            for load in expanded:
                                # Resolution must select the exact installed version at every edge.
                                if any(_npm_resolve(nodes, parent.lock_path, child.name) != child.lock_path
                                       for parent, child in zip(chain, chain[1:])):
                                    blocked, unknown = True, ('graph', 'Aresta npm não resolvida de forma inequívoca')
                                    continue
                                try:
                                    status, steps, reason = tracer.chain(chain, load)
                                except PackageUnknown as error:
                                    status, steps, reason = 'unknown', (), (error.code, str(error))
                                if status == 'reachable' and len(steps) > 63:
                                    status, reason = 'unknown', ('path_limit', 'caminho de evidência acima de 64 etapas')
                                if status == 'reachable':
                                    scope = load.scope or evidence_scope(load.file)
                                    if root.dev and scope == 'production':
                                        scope = 'dev_tooling'
                                    path = ({'package': None, 'version': None, 'file': load.file,
                                             'line': load.line, 'specifier': load.specifier, 'kind': load.kind,
                                             'label': load.label, 'url': None},) + steps
                                    decided = status
                                    break
                                if status != 'unreachable':
                                    blocked, unknown = True, reason
                            if decided:
                                break
                        if decided:
                            break
                except PackageUnknown as error:
                    blocked, unknown = True, (error.code, str(error))
            if not decided and tested and not blocked:
                if coverage.gaps:
                    unknown = ('coverage', 'Cobertura dos fontes do repositório incompleta')
                elif repo_uncertain:
                    unknown = ('repository_dynamic', 'Cargas não resolvidas ou versões não modeladas no repositório impedem prova negativa')
                else:
                    decided = 'unreachable'
            if not decided and entry_uncertain and row[0].status == ReachabilityStatus.UNREACHABLE:
                unknown = ('entry_dynamic', '; '.join(entry_issues[:3]))
            cache[decision_key] = decided, path, scope, unknown
        decided, path, scope, unknown = cache[decision_key]
        for index, result in enumerate(row):
            if decided:
                note = ('Caminho estático de importações até o pacote. Não comprova chamada do símbolo vulnerável, execução ou exploração.'
                        if decided == 'reachable' else
                        'Todos os caminhos ancestrais modelados foram excluídos com cobertura integral dos pacotes, sem cargas dinâmicas ou entradas CLI. Válido somente para este commit.')
                row[index] = replace(result, status=ReachabilityStatus(decided), reason=note,
                    dependency_note=note, granularity='import', scope=scope or result.scope,
                    transitive_decided=True, transitive_path=path, transitive_imported_via=False)
            else:
                locations = ', '.join(f'{item.path}:{item.line}' for item in result.evidence[:6])
                note = (f'Via {locations}. ' if locations else '') + unknown[1]
                row[index] = replace(result, status=ReachabilityStatus.UNKNOWN, reason=f'{note}. Desconhecido não significa seguro.',
                    dependency_note=note, transitive_unknown_reason=unknown[0])
    return results
