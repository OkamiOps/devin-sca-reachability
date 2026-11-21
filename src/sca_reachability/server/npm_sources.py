"""Bounded, integrity-checked npm snapshots. Nothing is extracted to disk."""

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from sca_reachability.server.errors import ScanError
from sca_reachability.server.public_github import parse_tarball


class PackageUnknown(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PackageSource:
    files: dict[str, bytes]
    metadata: dict
    gaps: tuple[str, ...] = ()


class NpmSources:
    def __init__(self, client=None, *, max_packages=150, max_download=64 * 1024 * 1024,
                 max_total=128 * 1024 * 1024, max_package=4 * 1024 * 1024,
                 max_unpacked=16 * 1024 * 1024, max_entries=3000):
        self.client = client or httpx.Client(timeout=httpx.Timeout(20, connect=5), follow_redirects=False)
        self.owns_client = client is None
        self.max_packages, self.max_download, self.max_total = max_packages, max_download, max_total
        self.max_package, self.max_unpacked, self.max_entries = max_package, max_unpacked, max_entries
        self.downloaded = self.unpacked = self.attempts = 0
        self.cache, self.urls, self.failures, self.integrities = {}, {}, {}, {}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.owns_client:
            self.client.close()

    def get(self, component):
        key = (component.resolved, component.integrity)
        if key in self.failures:
            raise self.failures[key]
        try:
            source = self._get(component)
            if source.metadata.get('name') != component.name or source.metadata.get('version') != component.version:
                raise PackageUnknown('identity', 'package.json não corresponde ao nome/versão do lockfile')
            return source
        except PackageUnknown as error:
            self.failures[key] = error
            raise

    def _get(self, component):
        url = component.resolved
        try:
            parts = urlsplit(url or '')
            valid = (parts.scheme == 'https' and parts.hostname == 'registry.npmjs.org'
                     and parts.port in (None, 443) and not parts.username and not parts.password
                     and not parts.query and not parts.fragment and parts.path.endswith('.tgz'))
        except ValueError:
            valid = False
        if not valid:
            raise PackageUnknown('host', 'resolved ausente ou fora de https://registry.npmjs.org/*.tgz')
        integrity = component.integrity
        expected = []
        algorithm = None
        if integrity is not None:
            tokens = integrity.split()
            algorithm = next((alg for alg in ('sha512', 'sha1') if any(t.startswith(alg + '-') for t in tokens)), None)
            try:
                if algorithm is None:
                    raise ValueError()
                expected = [base64.b64decode(t.split('-', 1)[1], validate=True)
                            for t in tokens if t.startswith(algorithm + '-')]
                if not expected or any(len(value) != hashlib.new(algorithm).digest_size for value in expected):
                    raise ValueError()
            except (ValueError, TypeError):
                raise PackageUnknown('integrity', 'integrity inválida ou sem sha512/sha1 suportado') from None
        key = (url, integrity)
        for value in expected:
            cached = self.integrities.get((algorithm, value))
            if cached:
                return self.cache[cached]
        if key in self.urls:
            return self.cache[self.urls[key]]
        if self.attempts >= self.max_packages:
            raise PackageUnknown('package_limit', 'limite de pacotes por análise atingido')
        self.attempts += 1
        try:
            with self.client.stream('GET', url, follow_redirects=False, headers={'Accept-Encoding': 'identity'}) as response:
                response.raise_for_status()
                data = bytearray()
                for chunk in response.iter_bytes():
                    self.downloaded += len(chunk)
                    if self.downloaded > self.max_download or len(data) + len(chunk) > self.max_package:
                        raise PackageUnknown('byte_limit', 'limite de download de pacotes atingido')
                    data.extend(chunk)
        except httpx.HTTPError:
            raise PackageUnknown('download', 'download do pacote falhou; redirecionamentos não são seguidos') from None
        data = bytes(data)
        if algorithm and not any(hmac.compare_digest(hashlib.new(algorithm, data).digest(), value) for value in expected):
            raise PackageUnknown('integrity', 'integrity não confere com o tarball recebido')
        digest = hashlib.sha512(data).hexdigest()
        if digest not in self.cache:
            remaining = min(self.max_unpacked, self.max_total - self.unpacked)
            if remaining <= 0:
                raise PackageUnknown('byte_limit', 'limite total de conteúdo descompactado atingido')
            try:
                tree, blobs = parse_tarball(data, max_compressed=self.max_package,
                    max_uncompressed=remaining, max_entries=self.max_entries)
                files, gaps = {}, []
                for entry in tree:
                    if entry['mode'] == '120000':
                        gaps.append('link não seguido: ' + entry['path'])
                    else:
                        files[entry['path']] = blobs[entry['sha']]
                self.unpacked += sum(len(value) for value in files.values())
                metadata = json.loads(files.get('package.json', b''))
                if not isinstance(metadata, dict):
                    raise ValueError()
            except (ScanError, ValueError, UnicodeError, RecursionError):
                raise PackageUnknown('archive', 'tarball inválido, inseguro, incompleto ou acima dos limites') from None
            self.cache[digest] = PackageSource(files, metadata, tuple(gaps))
        self.urls[key] = digest
        if algorithm:
            self.integrities[(algorithm, hashlib.new(algorithm, data).digest())] = digest
        return self.cache[digest]
