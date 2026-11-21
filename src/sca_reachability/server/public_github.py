import hashlib
import gzip
import io
import tarfile
import threading

import httpx

from sca_reachability.server.errors import RetryableError, ScanError
from sca_reachability.server.github import SHA_RE


MAX_COMPRESSED = 32 * 1024 * 1024
MAX_UNCOMPRESSED = 64 * 1024 * 1024
MAX_ENTRIES = 30000


def parse_refs(data: bytes) -> tuple[dict[str, str], str]:
    branches = {}
    default = None
    offset = 0
    try:
        while offset < len(data):
            size = int(data[offset:offset + 4], 16)
            offset += 4
            if size == 0:
                continue
            if size < 4 or offset + size - 4 > len(data):
                raise ValueError
            packet = data[offset:offset + size - 4].decode('utf-8')
            offset += size - 4
            if packet.startswith('#'):
                continue
            ref, _, capabilities = packet.rstrip('\n').partition('\0')
            sha, name = ref.split(' ', 1)
            if not SHA_RE.fullmatch(sha):
                raise ValueError
            for capability in capabilities.split():
                if capability.startswith('symref=HEAD:refs/heads/'):
                    default = capability.removeprefix('symref=HEAD:refs/heads/')
            if name.startswith('refs/heads/'):
                branch = name.removeprefix('refs/heads/')
                if not branch or len(branch) > 255 or any(ord(c) < 32 for c in branch):
                    raise ValueError
                branches[branch] = sha.lower()
        if not branches or default not in branches:
            raise ValueError
    except (ValueError, UnicodeError) as error:
        raise ScanError('GitHub returned invalid or incomplete smart HTTP refs.') from error
    return branches, default


def parse_tarball(data: bytes, *, max_compressed=None, max_uncompressed=None, max_entries=None) -> tuple[list[dict], dict[str, bytes]]:
    max_compressed = MAX_COMPRESSED if max_compressed is None else max_compressed
    max_uncompressed = MAX_UNCOMPRESSED if max_uncompressed is None else max_uncompressed
    max_entries = MAX_ENTRIES if max_entries is None else max_entries
    tree, blobs = [], {}
    total = 0
    root = None
    seen = set()
    try:
        if len(data) > max_compressed:
            raise ScanError('Public snapshot exceeds the compressed size limit.')
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            unpacked = compressed.read(max_uncompressed + 1)
        if len(unpacked) > max_uncompressed:
            raise ScanError('Public snapshot exceeds the uncompressed size limit.')
        with tarfile.open(fileobj=io.BytesIO(unpacked), mode='r|') as archive:
            for index, member in enumerate(archive):
                if index >= max_entries:
                    raise ScanError('Public snapshot has too many entries.')
                parts = member.name.rstrip('/').split('/')
                if any(p in {'', '.', '..'} for p in parts) or member.name.startswith('/') or '\\' in member.name or '\0' in member.name:
                    raise ScanError('Public snapshot contains an unsafe path.')
                root = root or parts[0]
                if parts[0] != root:
                    raise ScanError('Public snapshot has multiple roots.')
                if member.isdir():
                    continue
                if len(parts) < 2:
                    raise ScanError('Public snapshot file has no root directory.')
                path = '/'.join(parts[1:])
                if path in seen:
                    raise ScanError('Public snapshot has duplicate paths.')
                seen.add(path)
                total += member.size
                if total > max_uncompressed:
                    raise ScanError('Public snapshot exceeds the uncompressed size limit.')
                if member.issym() or member.islnk():
                    content = member.linkname.encode('utf-8')
                    mode = '120000'
                elif member.isfile():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ScanError('Public snapshot file is unavailable.')
                    content = stream.read(max_uncompressed + 1)
                    if len(content) != member.size:
                        raise ScanError('Public snapshot file is incomplete.')
                    mode = '100755' if member.mode & 0o111 else '100644'
                else:
                    raise ScanError('Public snapshot contains an unsupported entry.')
                sha = hashlib.sha1(b'blob %d\0' % len(content) + content).hexdigest()
                blobs[sha] = content
                tree.append(dict(path=path, mode=mode, type='blob', sha=sha, size=len(content)))
    except (tarfile.TarError, OSError, EOFError, UnicodeError) as error:
        raise ScanError('Public snapshot is not a complete tar archive.') from error
    if not tree:
        raise ScanError('Public snapshot is empty.')
    return tree, blobs


class PublicGitHubAdapter:
    installation_id = 9003

    def __init__(self, repositories: tuple[str, ...], client: httpx.Client | None = None):
        self.repositories = {self.repository_id(name): name for name in repositories}
        self._client = client or httpx.Client(timeout=httpx.Timeout(60, connect=10), follow_redirects=False)
        self._owns_client = client is None
        self._cache = None
        self._lock = threading.RLock()

    @staticmethod
    def repository_id(name: str) -> int:
        return int.from_bytes(hashlib.sha256(name.lower().encode()).digest()[:6], 'big') + 1

    def close(self):
        if self._owns_client:
            self._client.close()

    def _scope(self, installation_id, repository_id, repository):
        if installation_id != self.installation_id or self.repositories.get(repository_id) != repository:
            raise ScanError('Public repository is not configured.')

    def _download(self, url, limit):
        try:
            for _ in range(4):
                with self._client.stream('GET', url, follow_redirects=False) as response:
                    if response.is_redirect:
                        target = response.url.join(response.headers.get('location', ''))
                        if target.scheme != 'https' or target.host not in {'github.com', 'codeload.github.com'} or target.username or target.password:
                            raise ScanError('Public GitHub redirect target is not allowed.')
                        url = str(target)
                        continue
                    if response.status_code == 429 or response.status_code >= 500:
                        raise RetryableError('Public GitHub is temporarily unavailable.')
                    if response.status_code != 200:
                        raise ScanError(f'Public GitHub returned HTTP {response.status_code}.')
                    chunks, size = [], 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > limit:
                            raise ScanError('Public GitHub response exceeds the size limit.')
                        chunks.append(chunk)
                    return b''.join(chunks)
            raise ScanError('Too many public GitHub redirects.')
        except httpx.RequestError as error:
            raise RetryableError('Public GitHub request failed.') from error

    def _refs(self, repository):
        return parse_refs(self._download(f'https://github.com/{repository}.git/info/refs?service=git-upload-pack', 4 * 1024 * 1024))

    def list_installations(self):
        return [dict(id=self.installation_id, account='Repositórios públicos', status='active')]

    def list_repositories(self, installation_id):
        if installation_id != self.installation_id:
            return []
        return [dict(id=id, full_name=name, default_branch=self._refs(name)[1]) for id, name in self.repositories.items()]

    def list_branches(self, installation_id, repository_id, repository):
        self._scope(installation_id, repository_id, repository)
        return sorted(self._refs(repository)[0])

    def resolve_commit_sha(self, installation_id, repository_id, repository, branch):
        self._scope(installation_id, repository_id, repository)
        refs, _ = self._refs(repository)
        if branch not in refs:
            raise ScanError('Public branch is not available.')
        return refs[branch]

    def get_tree(self, installation_id, repository_id, repository, commit_sha):
        self._scope(installation_id, repository_id, repository)
        if not SHA_RE.fullmatch(commit_sha):
            raise ScanError('A full commit SHA is required.')
        key = (repository_id, commit_sha.lower())
        with self._lock:
            if self._cache is None or self._cache[0] != key:
                data = self._download(f'https://codeload.github.com/{repository}/tar.gz/{commit_sha}', MAX_COMPRESSED)
                tree, blobs = parse_tarball(data)
                self._cache = (key, tree, blobs)
            return self._cache[1], False

    def get_blob(self, installation_id, repository_id, repository, blob_sha):
        self._scope(installation_id, repository_id, repository)
        with self._lock:
            if self._cache and self._cache[0][0] == repository_id and blob_sha in self._cache[2]:
                return self._cache[2][blob_sha]
        raise ScanError('Public blob is not in the bounded commit cache.')
