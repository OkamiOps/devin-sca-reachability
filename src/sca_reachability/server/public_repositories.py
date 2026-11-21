import threading
import time

from sca_reachability.server.errors import PublicError, ScanError
from sca_reachability.server.public_github import normalize_repository
from sca_reachability.server.sync import _apply, _read_installations


MAX_REPOSITORIES = 25
ATTEMPTS_PER_MINUTE = 8


class PublicRepositories:
    def __init__(self, database, settings, github):
        self.database, self.settings, self.github = database, settings, github
        self.lock = threading.RLock()

    def restore(self):
        with self.database.connection() as connection:
            for row in connection.execute('SELECT id, full_name FROM repositories WHERE installation_id = 9003 AND active = 1'):
                self.github.repositories[row['id']] = row['full_name']

    def register(self, value, session):
        with self.lock:
            now = time.time()
            with self.database.transaction() as connection:
                connection.execute('DELETE FROM public_registration_attempts WHERE attempted_at < ?', (now - 60,))
                count = connection.execute('SELECT count(*) FROM public_registration_attempts WHERE session_hash = ?', (session,)).fetchone()[0]
                if count >= ATTEMPTS_PER_MINUTE:
                    raise PublicError('rate_limit', 'Muitas verificações. Aguarde um minuto e tente novamente.', 429)
                connection.execute('INSERT INTO public_registration_attempts VALUES (?, ?)', (session, now))
            name, requested = normalize_repository(value)
            with self.database.connection() as connection:
                stored = connection.execute('SELECT id FROM repositories WHERE installation_id = 9003').fetchall()
                repo_id = self.github.repository_id(name)
                known = {r['id'] for r in stored} | set(self.github.repositories)
                if repo_id not in known and len(known) >= MAX_REPOSITORIES:
                    raise PublicError('repository_cap', 'Limite de 25 repositórios atingido. Use um repositório já registrado.', 409)
            branches, default = self.github._refs(name)
            if requested is not None and requested not in branches:
                raise PublicError('invalid_url', 'A branch da URL não existe. Use a URL principal do repositório.')
            record = dict(id=repo_id, full_name=name, default_branch=default, branches=sorted(branches))
            records = []
            with self.database.connection() as connection:
                for row in connection.execute('SELECT * FROM repositories WHERE installation_id = 9003 AND active = 1 AND id != ?', (repo_id,)):
                    names = [b['name'] for b in connection.execute('SELECT name FROM branches WHERE installation_id = 9003 AND repository_id = ?', (row['id'],))]
                    records.append(dict(id=row['id'], full_name=row['full_name'], default_branch=row['default_branch'], branches=names))
            _apply(self.database, self.settings, [dict(id=9003, account='Repositórios públicos', status='active', repositories=records + [record])])
            self.github.repositories[repo_id] = name
            return dict(installation_id=9003, repository=record, branches=sorted(branches), default_branch=default,
                        selected_branch=requested or default)

    def sync(self):
        with self.lock:
            if len(self.github.repositories) > MAX_REPOSITORIES:
                raise PublicError('repository_cap', 'Limite de 25 repositórios atingido.', 409)
            previous = {}
            with self.database.connection() as connection:
                for row in connection.execute('SELECT * FROM repositories WHERE installation_id = 9003 AND active = 1'):
                    branches = [b['name'] for b in connection.execute('SELECT name FROM branches WHERE installation_id = 9003 AND repository_id = ?', (row['id'],))]
                    previous[row['id']] = dict(id=row['id'], full_name=row['full_name'], default_branch=row['default_branch'], branches=branches)
            records = []
            for repo_id, name in self.github.repositories.items():
                try:
                    branches, default = self.github._refs(name)
                except ScanError as error:
                    if getattr(error, 'code', None) != 'private_or_missing' and repo_id in previous:
                        records.append(previous[repo_id])
                    continue
                records.append(dict(id=repo_id, full_name=name, default_branch=default, branches=sorted(branches)))
            _apply(self.database, self.settings, [dict(id=9003, account='Repositórios públicos', status='active', repositories=records)])
            return _read_installations(self.database, self.settings)
